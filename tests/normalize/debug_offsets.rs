//! Tests for the debug file offsets after a new layout.

use super::{
    NormalizeChange, NormalizeKept, PeFile, PeHeaders, PeImage, characteristics, optional_offset,
    put32, section_header_offset, section_rvas, test_image,
};

/// The size of one `IMAGE_DEBUG_DIRECTORY` entry.
const DEBUG_ENTRY_SIZE: u32 = 28;
/// The offset of the debug data from the start of the section.
const DEBUG_DATA_OFFSET: u32 = 0x40;
/// The offset of `PointerToRawData` in a debug directory entry.
const DEBUG_POINTER_FIELD: usize = 24;
/// The amount that each `PointerToRawData` is off its file alignment.
const UNALIGNED: u32 = 0x10;
/// The index of the Base Relocation data directory.
const BASE_RELOC: usize = 5;
/// The index of the Debug data directory.
const DEBUG: usize = 6;

/// Make one CodeView `IMAGE_DEBUG_DIRECTORY` entry.
fn debug_entry(address: u32, pointer: u32) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    entry.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    entry.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    entry.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    entry.extend_from_slice(&2u32.to_le_bytes()); // Type: CodeView
    entry.extend_from_slice(&0x10u32.to_le_bytes()); // SizeOfData
    entry.extend_from_slice(&address.to_le_bytes()); // AddressOfRawData
    entry.extend_from_slice(&pointer.to_le_bytes()); // PointerToRawData
    entry
}

/// Write a debug entry at the file offset `start` and set the Debug data directory to `rva`.
fn put_debug_entry(raw: &mut [u8], start: u32, rva: u32, pointer: u32) {
    let entry = debug_entry(rva + DEBUG_DATA_OFFSET, pointer);
    let start = usize::try_from(start).unwrap();
    raw[start..start + entry.len()].copy_from_slice(&entry);
    put_directory(raw, DEBUG, rva, DEBUG_ENTRY_SIZE);
}

fn put_directory(raw: &mut [u8], index: usize, rva: u32, size: u32) {
    let directory = optional_offset(raw) + 112 + index * 8;
    put32(raw, directory, rva);
    put32(raw, directory + 4, size);
}

/// Make a file with 0x200 more header bytes and one debug directory entry in `.rdata`. Each
/// `PointerToRawData` is also `UNALIGNED` bytes off its alignment.
///
/// The loader maps `.text` from the rounded offset up to the next aligned end. Thus the
/// `FileAlignment` slack of `.text` holds the first bytes of `.rdata`. A new layout drops them.
fn padded_headers_with_a_debug_entry() -> Vec<u8> {
    let built = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&built).unwrap();
    let old_size = headers.optional_header.size_of_headers();
    let section_count = headers.section_headers.len();
    let size = usize::try_from(old_size).unwrap();

    // Insert 0x200 zero bytes after the headers.
    let mut raw = built[..size].to_vec();
    raw.extend(std::iter::repeat_n(0, 0x200));
    raw.extend_from_slice(&built[size..]);
    let size_of_headers = optional_offset(&raw) + 60;
    put32(&mut raw, size_of_headers, old_size + 0x200);
    for section in 0..section_count {
        let field = section_header_offset(&raw, section) + 20;
        let pointer = u32::from_le_bytes(raw[field..field + 4].try_into().unwrap());
        put32(&mut raw, field, pointer + 0x200 + UNALIGNED);
    }

    let headers = PeHeaders::from_slice(&raw).unwrap();
    let section = &headers.section_headers[1];
    let rva = section.virtual_address;
    // The loader reads the section data at the rounded offset.
    let pointer = section.pointer_to_raw_data - UNALIGNED;
    put_debug_entry(&mut raw, pointer, rva, pointer + DEBUG_DATA_OFFSET);
    raw
}

/// Make a file where `.rdata` maps the raw data of `.text`, with one debug directory entry at
/// the start of `.rdata`. A new layout gives `.rdata` its own raw range. The mapped bytes stay.
fn shared_raw_data_with_a_debug_entry() -> Vec<u8> {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let pointer = headers.section_headers[0].pointer_to_raw_data;
    let rva = headers.section_headers[1].virtual_address;
    let rdata = section_header_offset(&raw, 1);
    put32(&mut raw, rdata + 20, pointer);
    put_debug_entry(&mut raw, pointer, rva, pointer + DEBUG_DATA_OFFSET);
    raw
}

/// Read the `PointerToRawData` field of the debug entry at the start of section data.
fn debug_pointer(data: &[u8]) -> u32 {
    u32::from_le_bytes(
        data[DEBUG_POINTER_FIELD..DEBUG_POINTER_FIELD + 4]
            .try_into()
            .unwrap(),
    )
}

/// Normalize `raw` and expect that the layout stays because the section data changes.
fn assert_the_layout_stays(raw: &[u8]) {
    assert_eq!(PeFile::parse(raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.kept, [NormalizeKept::SectionData]);
    assert_eq!(result.changes, []);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn a_new_layout_rebases_the_debug_file_offsets() {
    let raw = shared_raw_data_with_a_debug_entry();
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
    let original = PeImage::parse(&raw).unwrap();
    let address = original.sections[1].header.virtual_address + DEBUG_DATA_OFFSET;
    assert_eq!(original.rva_to_offset(address), Some(0x240));
    assert_eq!(debug_pointer(&original.sections[1].data), 0x240);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.kept, []);
    assert_eq!(
        result.changes,
        [
            NormalizeChange::Section { index: 1 },
            NormalizeChange::DebugPointers,
        ]
    );

    let normalized = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(section_rvas(&normalized), section_rvas(&original));
    // The raw data of `.rdata` moves from 0x200 to 0x400.
    assert_eq!(normalized.rva_to_offset(address), Some(0x440));
    let (old, new) = (&original.sections[1], &normalized.sections[1]);
    // The entry follows the new file offset of AddressOfRawData.
    assert_eq!(debug_pointer(&new.data), 0x440);
    // Only the 4 bytes of the PointerToRawData field change.
    let field = DEBUG_POINTER_FIELD..DEBUG_POINTER_FIELD + 4;
    assert_eq!(new.data.len(), old.data.len());
    assert_eq!(new.data[..field.start], old.data[..field.start]);
    assert_eq!(new.data[field.end..], old.data[field.end..]);
}

#[test]
fn bytes_in_the_raw_alignment_slack_keep_the_layout() {
    assert_the_layout_stays(&padded_headers_with_a_debug_entry());
}

#[test]
fn debug_offsets_in_an_executable_section_keep_the_layout() {
    let mut raw = shared_raw_data_with_a_debug_entry();
    // Make `.rdata` a code section.
    let flags = characteristics::CODE | characteristics::EXECUTE | characteristics::READ;
    let field = section_header_offset(&raw, 1) + 36;
    put32(&mut raw, field, flags);
    assert_the_layout_stays(&raw);
}

#[test]
fn a_debug_field_inside_another_directory_keeps_the_layout() {
    let mut raw = shared_raw_data_with_a_debug_entry();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let rva = headers.section_headers[1].virtual_address;
    let pointer = usize::try_from(headers.section_headers[1].pointer_to_raw_data).unwrap();
    // The relocation block starts at the PointerToRawData field. Its SizeOfBlock follows the
    // debug entry and makes an empty block.
    let field = u32::try_from(DEBUG_POINTER_FIELD).unwrap();
    put_directory(&mut raw, BASE_RELOC, rva + field, 8);
    put32(&mut raw, pointer + DEBUG_POINTER_FIELD + 4, 8);
    assert_the_layout_stays(&raw);
}

#[test]
fn a_stale_debug_offset_is_reported() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let pointer = headers.section_headers[0].pointer_to_raw_data;
    let rva = headers.section_headers[0].virtual_address;
    put_debug_entry(&mut raw, pointer, rva, 0x1234);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, [NormalizeChange::DebugPointers]);
    assert_eq!(result.kept, []);

    // Only the 4 bytes of the PointerToRawData field change.
    let output = file.try_build().unwrap();
    let start = usize::try_from(pointer).unwrap() + DEBUG_POINTER_FIELD;
    assert_eq!(output.len(), raw.len());
    assert_eq!(output[..start], raw[..start]);
    assert_eq!(output[start + 4..], raw[start + 4..]);
    assert_eq!(
        debug_pointer(&output[start - DEBUG_POINTER_FIELD..]),
        pointer + DEBUG_DATA_OFFSET
    );
}

/// Keep the layout when `.rdata` maps bytes of `.text` after its raw size.
#[test]
fn section_bytes_past_the_raw_size_keep_the_layout() {
    let mut raw = test_image().try_build().unwrap();
    // Fill the full raw slot of `.text` at 0x200..0x400.
    raw[0x200..0x400].fill(0xcc);
    let rdata = section_header_offset(&raw, 1);
    put32(&mut raw, rdata + 16, 0x180);
    put32(&mut raw, rdata + 20, 0x200);
    // The loader maps 0x200 bytes of `.rdata`, so its bytes 0x180..0x200 are `.text` bytes. A new
    // layout would make these bytes zero.
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::SectionData]);
    assert_eq!(file.try_build().unwrap(), raw);
}
