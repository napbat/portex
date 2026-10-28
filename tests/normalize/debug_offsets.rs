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

/// The index of the Import data directory.
const IMPORT: usize = 1;

/// The file offset of the raw data of `.text` and `.rdata` in
/// [`padded_shared_raw_data_with_an_entry_at`]. It is also the RVA of `.text`.
const SHARED_START: u32 = 0x1000;

/// Make a file where `.rdata` maps the raw data of `.text`, as in
/// [`shared_raw_data_with_a_debug_entry`]. Zero padding moves this raw data to the file offset
/// [`SHARED_START`]. The first 0x180 bytes of `.rdata` are zero, and the debug entry is at
/// `entry`. `AddressOfRawData` is `address`. Each value is an offset from the start of `.rdata`.
///
/// The `PointerToRawData` field then is the RVA of the same byte in `.text`, which holds the
/// same byte as `address`. Thus a name at `address` is also a name at that RVA.
///
/// Return the file and the RVA of `.rdata`.
fn padded_shared_raw_data_with_an_entry_at(entry: u32, address: u32) -> (Vec<u8>, u32) {
    let built = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&built).unwrap();
    let size = usize::try_from(headers.optional_header.size_of_headers()).unwrap();
    let start = usize::try_from(SHARED_START).unwrap();
    let mut raw = built[..size].to_vec();
    raw.resize(start, 0);
    raw.extend_from_slice(&built[size..]);
    assert_eq!(headers.section_headers[0].virtual_address, SHARED_START);
    for index in 0..2 {
        let field = section_header_offset(&raw, index) + 20;
        put32(&mut raw, field, SHARED_START);
    }
    let rva = headers.section_headers[1].virtual_address;
    raw[start..start + 0x180].fill(0);
    let pointer = SHARED_START + address;
    put_bytes(&mut raw, entry, &debug_entry(rva + address, pointer));
    put_directory(&mut raw, DEBUG, rva + entry, DEBUG_ENTRY_SIZE);
    (raw, rva)
}

/// Write `bytes` at `offset` bytes after the start of the shared raw data.
fn put_bytes(raw: &mut [u8], offset: u32, bytes: &[u8]) {
    let offset = usize::try_from(SHARED_START + offset).unwrap();
    raw[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// Write a 32-bit value at `offset` bytes after the start of the shared raw data.
fn put_shared32(raw: &mut [u8], offset: u32, value: u32) {
    put_bytes(raw, offset, &value.to_le_bytes());
}

/// Write a PE32+ thunk with an ordinal import at `offset` bytes after the start of the shared
/// raw data. The null thunk must follow.
fn put_ordinal_thunk(raw: &mut [u8], offset: u32) {
    put_bytes(raw, offset, &0x8000_0000_0000_0001u64.to_le_bytes());
}

fn get_shared32(raw: &[u8], offset: u32) -> u32 {
    let offset = usize::try_from(SHARED_START + offset).unwrap();
    u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap())
}

#[test]
fn a_debug_field_in_an_import_descriptor_after_the_directory_size_keeps_the_layout() {
    // The descriptors are at 0x80 and 0x94 in `.rdata`, and the null descriptor is at 0xa8. The
    // debug entry at 0x88 shares the last 12 bytes of the first descriptor and the first 16
    // bytes of the second one. Its PointerToRawData field is the Name field of the second one.
    let (mut raw, rva) = padded_shared_raw_data_with_an_entry_at(0x88, 0xe0);
    // TimeDateStamp is the Name field of the first descriptor. MajorVersion and MinorVersion
    // are its FirstThunk field. Type 0 is the OriginalFirstThunk field of the second one.
    put_shared32(&mut raw, 0x88 + 4, rva + 0xc0);
    put_shared32(&mut raw, 0x88 + 8, rva + 0xd0);
    put_shared32(&mut raw, 0x88 + 12, 0);
    // The FirstThunk field of the second descriptor follows the debug entry.
    put_shared32(&mut raw, 0x88 + 28, rva + 0xf0);
    put_bytes(&mut raw, 0xc0, b"a.dll\0");
    put_ordinal_thunk(&mut raw, 0xd0);
    put_bytes(&mut raw, 0xe0, b"b.dll\0");
    put_ordinal_thunk(&mut raw, 0xf0);
    // The directory size covers only the first descriptor. The loader reads up to the null
    // descriptor.
    put_directory(&mut raw, IMPORT, rva + 0x80, 0x14);
    assert_eq!(get_shared32(&raw, 0x94 + 12), SHARED_START + 0xe0);
    // The loader view of the file has both descriptors and their names.
    let image = PeImage::parse(&raw).unwrap();
    let read = |rva, len| image.read_rva(rva, len);
    let table = portex::ImportTable::parse(rva + 0x80, true, read).unwrap();
    let names: Vec<_> = table.dlls.iter().map(|dll| dll.name.as_str()).collect();
    assert_eq!(names, ["a.dll", "b.dll"]);
    assert_the_layout_stays(&raw);
}

#[test]
fn a_debug_field_in_an_import_name_table_keeps_the_layout() {
    // The PointerToRawData field of the debug entry at 0x100 in `.rdata` is the first entry of
    // the OriginalFirstThunk array at 0x118. The null thunk is at 0x120.
    let (mut raw, rva) = padded_shared_raw_data_with_an_entry_at(0x100, 0x140);
    // One descriptor at 0x80, then the null descriptor.
    put_shared32(&mut raw, 0x80, rva + 0x118);
    put_shared32(&mut raw, 0x80 + 12, rva + 0xc0);
    put_shared32(&mut raw, 0x80 + 16, rva + 0xd0);
    put_bytes(&mut raw, 0xc0, b"a.dll\0");
    put_ordinal_thunk(&mut raw, 0xd0);
    // The hint/name entry.
    put_bytes(&mut raw, 0x140, b"\0\0Foo\0");
    // The file has no IAT directory.
    put_directory(&mut raw, IMPORT, rva + 0x80, 0x28);
    assert_eq!(get_shared32(&raw, 0x118), SHARED_START + 0x140);
    // The loader view of the file has the hint/name entry.
    let image = PeImage::parse(&raw).unwrap();
    let read = |rva, len| image.read_rva(rva, len);
    let table = portex::ImportTable::parse(rva + 0x80, true, read).unwrap();
    assert_eq!(
        table.dlls[0].imports,
        [portex::ImportThunk::Name {
            hint: 0,
            name: "Foo".to_string()
        }]
    );
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
