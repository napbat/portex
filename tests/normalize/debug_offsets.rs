//! Tests for the debug file offsets after a new layout.

use super::{
    NormalizeChange, NormalizeKept, PeFile, PeHeaders, PeImage, optional_offset, put32,
    section_header_offset, section_rvas, test_image,
};

/// The size of one `IMAGE_DEBUG_DIRECTORY` entry.
const DEBUG_ENTRY_SIZE: u32 = 28;
/// The offset of the debug data from the start of the section.
const DEBUG_DATA_OFFSET: u32 = 0x40;
/// The offset of `PointerToRawData` in a debug directory entry.
const DEBUG_POINTER_FIELD: usize = 24;
/// The amount that each `PointerToRawData` is off its file alignment. The loader rounds the
/// value down to a multiple of 0x200, so it reads the same bytes.
const UNALIGNED: u32 = 0x10;

/// Make a file with 0x200 more header bytes and one debug directory entry in the section
/// `index`. A new layout gives `SizeOfHeaders` 0x200 and moves the raw section data.
///
/// The padding alone does not move the sections, because a new layout keeps an aligned gap
/// before a section. Thus each `PointerToRawData` is also `UNALIGNED` bytes off its alignment.
/// A new layout moves an unaligned section to the next free aligned offset.
fn padded_headers_with_a_debug_entry(index: usize) -> Vec<u8> {
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
    let section = &headers.section_headers[index];
    let rva = section.virtual_address;
    // The loader reads the section data at the rounded offset.
    let pointer = section.pointer_to_raw_data - UNALIGNED;
    let mut entry = Vec::new();
    entry.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    entry.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    entry.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    entry.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    entry.extend_from_slice(&2u32.to_le_bytes()); // Type: CodeView
    entry.extend_from_slice(&0x10u32.to_le_bytes()); // SizeOfData
    entry.extend_from_slice(&(rva + DEBUG_DATA_OFFSET).to_le_bytes()); // AddressOfRawData
    entry.extend_from_slice(&(pointer + DEBUG_DATA_OFFSET).to_le_bytes()); // PointerToRawData
    let start = usize::try_from(pointer).unwrap();
    raw[start..start + entry.len()].copy_from_slice(&entry);

    // Set the Debug data directory (index 6).
    let directory = optional_offset(&raw) + 112 + 6 * 8;
    put32(&mut raw, directory, rva);
    put32(&mut raw, directory + 4, DEBUG_ENTRY_SIZE);
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

#[test]
fn a_new_layout_rebases_the_debug_file_offsets() {
    let raw = padded_headers_with_a_debug_entry(1);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
    let original = PeImage::parse(&raw).unwrap();
    let address = original.sections[1].header.virtual_address + DEBUG_DATA_OFFSET;
    assert_eq!(original.rva_to_offset(address), Some(0x640));
    assert_eq!(debug_pointer(&original.sections[1].data), 0x640);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.kept, []);
    assert_eq!(
        result.changes,
        [
            NormalizeChange::SizeOfHeaders {
                old: 0x400,
                new: 0x200
            },
            NormalizeChange::Section { index: 0 },
            NormalizeChange::Section { index: 1 },
            NormalizeChange::DebugPointers,
        ]
    );

    let normalized = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(section_rvas(&normalized), section_rvas(&original));
    // The raw data of `.rdata` moves from 0x600 to 0x400.
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
fn debug_offsets_in_an_executable_section_keep_the_layout() {
    let raw = padded_headers_with_a_debug_entry(0);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.kept, [NormalizeKept::SectionData]);
    assert_eq!(result.changes, []);
    assert_eq!(file.try_build().unwrap(), raw);
}
