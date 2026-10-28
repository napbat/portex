//! Tests for the header bytes that the loader maps.

use super::{
    MachineType, NormalizeChange, NormalizeKept, PeBuilder, PeFile, characteristics,
    optional_offset, put32, section_header_offset, test_image,
};

/// Make a file with page alignment, where `.text` starts at file offset 0x200, in the header page.
fn text_in_the_header_page() -> Vec<u8> {
    let built = PeBuilder::new()
        .machine(MachineType::Amd64)
        .file_alignment(0x1000)
        .section_alignment(0x1000)
        .entry_point(0x300)
        .add_section(
            ".text",
            vec![0xcc; 0xe00],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    // Keep the headers and put the `.text` bytes at 0x200..0x1000.
    let mut raw = built[..0x1000].to_vec();
    raw[0x200..].fill(0xcc);
    let text = section_header_offset(&raw, 0);
    put32(&mut raw, text + 8, 0xe00);
    put32(&mut raw, text + 12, 0x1000);
    put32(&mut raw, text + 16, 0xe00);
    put32(&mut raw, text + 20, 0x200);
    let optional = optional_offset(&raw);
    // SizeOfHeaders is 0x1000, and the checksum is zero.
    put32(&mut raw, optional + 60, 0x1000);
    put32(&mut raw, optional + 64, 0);
    raw
}

#[test]
fn section_bytes_in_the_header_page_stay_mapped() {
    let raw = text_in_the_header_page();
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    // The loader maps file bytes 0..0x1000 as the header page, so the entry point at RVA 0x300
    // holds `.text` bytes. A new layout would make these bytes zero.
    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    let normalized = file.try_build().unwrap();
    assert_eq!(normalized, raw);
    assert!(normalized[0x300..0x310].iter().all(|&byte| byte == 0xcc));
}

#[test]
fn a_larger_size_of_headers_does_not_cover_a_referenced_range() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&raw);
    let table_end = section_header_offset(&raw, 2);
    assert!(table_end > 0x180);
    // SizeOfHeaders is smaller than the section table end. The loader maps zeros at 0x100..0x1000.
    put32(&mut raw, optional + 60, 0x100);
    // The entry point refers to these zeros. A larger SizeOfHeaders would map header bytes there.
    put32(&mut raw, optional + 16, 0x180);
    put32(&mut raw, optional + 64, 0);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert!(
        !result
            .changes
            .iter()
            .any(|change| matches!(change, NormalizeChange::SizeOfHeaders { .. }))
    );
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn a_checksum_fix_in_referenced_header_bytes_is_not_made() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&raw);
    // The entry point refers to the CheckSum field, so a checksum fix would change the code.
    put32(
        &mut raw,
        optional + 16,
        u32::try_from(optional + 64).unwrap(),
    );
    put32(&mut raw, optional + 64, 1);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    assert_eq!(file.try_build().unwrap(), raw);
}
