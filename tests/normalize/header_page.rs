//! Tests for the header bytes that the loader maps.

use super::{
    MachineType, NormalizeChange, NormalizeKept, PeBuilder, PeFile, characteristics,
    move_nt_headers_into_the_dos_header, optional_offset, put32, section_header_offset, test_image,
};

fn get32(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap())
}

fn add32(raw: &mut [u8], offset: usize, value: u32) {
    let old = get32(raw, offset);
    put32(raw, offset, old + value);
}

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
    // The entry point refers to the CheckSum field, so a checksum fix would change the code. The
    // checksum stays wrong.
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
    assert_eq!(result.kept, [NormalizeKept::Checksum]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn a_directory_size_does_not_limit_the_referenced_header_bytes() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&raw);
    let import = optional + 112 + 8;
    let architecture = optional + 112 + 7 * 8;
    // The fields-only candidate would make the Architecture entry zero.
    put32(&mut raw, architecture, 0x1234);
    put32(&mut raw, architecture + 4, 8);
    // The Import range ends before the Architecture entry, but the loader ignores the size.
    put32(&mut raw, import, u32::try_from(architecture - 8).unwrap());
    put32(&mut raw, import + 4, 4);
    put32(&mut raw, optional + 64, 0);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn an_import_name_in_the_headers_keeps_its_bytes() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&raw);
    // The DLL name is in the Architecture entry. The NUL is the first byte of GlobalPtr.
    let architecture = optional + 112 + 7 * 8;
    let name = b"evil.dll\0";
    raw[architecture..architecture + name.len()].copy_from_slice(name);
    // One import descriptor at the start of `.rdata`, then the null descriptor. The FirstThunk
    // array has one ordinal import and the null thunk.
    let rdata = section_header_offset(&raw, 1);
    let rva = get32(&raw, rdata + 12);
    let start = usize::try_from(get32(&raw, rdata + 20)).unwrap();
    raw[start..start + 0x50].fill(0);
    put32(&mut raw, start + 12, u32::try_from(architecture).unwrap());
    put32(&mut raw, start + 16, rva + 0x40);
    put32(&mut raw, start + 0x40, 1);
    put32(&mut raw, start + 0x44, 0x8000_0000);
    let import = optional + 112 + 8;
    put32(&mut raw, import, rva);
    put32(&mut raw, import + 4, 0x28);
    put32(&mut raw, optional + 64, 0);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    // The fields-only candidate would make the Architecture entry zero, and so the DLL name.
    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn nonzero_bytes_after_the_section_table_keep_the_headers() {
    let mut raw = test_image().try_build().unwrap();
    move_nt_headers_into_the_dos_header(&mut raw);
    // No data directory refers to these bytes, but an indirect RVA can. The NT-header move would
    // grow the section table over them.
    let table_end = section_header_offset(&raw, 2);
    let name = b"KERNEL32.dll\0";
    raw[table_end..table_end + name.len()].copy_from_slice(name);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    assert_eq!(file.try_build().unwrap(), raw);
}

/// Make a file where the first section starts at RVA 0x2000 and `SizeOfHeaders` is 0x1200.
fn headers_up_to_the_second_page() -> Vec<u8> {
    let built = test_image().try_build().unwrap();
    let optional = optional_offset(&built);
    let headers = usize::try_from(get32(&built, optional + 60)).unwrap();
    // Add zero padding after the headers, so that the sections start at file offset 0x1200.
    let mut raw = built[..headers].to_vec();
    raw.resize(0x1200, 0);
    raw.extend_from_slice(&built[headers..]);
    let shift = u32::try_from(0x1200 - headers).unwrap();
    for index in 0..2 {
        let section = section_header_offset(&raw, index);
        add32(&mut raw, section + 12, 0x1000);
        add32(&mut raw, section + 20, shift);
    }
    // Move the entry point, BaseOfCode and SizeOfImage by one page too.
    for field in [16, 20, 56] {
        add32(&mut raw, optional + field, 0x1000);
    }
    put32(&mut raw, optional + 60, 0x1200);
    put32(&mut raw, optional + 64, 0);
    raw
}

#[test]
fn a_smaller_size_of_headers_does_not_open_a_gap() {
    let raw = headers_up_to_the_second_page();
    assert_eq!(get32(&raw, section_header_offset(&raw, 0) + 12), 0x2000);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    // The aligned header end must stay at the first section RVA 0x2000. A SizeOfHeaders of 0x200
    // would put it at 0x1000.
    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert!(
        !result
            .changes
            .iter()
            .any(|change| matches!(change, NormalizeChange::SizeOfHeaders { .. }))
    );
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::SectionAddresses]);
    assert_eq!(file.try_build().unwrap(), raw);
}

/// Report the checksum when no candidate is accepted and the fix on the original is refused.
#[test]
fn a_checksum_fix_without_a_candidate_is_reported() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&raw);
    // The entry point refers to the CheckSum field, and the checksum is wrong.
    put32(
        &mut raw,
        optional + 16,
        u32::try_from(optional + 64).unwrap(),
    );
    put32(&mut raw, optional + 64, 1);
    // The Architecture entry makes all candidates fail, so the original stays.
    let architecture = optional + 112 + 7 * 8;
    put32(&mut raw, architecture, 0x1234);
    put32(&mut raw, architecture + 4, 8);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(
        result.kept,
        [NormalizeKept::HeaderBytesInUse, NormalizeKept::Checksum]
    );
    assert_eq!(file.try_build().unwrap(), raw);
}
