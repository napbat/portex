//! Regression tests for the debug directory and the attribute certificate table.
//!
//! Each test builds its image with `PeBuilder` and then changes the bytes.

use portex::directories::{
    Certificate, CertificateRevision, CertificateType, CodeViewRsds, DebugDirectory, DebugInfo,
    DebugType,
};
use portex::headers::{CoffHeader, DataDirectoryType, MachineType};
use portex::image::{PeBuilder, PeFile, PeHeaders, PeImage};
use portex::section::characteristics;

const RDATA: u32 = 0x2000;

fn image_with_rdata(rdata: Vec<u8>) -> PeImage {
    let image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".text",
            vec![0xcc; 0x200],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".rdata",
            rdata,
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    assert_eq!(image.sections[1].header.virtual_address, RDATA);
    image
}

fn entry(debug_type: DebugType, size: usize, rva: u32, pointer: u32) -> [u8; 28] {
    DebugDirectory {
        debug_type: debug_type.as_u32(),
        size_of_data: u32::try_from(size).unwrap(),
        address_of_raw_data: rva,
        pointer_to_raw_data: pointer,
        ..DebugDirectory::default()
    }
    .to_bytes()
}

fn codeview(path: &[u8]) -> CodeViewRsds {
    CodeViewRsds {
        guid: [7; 16],
        age: 3,
        pdb_path: path.to_vec(),
    }
}

/// Build an image with a debug directory of `table_size` bytes at the start of `.rdata`.
fn debug_image(mut rdata: Vec<u8>, table: &[u8], table_size: u32) -> PeImage {
    rdata[..table.len()].copy_from_slice(table);
    let mut image = image_with_rdata(rdata);
    image.set_data_directory(DataDirectoryType::Debug, RDATA, table_size);
    image
}

fn rebuilt(image: &PeImage) -> PeImage {
    PeImage::parse(&image.try_build().unwrap()).unwrap()
}

fn is_invalid_data_directory(error: &portex::Error) -> bool {
    matches!(error.kind, portex::ErrorKind::InvalidDataDirectory(_))
}

#[test]
fn many_entries_with_one_payload_exceed_the_payload_budget() {
    // Before the fix, each entry kept its own copy of the same 1 MiB payload.
    let payload = 1 << 20;
    let count = DebugInfo::MAX_PAYLOAD_BYTES / payload + 1;
    let mut table = Vec::new();
    for _ in 0..count {
        table.extend_from_slice(&entry(DebugType::Pogo, payload, RDATA + 0x1000, 0));
    }
    let table_size = u32::try_from(table.len()).unwrap();
    let image = debug_image(vec![0x11; 0x1000 + payload], &table, table_size);

    assert!(is_invalid_data_directory(&image.debug_info().unwrap_err()));
    let file = PeFile::parse(&image.try_build().unwrap()).unwrap();
    assert!(is_invalid_data_directory(&file.debug_info().unwrap_err()));
}

#[test]
fn an_edited_codeview_record_reaches_update_debug() {
    let mut image = image_with_rdata(vec![0; 0x200]);
    image
        .update_debug_codeview(&codeview(b"old.pdb"), None)
        .unwrap();
    let mut image = rebuilt(&image);

    let mut info = image.debug_info().unwrap().unwrap();
    let mut record = info.codeview().unwrap().unwrap();
    record.pdb_path = b"new.pdb".to_vec();
    info.set_codeview(&record).unwrap();
    image.update_debug(&info, None).unwrap();

    let info = rebuilt(&image).debug_info().unwrap().unwrap();
    assert_eq!(info.pdb_path().as_deref(), Some("new.pdb"));
    assert_eq!(info.codeview().unwrap(), Some(record));
}

#[test]
fn an_ansi_pdb_path_keeps_the_entries_and_its_bytes() {
    let mut image = image_with_rdata(vec![0; 0x200]);
    image
        .update_debug_codeview(&codeview(b"abc.pdb"), None)
        .unwrap();
    let mut raw = image.try_build().unwrap();
    let at = raw.windows(7).position(|w| w == b"abc.pdb").unwrap();
    // 0xE9 is "é" in Windows-1252.
    raw[at] = 0xe9;
    let mut image = PeImage::parse(&raw).unwrap();

    let info = image.debug_info().unwrap().unwrap();
    assert_eq!(info.directories.len(), 1);
    assert_eq!(info.pdb_path().as_deref(), Some("\u{fffd}bc.pdb"));
    let record = info.codeview().unwrap().unwrap();
    assert_eq!(record.pdb_path, b"\xe9bc.pdb");
    assert_eq!(record.pdb_path_str(), None);

    image.update_debug(&info, None).unwrap();
    let info = rebuilt(&image).debug_info().unwrap().unwrap();
    assert_eq!(info.codeview().unwrap(), Some(record));
}

#[test]
fn the_first_rsds_record_gives_the_pdb_path() {
    let first = codeview(b"first.pdb").to_bytes();
    let second = codeview(b"second.pdb").to_bytes();
    let mut rdata = vec![0; 0x200];
    rdata[0x100..0x100 + first.len()].copy_from_slice(&first);
    rdata[0x180..0x180 + second.len()].copy_from_slice(&second);
    let mut table = entry(DebugType::CodeView, first.len(), RDATA + 0x100, 0).to_vec();
    table.extend_from_slice(&entry(DebugType::CodeView, second.len(), RDATA + 0x180, 0));
    let image = debug_image(rdata, &table, 56);

    let info = image.debug_info().unwrap().unwrap();
    assert_eq!(info.pdb_path().as_deref(), Some("first.pdb"));
    assert_eq!(info.codeview().unwrap(), Some(codeview(b"first.pdb")));
}

#[test]
fn a_nonzero_characteristics_field_keeps_the_entries() {
    let mut table = entry(DebugType::Repro, 0, 0, 0);
    table[0] = 1;
    let image = debug_image(vec![0; 0x200], &table, 28);

    let info = image.debug_info().unwrap().unwrap();
    assert_eq!(info.directories.len(), 1);
    assert_eq!(info.directories[0].characteristics, 1);
}

#[test]
fn a_directory_size_that_is_not_a_multiple_of_28_ignores_the_tail() {
    let mut table = entry(DebugType::Repro, 0, 0, 0).to_vec();
    table.extend_from_slice(&entry(DebugType::VcFeature, 0, 0, 0));
    let image = debug_image(vec![0; 0x200], &table, 61);

    let info = image.debug_info().unwrap().unwrap();
    assert_eq!(info.directories.len(), 2);
    assert_eq!(info.directories[1].get_type(), Some(DebugType::VcFeature));
}

#[test]
fn an_entry_with_only_a_file_offset_does_not_lose_its_payload() {
    let mut rdata = vec![0; 0x200];
    rdata[0x100..0x110].copy_from_slice(&[0x42; 16]);
    let mut image = rebuilt(&image_with_rdata(rdata));
    // The entry has no RVA. Only `PointerToRawData` finds its payload.
    let pointer = image.sections[1].header.pointer_to_raw_data + 0x100;
    image.sections[1].data[..28].copy_from_slice(&entry(DebugType::Misc, 16, 0, pointer));
    image.set_data_directory(DataDirectoryType::Debug, RDATA, 28);
    let raw = image.try_build().unwrap();

    // Before the fix, `update_debug` wrote the entry with `SizeOfData` 0.
    let mut image = PeImage::parse(&raw).unwrap();
    let info = image.debug_info().unwrap().unwrap();
    assert_eq!(info.data, [None]);
    assert!(is_invalid_data_directory(
        &image.update_debug(&info, None).unwrap_err()
    ));

    let info = PeFile::parse(&raw).unwrap().debug_info().unwrap().unwrap();
    assert_eq!(info.data, [Some(vec![0x42; 16])]);
    image.update_debug(&info, None).unwrap();
    let info = rebuilt(&image).debug_info().unwrap().unwrap();
    assert_eq!(info.directories[0].size_of_data, 16);
    assert_eq!(info.data, [Some(vec![0x42; 16])]);
}

#[test]
fn debug_types_17_to_21_have_names() {
    for (value, name) in [
        (17, DebugType::EmbeddedPortablePdb),
        (18, DebugType::Spgo),
        (19, DebugType::PdbChecksum),
        (20, DebugType::ExDllCharacteristics),
        (21, DebugType::PerfMap),
    ] {
        assert_eq!(DebugType::from_u32(value), Some(name));
    }
    assert_eq!(DebugType::from_u32(0), Some(DebugType::Unknown));
    assert_eq!(DebugType::from_u32(22), None);
    assert_eq!(
        CertificateType::from_u16(0x0EF0),
        CertificateType::EfiPkcs115
    );
}

#[test]
fn a_last_certificate_without_padding_is_a_certificate_table() {
    // One `WIN_CERTIFICATE` of 13 bytes. The table ends before the 3 padding bytes.
    let mut table = vec![0u8; 13];
    table[..4].copy_from_slice(&13u32.to_le_bytes());
    table[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
    table[6..8].copy_from_slice(&0x0002u16.to_le_bytes());
    table[8..].copy_from_slice(&[1, 2, 3, 4, 5]);

    let mut raw = image_with_rdata(vec![0; 0x200]).try_build().unwrap();
    assert_eq!(raw.len() % 8, 0);
    let headers = PeHeaders::from_slice(&raw).unwrap();
    // The PE32+ data directories start at offset 112. Security is entry 4.
    let security = usize::try_from(headers.pe_offset).unwrap() + 4 + CoffHeader::SIZE + 112 + 32;
    let offset = u32::try_from(raw.len()).unwrap();
    raw[security..security + 4].copy_from_slice(&offset.to_le_bytes());
    raw[security + 4..security + 8].copy_from_slice(&13u32.to_le_bytes());
    raw.extend_from_slice(&table);

    let file = PeFile::parse(&raw).unwrap();
    let certificates = file.security().unwrap().unwrap().certificates;
    assert_eq!(
        certificates,
        [Certificate {
            length: 13,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![1, 2, 3, 4, 5],
        }]
    );
    assert_eq!(file.try_build().unwrap(), raw);
}

/// Return the `PointerToRawData` field of each entry of a debug directory of `count` entries
/// at `rva`.
fn debug_pointers(image: &PeImage, rva: u32, count: usize) -> Vec<u32> {
    let table = image.read_rva(rva, count * DebugDirectory::SIZE).unwrap();
    table
        .as_chunks::<{ DebugDirectory::SIZE }>()
        .0
        .iter()
        .map(|bytes| DebugDirectory::parse(bytes).unwrap().pointer_to_raw_data)
        .collect()
}

#[test]
fn a_layout_change_rebases_each_debug_file_offset_by_its_distance() {
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".text",
            vec![0xcc; 0x200],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".rdata",
            vec![0; 0x200],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .add_section(
            ".data",
            vec![0; 0x200],
            characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
        )
        .try_build()
        .unwrap();
    let data = image.sections[2].header.virtual_address;
    let payload = data + 0x80;
    let offset = image.rva_to_offset(payload).unwrap();
    // The first entry is correct. The second entry is stale: 0x10 bytes after the payload.
    let mut table = entry(DebugType::CodeView, 0x10, payload, offset).to_vec();
    table.extend_from_slice(&entry(DebugType::CodeView, 0x10, payload, offset + 0x10));
    image.write_at_rva(data, &table).unwrap();
    image.set_data_directory(DataDirectoryType::Debug, data, 56);

    // The raw data of `.rdata` grows, so the raw data of `.data` moves 0x400 bytes.
    image.sections[1].data.resize(0x600, 0x11);
    image.try_update_layout().unwrap();
    let moved = image.rva_to_offset(payload).unwrap();
    assert_eq!(moved, offset + 0x400);

    // Before the fix, the build set the stale field to the new offset of the payload.
    let rebuilt = rebuilt(&image);
    assert_eq!(debug_pointers(&rebuilt, data, 2), [moved, moved + 0x10]);
}
