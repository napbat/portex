use super::*;

#[test]
fn test_cli_header_size() {
    assert_eq!(CliHeader::SIZE, 72);
}

#[test]
fn test_cli_header_buffer_too_small() {
    let data = [0u8; 71];
    assert!(CliHeader::parse(&data).is_err());
}

#[test]
fn test_cli_header_roundtrip() {
    let header = CliHeader {
        cb: 72,
        major_runtime_version: 2,
        minor_runtime_version: 5,
        metadata_rva: 0x2000,
        metadata_size: 0x1234,
        flags: CliHeader::FLAG_ILONLY | CliHeader::FLAG_STRONGNAMESIGNED,
        entry_point_token_or_rva: 0x0600_0001,
        resources_rva: 0x3000,
        resources_size: 0x100,
        strong_name_signature_rva: 0,
        strong_name_signature_size: 0,
        code_manager_table_rva: 0,
        code_manager_table_size: 0,
        vtable_fixups_rva: 0,
        vtable_fixups_size: 0,
        export_address_table_jumps_rva: 0,
        export_address_table_jumps_size: 0,
        managed_native_header_rva: 0,
        managed_native_header_size: 0,
    };

    let bytes = header.to_bytes();
    let parsed = CliHeader::parse(&bytes).unwrap();

    assert_eq!(header, parsed);
}

#[test]
fn test_cli_header_default() {
    let header = CliHeader::default();
    assert_eq!(header.cb, 72);
    assert_eq!(header.major_runtime_version, 2);
    assert_eq!(header.minor_runtime_version, 5);
}

#[test]
fn test_cli_builder() {
    let mut builder = CliBuilder::new();

    builder
        .metadata(0x2000, 0x1234)
        .entry_point_token(0x0600_0001)
        .il_only(true)
        .resources(0x3000, 0x100);

    let (data, size) = builder.build();
    assert_eq!(size, CliHeader::SIZE_U32);
    assert_eq!(data.len(), CliHeader::SIZE);

    let header = CliHeader::parse(&data).unwrap();
    assert_eq!(header.metadata_rva, 0x2000);
    assert_eq!(header.metadata_size, 0x1234);
    assert_eq!(header.entry_point_token_or_rva, 0x0600_0001);
    assert!(header.is_il_only());
    assert_eq!(header.resources_rva, 0x3000);
    assert_eq!(header.resources_size, 0x100);
}

#[test]
fn test_cli_builder_from_header() {
    let original = CliHeader {
        metadata_rva: 0x5000,
        metadata_size: 0x2000,
        ..Default::default()
    };

    let builder = CliBuilder::from_header(original);
    let header = builder.into_header();

    assert_eq!(header.metadata_rva, 0x5000);
    assert_eq!(header.metadata_size, 0x2000);
}
