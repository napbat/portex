use super::*;

#[test]
fn test_section_header_size() {
    assert_eq!(SectionHeader::SIZE, 40);
}

#[test]
fn test_section_header_name() {
    let mut header = SectionHeader {
        name: [0u8; 8],
        virtual_size: 0,
        virtual_address: 0,
        size_of_raw_data: 0,
        pointer_to_raw_data: 0,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: 0,
    };
    header.set_name(".text");
    assert_eq!(header.name_str(), ".text");
}

#[test]
fn test_section_header_roundtrip() {
    let original = SectionHeader {
        name: *b".text\0\0\0",
        virtual_size: 0x1000,
        virtual_address: 0x1000,
        size_of_raw_data: 0x200,
        pointer_to_raw_data: 0x200,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
    };

    let bytes = original.to_bytes();
    let parsed = SectionHeader::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_section_new() {
    let section = Section::new(".test", characteristics::READ | characteristics::WRITE);
    assert_eq!(section.name(), ".test");
    assert!(section.header.is_readable());
    assert!(section.header.is_writable());
}

#[test]
fn test_section_data_at_rva() {
    let mut section = Section::new(".data", characteristics::READ);
    section.header.virtual_address = 0x2000;
    section.set_data(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

    assert!(section.contains_rva(0x2000, 0));
    assert!(section.contains_rva(0x2004, 0));
    assert!(!section.contains_rva(0x1FFF, 0));
    assert!(!section.contains_rva(0x2005, 0));
    // The loader maps the complete page.
    assert!(section.contains_rva(0x2FFF, 0x1000));
    assert!(!section.contains_rva(0x3000, 0x1000));

    assert_eq!(section.data_at_rva(0x2001, 2), Some(&[0x22, 0x33][..]));
    assert_eq!(section.data_at_rva(0x2000, 10), None); // too long
}

#[test]
fn test_rva_to_offset_excludes_virtual_only_data() {
    let header = SectionHeader {
        name: *b".data\0\0\0",
        virtual_size: 0x1000,
        virtual_address: 0x2000,
        size_of_raw_data: 0x200,
        pointer_to_raw_data: 0x400,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: characteristics::INITIALIZED_DATA | characteristics::READ,
    };

    assert!(header.contains_rva(0x2200, 0x1000));
    assert_eq!(header.rva_to_offset(0x21ff, 0x1000), Some(0x5ff));
    assert_eq!(header.rva_to_offset(0x2200, 0x1000), None);
}

#[test]
fn raw_data_after_the_aligned_virtual_size_is_not_in_the_section() {
    // The loader places the next section at 0x2000. `SizeOfRawData` cannot make the section
    // larger than its aligned `VirtualSize`.
    let header = SectionHeader {
        virtual_size: 0x10,
        virtual_address: 0x1000,
        size_of_raw_data: 0x1200,
        pointer_to_raw_data: 0x200,
        ..SectionHeader::default()
    };
    assert_eq!(header.mapped_size(0x1000), 0x1000);
    assert!(header.contains_rva(0x1fff, 0x1000));
    assert!(!header.contains_rva(0x2000, 0x1000));
    assert_eq!(header.rva_to_offset(0x1fff, 0x1000), Some(0x11ff));
    assert_eq!(header.rva_to_offset(0x2000, 0x1000), None);

    // A `VirtualSize` of 0 makes `SizeOfRawData` the size.
    let raw_only = SectionHeader {
        virtual_size: 0,
        ..header
    };
    assert_eq!(raw_only.mapped_size(0x1000), 0x2000);
    assert_eq!(raw_only.rva_to_offset(0x2000, 0x1000), Some(0x1200));
    assert_eq!(SectionHeader::default().mapped_size(0x1000), 0);
    // The size cannot overflow.
    let large = SectionHeader {
        virtual_size: u32::MAX,
        ..SectionHeader::default()
    };
    assert_eq!(large.mapped_size(0x1000), 0x1_0000_0000);
}

#[test]
fn test_name_bytes_full_and_padded() {
    let mut header = SectionHeader::default();
    header.set_name(".verylongname");
    assert_eq!(header.name_bytes(), b".verylon");
    header.set_name("");
    assert_eq!(header.name_bytes(), b"");
}

#[test]
fn test_parse_short_header_fails() {
    assert!(SectionHeader::parse(&[0u8; SectionHeader::SIZE - 1]).is_err());
}

#[test]
fn test_try_materialize_virtual_data() {
    let header = SectionHeader {
        size_of_raw_data: 2,
        ..SectionHeader::default()
    };
    let mut section = Section::from_mapped_header_and_data(header, vec![1, 2, 0, 0]);
    assert_eq!(section.preserved_raw_size(), Some(2));
    section.try_materialize_virtual_data().unwrap();
    assert_eq!(section.preserved_raw_size(), None);
    assert_eq!(section.header.virtual_size, 4);
}
