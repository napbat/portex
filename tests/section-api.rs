//! Regression tests for the section and header APIs.

use portex::headers::{CoffHeader, DataDirectory, DataDirectoryType, SectionHeader};
use portex::image::{PeBuilder, PeHeaders};
use portex::section::characteristics;
use portex::{LayoutConfig, SliceReader};

#[test]
fn set_name_does_not_cut_a_character() {
    let mut header = SectionHeader::default();
    // Three ASCII bytes and three 2-byte characters: the limit is inside the third character.
    header.set_name(".ab\u{e9}\u{e9}\u{e9}");
    assert_eq!(header.name_str(), ".ab\u{e9}\u{e9}");
    assert_eq!(header.name_bytes().len(), 7);
}

#[test]
fn try_set_name_rejects_a_long_name() {
    let mut header = SectionHeader::default();
    header.try_set_name(".text").unwrap();
    assert!(header.try_set_name(".textlong").is_err());
    assert_eq!(header.name_str(), ".text");
    header.try_set_name(".1234567").unwrap();
    assert_eq!(header.name_bytes(), b".1234567");
}

#[test]
fn read_sections_with_a_huge_count_is_an_error() {
    let reader = SliceReader::new(&[0; 80]);
    assert!(SectionHeader::read_sections(&reader, 0, usize::MAX / 64).is_err());
    assert_eq!(
        SectionHeader::read_sections(&reader, 0, 2).unwrap().len(),
        2
    );
}

#[test]
fn read_directories_with_a_huge_count_is_an_error() {
    let reader = SliceReader::new(&[0; 16]);
    // The table size fits in `usize`, but the memory for the entries does not.
    assert!(DataDirectory::read_directories(&reader, 0, usize::MAX / 9).is_err());
    assert!(DataDirectory::read_directories(&reader, 0, u32::MAX as usize).is_err());
    assert_eq!(
        DataDirectory::read_directories(&reader, 0, 2)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn headers_data_directory_handles_a_short_table() {
    let mut raw = PeBuilder::new()
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    assert_eq!(
        headers.data_directory(DataDirectoryType::Import),
        Some(&DataDirectory::default())
    );

    // Set `NumberOfRvaAndSizes` of the PE32+ optional header to 0.
    let field = usize::try_from(headers.pe_offset).unwrap() + 4 + CoffHeader::SIZE + 108;
    raw[field..field + 4].fill(0);
    let headers = PeHeaders::from_slice(&raw).unwrap();
    assert_eq!(headers.data_directory(DataDirectoryType::Import), None);
}

#[test]
fn layout_config_has_a_constructor() {
    let config = LayoutConfig::new(0x200, 0x1000);
    assert_eq!(config.align_file(0x201), 0x400);
    assert_eq!(config.align_section(0x1001), 0x2000);
}
