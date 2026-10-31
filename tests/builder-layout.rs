//! Regression tests for the builder and for the layout of rebuilt images.

use portex::headers::{CoffHeader, MachineType};
use portex::image::{PeBuilder, PeHeaders, PeImage};
use portex::section::characteristics;

const READ_DATA: u32 = characteristics::INITIALIZED_DATA | characteristics::READ;

fn section_rvas(image: &PeImage) -> Vec<u32> {
    image
        .sections
        .iter()
        .map(|section| section.header.virtual_address)
        .collect()
}

#[test]
fn empty_builder_section_gets_a_virtual_size() {
    let image = PeBuilder::new()
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section(".bss", Vec::new(), characteristics::UNINITIALIZED_DATA)
        .add_section(".data", vec![2; 16], READ_DATA)
        .try_build()
        .unwrap();
    assert_eq!(section_rvas(&image), [0x1000, 0x2000, 0x3000]);
    assert_eq!(image.sections[1].header.virtual_size, 0x1000);
    assert!(!image.validate().has_errors(), "{:?}", image.validate());
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.sections[1].header.virtual_size, 0x1000);
}

#[test]
fn builder_section_with_a_virtual_size() {
    let image = PeBuilder::new()
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section_with_virtual_size(
            ".bss",
            Vec::new(),
            0x2800,
            characteristics::UNINITIALIZED_DATA,
        )
        .add_section_with_virtual_size(".data", vec![2; 0x40], 0x10, READ_DATA)
        .try_build()
        .unwrap();
    assert_eq!(section_rvas(&image), [0x1000, 0x2000, 0x5000]);
    assert_eq!(image.sections[1].header.virtual_size, 0x2800);
    assert_eq!(image.sections[1].header.size_of_raw_data, 0);
    // A virtual size smaller than the data does not cut the data.
    assert_eq!(image.sections[2].header.virtual_size, 0x40);
    assert_eq!(image.optional_header.size_of_image(), 0x6000);
    assert!(!image.validate().has_errors(), "{:?}", image.validate());
}

#[test]
fn machine_keeps_an_image_base_that_the_caller_set() {
    let image = PeBuilder::new()
        .image_base(0x1000_0000)
        .machine(MachineType::I386)
        .try_build()
        .unwrap();
    assert_eq!(image.image_base(), 0x1000_0000);
    let image = PeBuilder::new()
        .machine(MachineType::I386)
        .try_build()
        .unwrap();
    assert_eq!(image.image_base(), 0x40_0000);
    assert_eq!(
        PeBuilder::new().try_build().unwrap().image_base(),
        0x1_4000_0000
    );
}

/// Make a mapped image of two sections, and set `PointerToRawData` of `.data` to `offset`.
fn mapped_image_with_data_offset(offset: u32) -> Vec<u8> {
    let mut mapped = PeBuilder::new()
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section(".data", vec![2; 16], READ_DATA)
        .try_build()
        .unwrap()
        .to_mapped_image()
        .unwrap();
    let headers = PeHeaders::from_slice(&mapped).unwrap();
    let table = usize::try_from(headers.pe_offset).unwrap()
        + 4
        + CoffHeader::SIZE
        + usize::from(headers.coff_header.size_of_optional_header);
    let field = table + 40 + 20;
    mapped[field..field + 4].copy_from_slice(&offset.to_le_bytes());
    mapped
}

#[test]
fn mapped_source_raw_offsets_do_not_decide_the_output_size() {
    let mapped = mapped_image_with_data_offset(0x0100_0000);
    let image = PeImage::parse_mapped(&mapped).unwrap();
    let raw = image.try_build().unwrap();
    assert_eq!(raw.len(), 0x600);
    let rebuilt = PeImage::parse(&raw).unwrap();
    assert_eq!(rebuilt.sections[1].header.pointer_to_raw_data, 0x400);
    assert_eq!(rebuilt.read_rva(0x2000, 4).as_deref(), Some(&[2; 4][..]));
}

#[test]
fn mapped_source_build_does_not_keep_the_raw_offsets() {
    let mut mapped = mapped_image_with_data_offset(0x0100_0000);
    // A `SectionAlignment` of 0 makes the layout update fail.
    let headers = PeHeaders::from_slice(&mapped).unwrap();
    let field = usize::try_from(headers.pe_offset).unwrap() + 4 + CoffHeader::SIZE + 32;
    mapped[field..field + 4].copy_from_slice(&0u32.to_le_bytes());
    let image = PeImage::parse_mapped(&mapped).unwrap();
    assert!(image.try_build().is_err());
}
