//! Regression tests for edits that change sections: an edit never moves a section, never
//! overwrites uninitialized data, and never leaves a gap that the loader rejects.

use portex::headers::{CoffHeader, MachineType};
use portex::image::{PeBuilder, PeHeaders, PeImage};
use portex::section::{Section, characteristics};
use portex::{ExportTable, ValidationCode};

const READ_DATA: u32 = characteristics::INITIALIZED_DATA | characteristics::READ;

/// Build `.text` (VA 0x1000), `.rdata` (VA 0x2000) and `.data` (VA 0x3000), 16 bytes each.
fn three_sections() -> PeImage {
    PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".text",
            vec![0xc3; 16],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(".rdata", vec![1; 16], READ_DATA)
        .add_section(".data", vec![2; 16], READ_DATA | characteristics::WRITE)
        .try_build()
        .unwrap()
}

/// Return an export table that needs more than one page.
fn large_exports() -> ExportTable {
    let mut exports = ExportTable::default();
    exports.set_dll_name("large.dll");
    for index in 0..400 {
        exports.add_export(Some(&format!("ExportedFunction{index:04}")), 0x1000);
    }
    exports
}

fn section_rvas(image: &PeImage) -> Vec<u32> {
    image
        .sections
        .iter()
        .map(|section| section.header.virtual_address)
        .collect()
}

#[test]
fn append_to_a_named_section_that_does_not_fit_is_an_error() {
    let mut image = three_sections();
    let before = image.clone();
    assert!(
        image
            .update_exports(&large_exports(), Some(".rdata"))
            .is_err()
    );
    assert_eq!(image, before);
    assert!(image.try_append_to_section(".rdata", &[0; 0x2000]).is_err());
    assert_eq!(image, before);
}

#[test]
fn append_to_the_default_section_falls_back_to_the_last_section() {
    let mut image = three_sections();
    let rva = image.update_exports(&large_exports(), None).unwrap();
    assert_eq!(section_rvas(&image), [0x1000, 0x2000, 0x3000]);
    assert!(rva >= 0x3000);
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(section_rvas(&rebuilt), [0x1000, 0x2000, 0x3000]);
    assert_eq!(rebuilt.exports().unwrap().exports.len(), 400);
}

#[test]
fn append_goes_after_uninitialized_data() {
    let mut image = PeBuilder::new()
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section(".data", vec![2; 0x100], READ_DATA | characteristics::WRITE)
        .try_build()
        .unwrap();
    image.sections[1].header.virtual_size = 0x3000;
    image.try_update_layout().unwrap();
    assert_eq!(image.optional_header.size_of_image(), 0x5000);

    let mut exports = ExportTable::default();
    exports.set_dll_name("bss.dll");
    exports.add_export(Some("Function"), 0x1000);
    let rva = image.update_exports(&exports, Some(".data")).unwrap();
    assert_eq!(rva, 0x5000);
    let data = &image.sections[1];
    assert!(data.header.virtual_size > 0x3000);
    assert!(data.data[0x100..0x3000].iter().all(|byte| *byte == 0));
    assert_eq!(image.optional_header.size_of_image(), 0x6000);
}

#[test]
fn section_append_does_not_shrink_the_virtual_size() {
    let mut section = Section::new(".data", READ_DATA);
    section.set_data(vec![1; 0x10]);
    section.header.virtual_size = 0x100;
    assert_eq!(section.try_append_data(&[2, 3]).unwrap(), 0x100);
    assert_eq!(section.header.virtual_size, 0x102);
    assert_eq!(&section.data[0x10..0x100], &[0; 0xf0]);
    assert_eq!(&section.data[0x100..], &[2, 3]);
}

#[test]
fn appended_directories_are_8_byte_aligned() {
    let mut image = PeBuilder::new()
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section(".odd", vec![1; 5], READ_DATA)
        .try_build()
        .unwrap();
    let mut exports = ExportTable::default();
    exports.set_dll_name("odd.dll");
    exports.add_export(Some("Function"), 0x1000);
    let rva = image.update_exports(&exports, Some(".odd")).unwrap();
    assert_eq!(rva, 0x2008);
    assert_eq!(image.try_append_to_section(".odd", &[7]).unwrap() % 8, 0);
}

#[test]
fn removing_a_middle_section_is_an_error() {
    let mut image = three_sections();
    let before = image.clone();
    assert!(image.remove_section(".rdata").is_err());
    assert!(image.remove_section_at(0).is_err());
    assert!(image.remove_section("missing").is_err());
    assert!(image.remove_section_at(3).is_err());
    assert_eq!(image, before);

    let removed = image.remove_section(".data").unwrap();
    assert_eq!(removed.name(), ".data");
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(section_rvas(&rebuilt), [0x1000, 0x2000]);
    assert_eq!(rebuilt.optional_header.size_of_image(), 0x3000);
}

#[test]
fn shrinking_a_middle_section_keeps_its_rva_range() {
    let mut image = PeBuilder::new()
        .add_section(".text", vec![0xc3; 0x3000], characteristics::CODE)
        .add_section(".data", vec![2; 16], READ_DATA)
        .try_build()
        .unwrap();
    image.try_resize_section(".text", 0x10).unwrap();
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(section_rvas(&rebuilt), [0x1000, 0x4000]);
    assert_eq!(rebuilt.sections[0].header.virtual_size, 0x3000);
    assert_eq!(rebuilt.sections[0].header.size_of_raw_data, 0x200);
    assert!(!rebuilt.validate().has_errors());

    // A middle section cannot grow into the next section.
    assert!(image.try_resize_section(".text", 0x3001).is_err());
    assert!(image.try_resize_section("missing", 1).is_err());
    // The last section can shrink.
    image.try_resize_section(".data", 4).unwrap();
    assert_eq!(image.sections[1].header.virtual_size, 4);
}

#[test]
fn adding_a_section_does_not_move_the_first_section() {
    // With a low alignment, the first section follows the section table directly.
    let mut image = PeBuilder::new()
        .file_alignment(0x200)
        .section_alignment(0x200)
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .try_build()
        .unwrap();
    assert_eq!(image.sections[0].header.virtual_address, 0x200);
    image
        .try_add_section_with_data(".a", vec![1; 16], READ_DATA)
        .unwrap();
    image
        .try_add_section_with_data(".b", vec![1; 16], READ_DATA)
        .unwrap();
    let before = image.clone();
    // The fourth entry makes the section table end after 0x200.
    assert!(
        image
            .try_add_section_with_data(".c", vec![1; 16], READ_DATA)
            .is_err()
    );
    assert_eq!(image, before);
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.sections[0].header.virtual_address, 0x200);
}

#[test]
fn validate_reports_a_gap_between_sections() {
    let mut raw = three_sections().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let optional = usize::try_from(headers.pe_offset).unwrap() + 4 + CoffHeader::SIZE;
    let table = optional + usize::from(headers.coff_header.size_of_optional_header);
    // Move `.data` from 0x3000 to 0x4000, and make `SizeOfImage` hold it.
    raw[table + 80 + 12..table + 80 + 16].copy_from_slice(&0x4000u32.to_le_bytes());
    raw[optional + 56..optional + 60].copy_from_slice(&0x5000u32.to_le_bytes());

    let result = PeImage::parse(&raw).unwrap().validate();
    assert!(
        result.errors().any(|issue| {
            issue.code == ValidationCode::InvalidSectionLayout && issue.message.contains("gap")
        }),
        "{result:?}"
    );
    assert!(!three_sections().validate().has_errors());
}
