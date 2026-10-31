//! Regression tests for the section extent: the loader maps `VirtualSize` (or `SizeOfRawData` if
//! `VirtualSize` is 0), aligned to `SectionAlignment`. Raw data after that size belongs to no RVA.

use portex::headers::{CoffHeader, MachineType};
use portex::image::{PeBuilder, PeHeaders, PeImage};
use portex::section::characteristics;
use portex::{ParseOptions, ValidationCode};

/// Build a file with `.text` (VA 0x1000, 16 bytes of 0xC3) and `.data` (VA 0x2000, 16 bytes of
/// 0x5A, raw data at 0x400).
fn two_section_file() -> Vec<u8> {
    PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".text",
            vec![0xc3; 16],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".data",
            vec![0x5a; 16],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap()
        .try_build()
        .unwrap()
}

/// Return the offset of the section header at `index` in `raw`.
fn section_header_offset(raw: &[u8], index: usize) -> usize {
    let headers = PeHeaders::from_slice(raw).unwrap();
    usize::try_from(headers.pe_offset).unwrap()
        + 4
        + CoffHeader::SIZE
        + usize::from(headers.coff_header.size_of_optional_header)
        + index * 40
}

/// Set the `SizeOfRawData` of `.text` to `raw_size`, and pad the file with 0xEE to hold it.
fn file_with_large_text_raw_size(raw_size: u32) -> Vec<u8> {
    let mut raw = two_section_file();
    let text = section_header_offset(&raw, 0);
    raw[text + 16..text + 20].copy_from_slice(&raw_size.to_le_bytes());
    let end = 0x200 + raw_size as usize;
    if raw.len() < end {
        raw.resize(end, 0xee);
    }
    raw
}

#[test]
fn headers_rva_to_offset_stops_at_the_mapped_size() {
    let raw = file_with_large_text_raw_size(0x1200);
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let data = headers.section_headers[1].pointer_to_raw_data;
    assert_eq!(data, 0x400);
    assert_eq!(headers.rva_to_offset(0x2000), Some(data));
    assert_eq!(headers.rva_to_offset(0x1fff), Some(0x11ff));
}

#[test]
fn image_reads_stop_at_the_mapped_size() {
    let raw = file_with_large_text_raw_size(0x1200);
    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.section_by_rva(0x2000).unwrap().name(), ".data");
    assert_eq!(image.rva_to_offset(0x2000), Some(0x400));
    assert_eq!(image.read_at_rva(0x2000, 4), Some(&[0x5a; 4][..]));
    assert_eq!(image.read_rva(0x2000, 4).as_deref(), Some(&[0x5a; 4][..]));
    // A read cannot go from `.text` into the raw bytes after its mapped size.
    assert_eq!(image.read_at_rva(0x1ffe, 4), None);
    assert_eq!(
        image.read_rva(0x1ffe, 4).as_deref(),
        Some(&[0xee, 0xee, 0x5a, 0x5a][..])
    );
}

#[test]
fn validate_does_not_report_a_virtual_overlap_for_large_raw_data() {
    let raw = file_with_large_text_raw_size(0x1200);
    let image = PeImage::parse(&raw).unwrap();
    let result = image.validate();
    assert!(
        !result.iter().any(|issue| {
            issue.code == ValidationCode::OverlappingSections
                && issue.message.contains("virtual memory")
        }),
        "{result:?}"
    );
}

#[test]
fn build_keeps_the_next_section_after_the_mapped_size() {
    // The loader accepts this file: `.data` follows the aligned `VirtualSize` of `.text`.
    let raw = file_with_large_text_raw_size(0x1800);
    let image = PeImage::parse(&raw).unwrap();
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.sections[1].header.virtual_address, 0x2000);
    assert_eq!(rebuilt.optional_header.size_of_image(), 0x3000);
    assert_eq!(rebuilt.read_rva(0x2000, 4).as_deref(), Some(&[0x5a; 4][..]));
}

#[test]
fn mapped_image_copies_only_the_mapped_raw_bytes() {
    let raw = file_with_large_text_raw_size(0x1800);
    let mapped = PeImage::parse(&raw).unwrap().to_mapped_image().unwrap();
    assert_eq!(mapped.len(), 0x3000);
    assert_eq!(&mapped[0x2000..0x2010], &[0x5a; 16]);
    assert!(mapped[0x2010..].iter().all(|byte| *byte == 0));
}

#[test]
fn mapped_parse_reads_only_the_mapped_size() {
    let mut mapped = PeImage::parse(&two_section_file())
        .unwrap()
        .to_mapped_image()
        .unwrap();
    let text = section_header_offset(&mapped, 0);
    mapped[text + 16..text + 20].copy_from_slice(&0x1800u32.to_le_bytes());
    let image = PeImage::parse_with_options(&mapped, ParseOptions::mapped()).unwrap();
    assert_eq!(image.sections[0].data.len(), 0x1000);
    assert_eq!(image.section_by_rva(0x2000).unwrap().name(), ".data");
}
