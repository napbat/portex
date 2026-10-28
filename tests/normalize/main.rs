//! Tests for `PeFile::normalize`.
//!
//! Each test builds its image with `PeBuilder` and then changes the bytes. The tests check that
//! normalization keeps the loader view: the section RVAs, the section data, and the header bytes
//! that the entry point or a data directory refers to.

mod bound_imports;
mod debug_offsets;
mod header_page;
mod low_alignment;

use portex::directories::{Certificate, CertificateRevision, CertificateType, SecurityDirectory};
use portex::headers::{CoffHeader, DataDirectoryType, MachineType, SectionHeader};
use portex::image::{
    NormalizeChange, NormalizeKept, PeBuilder, PeFile, PeHeaders, PeImage, ValidationCode,
};
use portex::section::characteristics;
use portex::{Subsystem, compute_pe_checksum};

fn test_image() -> PeImage {
    PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(
            ".text",
            vec![0xcc; 0x180],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".rdata",
            vec![0x5a; 0x180],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap()
}

fn optional_offset(raw: &[u8]) -> usize {
    usize::try_from(PeHeaders::from_slice(raw).unwrap().pe_offset).unwrap() + 4 + CoffHeader::SIZE
}

fn section_header_offset(raw: &[u8], index: usize) -> usize {
    let headers = PeHeaders::from_slice(raw).unwrap();
    optional_offset(raw)
        + usize::from(headers.coff_header.size_of_optional_header)
        + index * SectionHeader::SIZE
}

fn put32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Move the NT headers to 0x10, inside the DOS header.
fn move_nt_headers_into_the_dos_header(raw: &mut [u8]) {
    let old = usize::try_from(PeHeaders::from_slice(raw).unwrap().pe_offset).unwrap();
    let headers = PeHeaders::from_slice(raw).unwrap();
    let length = section_header_offset(raw, headers.section_headers.len()) - old;
    let mut nt_headers = raw[old..old + length].to_vec();
    raw[old..old + length].fill(0);
    // The `e_lfanew` field at 0x3C is then the `BaseOfCode` field of the PE32+ optional header.
    put32(&mut nt_headers, 4 + CoffHeader::SIZE + 20, 0x10);
    raw[0x10..0x10 + length].copy_from_slice(&nt_headers);
}

fn section_rvas(image: &PeImage) -> Vec<u32> {
    image
        .sections
        .iter()
        .map(|section| section.header.virtual_address)
        .collect()
}

fn has_issue(image: &PeImage, code: ValidationCode) -> bool {
    image
        .validate()
        .issues
        .iter()
        .any(|issue| issue.code == code)
}

#[test]
fn a_normal_file_does_not_change() {
    let raw = test_image().try_build().unwrap();
    let mut file = PeFile::parse(&raw).unwrap();

    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, []);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn sections_that_share_raw_data_get_their_own_raw_ranges() {
    let mut raw = test_image().try_build().unwrap();
    let text = PeHeaders::from_slice(&raw).unwrap().section_headers[0].pointer_to_raw_data;
    let rdata = section_header_offset(&raw, 1);
    put32(&mut raw, rdata + 20, text);
    let original = PeImage::parse(&raw).unwrap();
    assert!(has_issue(&original, ValidationCode::OverlappingSections));

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, [NormalizeChange::Section { index: 1 }]);
    assert_eq!(result.kept, []);
    let normalized = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert!(!has_issue(&normalized, ValidationCode::OverlappingSections));
    assert_eq!(section_rvas(&normalized), section_rvas(&original));
    assert_eq!(normalized.sections[1].data, original.sections[1].data);
}

#[test]
fn nt_headers_in_the_dos_header_move_after_it() {
    let mut raw = test_image().try_build().unwrap();
    move_nt_headers_into_the_dos_header(&mut raw);
    let original = PeImage::parse(&raw).unwrap();

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    // The move writes 0x10 into `BaseOfCode`, so the code and data fields change too.
    assert_eq!(
        result.changes,
        [
            NormalizeChange::NtHeadersOffset {
                old: 0x10,
                new: 0x40
            },
            NormalizeChange::CodeAndDataFields,
        ]
    );
    assert_eq!(result.kept, []);
    let normalized = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(normalized.dos_header.e_lfanew, 0x40);
    assert_eq!(normalized.entry_point(), original.entry_point());
    assert_eq!(section_rvas(&normalized), section_rvas(&original));
    assert!(!has_issue(
        &normalized,
        ValidationCode::InconsistentHeadersSize
    ));
}

#[test]
fn code_in_the_headers_keeps_the_headers() {
    let mut raw = test_image().try_build().unwrap();
    move_nt_headers_into_the_dos_header(&mut raw);
    // The entry point is in the headers, so the header bytes are code.
    put32(&mut raw, 0x10 + 4 + CoffHeader::SIZE + 16, 0x100);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn a_data_directory_in_the_headers_keeps_its_bytes() {
    let mut raw = test_image().try_build().unwrap();
    move_nt_headers_into_the_dos_header(&mut raw);
    // The import directory points to the optional header. A move of the NT headers would change
    // these bytes.
    let optional = optional_offset(&raw);
    put32(&mut raw, optional + 112 + 8, 0x30);
    put32(&mut raw, optional + 112 + 12, 0x14);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(result.kept, [NormalizeKept::HeaderBytesInUse]);
    let normalized = file.try_build().unwrap();
    assert_eq!(normalized[0x30..0x44], raw[0x30..0x44]);
}

#[test]
fn an_unaligned_section_rva_keeps_the_layout() {
    let mut raw = test_image().try_build().unwrap();
    let rdata = section_header_offset(&raw, 1);
    put32(&mut raw, rdata + 12, 0x2100);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.kept, [NormalizeKept::SectionAddresses]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn a_low_alignment_keeps_the_file_layout() {
    let raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .file_alignment(0x200)
        .section_alignment(0x200)
        .add_section(".text", vec![0xcc; 0x180], characteristics::READ)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.kept, [NormalizeKept::LowAlignment]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn an_invalid_section_alignment_becomes_a_page() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&raw);
    put32(&mut raw, optional + 32, 0);
    let original = PeImage::parse(&raw).unwrap();
    assert!(has_issue(
        &original,
        ValidationCode::InvalidSectionAlignment
    ));

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(
        result.changes,
        [NormalizeChange::SectionAlignment {
            old: 0,
            new: 0x1000
        }]
    );
    assert_eq!(result.kept, []);
    let normalized = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert!(!has_issue(
        &normalized,
        ValidationCode::InvalidSectionAlignment
    ));
    assert_eq!(section_rvas(&normalized), section_rvas(&original));
}

#[test]
fn reserved_directories_and_a_large_directory_count_become_valid() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&raw);
    put32(&mut raw, optional + 108, 0x20);
    let architecture = optional + 112 + DataDirectoryType::Architecture.as_index() * 8;
    put32(&mut raw, architecture, 0x1234);
    put32(&mut raw, architecture + 4, 8);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(
        result.changes,
        [
            NormalizeChange::NumberOfRvaAndSizes { old: 0x20, new: 16 },
            NormalizeChange::DataDirectory(DataDirectoryType::Architecture),
        ]
    );
    assert_eq!(result.kept, []);
    let normalized = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert!(!has_issue(
        &normalized,
        ValidationCode::ReservedDataDirectory
    ));
}

#[test]
fn a_wrong_checksum_is_corrected_and_a_zero_checksum_stays() {
    let mut raw = test_image().try_build().unwrap();
    let field = optional_offset(&raw) + 64;
    put32(&mut raw, field, 1);

    let mut file = PeFile::parse(&raw).unwrap();
    file.normalize().unwrap();
    let normalized = file.try_build().unwrap();
    let stored = u32::from_le_bytes(normalized[field..field + 4].try_into().unwrap());
    assert_eq!(Some(stored), compute_pe_checksum(&normalized));

    put32(&mut raw, field, 0);
    let mut file = PeFile::parse(&raw).unwrap();
    file.normalize().unwrap();
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn the_overlay_and_the_certificate_table_survive_a_new_layout() {
    let mut file = PeFile::parse(&test_image().try_build().unwrap()).unwrap();
    file.set_overlay(b"OVERLAY".to_vec());
    let security = SecurityDirectory {
        certificates: vec![Certificate {
            length: 8,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: Vec::new(),
        }],
    };
    file.set_security(&security).unwrap();
    let mut raw = file.try_build().unwrap();
    move_nt_headers_into_the_dos_header(&mut raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    // The move writes 0x10 into `BaseOfCode`, so the code and data fields change too.
    assert_eq!(
        result.changes,
        [
            NormalizeChange::NtHeadersOffset {
                old: 0x10,
                new: 0x40
            },
            NormalizeChange::CodeAndDataFields,
        ]
    );
    assert_eq!(result.kept, []);
    let normalized = PeFile::parse(&file.try_build().unwrap()).unwrap();
    assert!(normalized.overlay().starts_with(b"OVERLAY"));
    assert_eq!(normalized.security().unwrap(), Some(security));
}

#[test]
fn a_checksum_fix_covers_the_overlay_and_the_certificate() {
    let mut file = PeFile::parse(&test_image().try_build().unwrap()).unwrap();
    file.set_overlay(b"OVERLAY".to_vec());
    let security = SecurityDirectory {
        certificates: vec![Certificate {
            length: 8,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: Vec::new(),
        }],
    };
    file.set_security(&security).unwrap();
    let mut raw = file.try_build().unwrap();
    let field = optional_offset(&raw) + 64;
    put32(&mut raw, field, 1);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    let output = file.try_build().unwrap();
    let stored = u32::from_le_bytes(output[field..field + 4].try_into().unwrap());
    assert_eq!(Some(stored), compute_pe_checksum(&output));
    assert_eq!(
        result.changes,
        [NormalizeChange::Checksum {
            old: 1,
            new: stored
        }]
    );
    assert_eq!(result.kept, []);
    let normalized = PeFile::parse(&output).unwrap();
    assert!(normalized.overlay().starts_with(b"OVERLAY"));
    assert_eq!(normalized.security().unwrap(), Some(security));
}
