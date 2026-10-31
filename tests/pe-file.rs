//! Regression tests for the raw-file state of `PeFile`: the certificate table, the Security
//! directory entry, and the checksum and validation of the complete file.

use portex::directories::{Certificate, CertificateRevision, CertificateType, SecurityDirectory};
use portex::headers::{CoffHeader, DataDirectoryType, MachineType, SectionHeader};
use portex::image::{PeBuilder, PeFile, PeHeaders, PeImage};
use portex::section::characteristics;
use portex::{OptionalHeader64, Subsystem, ValidationCode, compute_pe_checksum};

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

fn certificate() -> SecurityDirectory {
    SecurityDirectory {
        certificates: vec![Certificate {
            length: 8,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: Vec::new(),
        }],
    }
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

fn security_entry_offset(raw: &[u8]) -> usize {
    optional_offset(raw) + OptionalHeader64::BASE_SIZE + DataDirectoryType::Security.as_index() * 8
}

fn get32(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap())
}

fn put32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn stored_checksum(raw: &[u8]) -> u32 {
    get32(raw, optional_offset(raw) + 64)
}

/// Return a signed file with an overlay and a correct checksum.
fn signed_file_with_overlay() -> Vec<u8> {
    let mut file = PeFile::new(test_image()).unwrap();
    file.set_overlay(vec![0x5a; 0x300]);
    file.set_security(&certificate()).unwrap();
    let mut raw = file.try_build().unwrap();
    let checksum = compute_pe_checksum(&raw).unwrap();
    let field = optional_offset(&raw) + 64;
    put32(&mut raw, field, checksum);
    raw
}

/// Return a file with an overlay of 0x40 bytes and an unaligned Security entry in it. The loader
/// ignores such an entry. Also return the file offset of the overlay.
fn invalid_security_entry_in_the_overlay() -> (Vec<u8>, usize) {
    let mut raw = test_image().try_build().unwrap();
    let overlay_start = raw.len();
    raw.extend_from_slice(&[0x7e; 0x40]);
    let entry = security_entry_offset(&raw);
    put32(&mut raw, entry, u32::try_from(overlay_start + 4).unwrap());
    put32(&mut raw, entry + 4, 0x10);
    (raw, overlay_start)
}

#[test]
fn a_certificate_table_keeps_the_round_trip_when_a_section_covers_the_headers() {
    let mut file = PeFile::new(test_image()).unwrap();
    file.set_security(&certificate()).unwrap();
    let mut raw = file.try_build().unwrap();
    // The loader rounds 0x40 down to 0, so the raw data of `.text` covers the headers.
    let text = section_header_offset(&raw, 0);
    put32(&mut raw, text + 20, 0x40);

    let parsed = PeFile::parse(&raw).unwrap();
    assert_eq!(parsed.security().unwrap(), Some(certificate()));
    assert!(parsed.preserves_source_gaps());
    let rebuilt = parsed.try_build().unwrap();
    assert_eq!(get32(&rebuilt, text + 20), 0x40);
    assert_eq!(rebuilt, raw);
}

#[test]
fn an_unedited_signed_file_keeps_its_bytes() {
    let raw = signed_file_with_overlay();
    let file = PeFile::parse(&raw).unwrap();
    assert!(file.preserves_source_gaps());
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn an_invalid_security_entry_moves_with_the_overlay() {
    let (raw, overlay_start) = invalid_security_entry_in_the_overlay();
    let mut file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.security().unwrap(), None);
    assert_eq!(file.try_build().unwrap(), raw);

    // Grow `.rdata`, so that the overlay moves.
    let rdata = &mut file.sections[1];
    rdata.header.virtual_size = 0x800;
    rdata.data.resize(0x800, 0x11);
    let rebuilt = file.try_build().unwrap();
    let new_overlay_start = rebuilt.len() - 0x40;
    assert_ne!(new_overlay_start, overlay_start);
    assert_eq!(rebuilt[new_overlay_start..], raw[overlay_start..]);
    let entry = security_entry_offset(&rebuilt);
    assert_eq!(
        get32(&rebuilt, entry),
        u32::try_from(new_overlay_start + 4).unwrap()
    );
    assert_eq!(get32(&rebuilt, entry + 4), 0x10);
}

#[test]
fn an_invalid_security_entry_in_the_image_is_cleared_by_a_new_layout() {
    let mut raw = test_image().try_build().unwrap();
    let entry = security_entry_offset(&raw);
    put32(&mut raw, entry, 0x204);
    put32(&mut raw, entry + 4, 0x10);
    let mut file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.try_build().unwrap(), raw);

    let rdata = &mut file.sections[1];
    rdata.header.virtual_size = 0x800;
    rdata.data.resize(0x800, 0x11);
    let rebuilt = file.try_build().unwrap();
    let entry = security_entry_offset(&rebuilt);
    assert_eq!(get32(&rebuilt, entry), 0);
    assert_eq!(get32(&rebuilt, entry + 4), 0);
}

#[test]
fn the_checksum_of_a_file_covers_the_overlay_and_the_certificate_table() {
    let raw = signed_file_with_overlay();
    let stored = stored_checksum(&raw);
    let mut file = PeFile::parse(&raw).unwrap();

    assert_eq!(file.try_calculate_checksum().unwrap(), stored);
    assert_eq!(file.calculate_checksum(), stored);
    let issues = file.validate();
    assert!(
        !issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidChecksum),
        "{issues:?}"
    );

    file.try_update_checksum().unwrap();
    assert_eq!(file.try_build().unwrap(), raw);
    file.update_checksum();
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn validate_reports_a_wrong_checksum_of_the_complete_file() {
    let mut raw = signed_file_with_overlay();
    let field = optional_offset(&raw) + 64;
    let wrong = stored_checksum(&raw) ^ 1;
    put32(&mut raw, field, wrong);

    let file = PeFile::parse(&raw).unwrap();
    assert!(
        file.validate()
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidChecksum)
    );
}

#[test]
fn update_checksum_writes_the_checksum_of_the_complete_file() {
    let raw = signed_file_with_overlay();
    let mut file = PeFile::parse(&raw).unwrap();
    file.set_overlay(b"new overlay".to_vec());
    file.set_security(&certificate()).unwrap();

    file.try_update_checksum().unwrap();
    let output = file.try_build().unwrap();
    assert_eq!(Some(stored_checksum(&output)), compute_pe_checksum(&output));

    file.try_finalize().unwrap();
    let output = file.try_build().unwrap();
    assert_eq!(Some(stored_checksum(&output)), compute_pe_checksum(&output));
    file.finalize();
    assert_eq!(file.try_build().unwrap(), output);
}

#[test]
fn validate_reports_an_invalid_security_entry() {
    let (raw, _) = invalid_security_entry_in_the_overlay();
    let file = PeFile::parse(&raw).unwrap();
    assert!(file.validate().iter().any(|issue| {
        issue.code == ValidationCode::InvalidDataDirectoryRange
            && issue.context.as_deref() == Some(DataDirectoryType::Security.name())
    }));

    let file = PeFile::parse(&signed_file_with_overlay()).unwrap();
    assert!(
        !file
            .validate()
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidDataDirectoryRange)
    );
}
