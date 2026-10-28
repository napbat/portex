//! Regression tests for malformed image shapes that portex reads, and builds back.
//!
//! Each test builds its image with `PeBuilder` or explicit bytes, and then changes the bytes.

use portex::directories::{Certificate, CertificateRevision, CertificateType, SecurityDirectory};
use portex::headers::{CoffHeader, DataDirectoryType, MachineType, OptionalHeader, SectionHeader};
use portex::image::{PeBuilder, PeFile, PeHeaders, PeImage};
use portex::section::characteristics;
use portex::{Subsystem, ValidationCode};

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

/// Build a raw file with `count` sections of 0x200 bytes each.
fn many_sections(count: usize) -> Vec<u8> {
    let mut builder = PeBuilder::new().machine(MachineType::Amd64);
    for index in 0..count {
        builder = builder.add_section(
            &format!(".s{index}"),
            vec![u8::try_from(index % 256).unwrap(); 0x200],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        );
    }
    builder.try_build().unwrap().try_build().unwrap()
}

fn pe_offset(headers: &PeHeaders) -> usize {
    usize::try_from(headers.pe_offset).unwrap()
}

fn optional_offset(headers: &PeHeaders) -> usize {
    pe_offset(headers) + 4 + CoffHeader::SIZE
}

fn section_header_offset(headers: &PeHeaders, index: usize) -> usize {
    optional_offset(headers)
        + usize::from(headers.coff_header.size_of_optional_header)
        + index * SectionHeader::SIZE
}

fn put16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Move the NT headers to 0x10, inside the DOS header.
///
/// Then the `e_lfanew` field at 0x3C is the `BaseOfCode` field of the PE32+ optional header.
fn nt_headers_in_the_dos_header() -> Vec<u8> {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let old = pe_offset(&headers);
    let length = section_header_offset(&headers, headers.section_headers.len()) - old;
    let mut nt_headers = raw[old..old + length].to_vec();
    put32(&mut nt_headers, 4 + CoffHeader::SIZE + 20, 0x10);
    raw[old..old + length].fill(0);
    raw[0x10..0x10 + length].copy_from_slice(&nt_headers);
    raw
}

fn set_base_of_code(image: &mut PeImage, value: u32) {
    match &mut image.optional_header {
        OptionalHeader::Pe32(header) => header.base_of_code = value,
        OptionalHeader::Pe32Plus(header) => header.base_of_code = value,
    }
}

#[test]
fn nt_headers_inside_the_dos_header_parse_and_round_trip() {
    let original = test_image();
    let raw = nt_headers_in_the_dos_header();

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.dos_header.e_lfanew, 0x10);
    assert_eq!(image.dos_stub, []);
    assert_eq!(
        image.sections[1].data[..0x180],
        original.sections[1].data[..]
    );
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    // The mapped image keeps the headers as they are in the file.
    let mapped = PeImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
    assert_eq!(mapped.dos_header.e_lfanew, 0x10);

    // The build calculates BaseOfCode again, which would change `e_lfanew`. Thus the NT headers
    // move after the DOS header.
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.dos_header.e_lfanew, 0x40);
    assert_eq!(
        rebuilt.sections[1].data[..0x180],
        original.sections[1].data[..]
    );
}

#[test]
fn an_edit_that_changes_e_lfanew_moves_the_nt_headers() {
    let mut file = PeFile::parse(&nt_headers_in_the_dos_header()).unwrap();
    set_base_of_code(&mut file, 0x1000);

    let rebuilt = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.dos_header.e_lfanew, 0x40);
    assert_eq!(rebuilt.sections[0].data[..0x180], [0xcc; 0x180]);
}

#[test]
fn a_large_number_of_rva_and_sizes_reads_16_entries() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    put32(&mut raw, optional_offset(&headers) + 108, u32::MAX);

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.optional_header.data_directories().len(), 16);
    let OptionalHeader::Pe32Plus(optional) = &image.optional_header else {
        panic!("the test image is PE32+");
    };
    assert_eq!(optional.number_of_rva_and_sizes, u32::MAX);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

/// Put the section table over the data directories of the optional header.
///
/// `NumberOfRvaAndSizes` is 2 and `SizeOfOptionalHeader` is the size of the fixed part. Thus the
/// two data directories are the first 16 bytes of the `.text` section header.
fn section_table_over_the_optional_header() -> Vec<u8> {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let optional = optional_offset(&headers);
    let old_table = section_header_offset(&headers, 0);
    let table_length = headers.section_headers.len() * SectionHeader::SIZE;
    let table = raw[old_table..old_table + table_length].to_vec();
    raw[old_table..old_table + table_length].fill(0);
    put32(&mut raw, optional + 108, 2);
    put16(&mut raw, pe_offset(&headers) + 4 + 16, 112);
    raw[optional + 112..optional + 112 + table_length].copy_from_slice(&table);
    raw
}

#[test]
fn a_section_table_that_overlaps_the_optional_header() {
    let raw = section_table_over_the_optional_header();

    let image = PeImage::parse(&raw).unwrap();
    let directories = image.optional_header.data_directories();
    assert_eq!(directories.len(), 2);
    assert_eq!(directories[0].virtual_address, u32::from_le_bytes(*b".tex"));
    assert_eq!(image.sections[0].name(), ".text");
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    // The build puts the section table after the optional header.
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.coff_header.size_of_optional_header, 128);
    assert_eq!(rebuilt.sections[0].name(), ".text");

    // The section name is also a data directory. A change makes a new layout.
    let mut file = PeFile::parse(&raw).unwrap();
    file.sections[0].header.set_name(".code");
    let edited = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(edited.coff_header.size_of_optional_header, 128);
    assert_eq!(edited.sections[0].name(), ".code");
}

#[test]
fn more_than_96_sections_parse_and_round_trip() {
    let raw = many_sections(100);

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.sections.len(), 100);
    assert_eq!(image.sections[99].data, [99; 0x200]);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

/// Point the raw data of each section at the raw data of the first section.
///
/// The shared raw data has `size` bytes. If `size` is `None`, it goes to the end of the file.
fn share_the_first_raw_range(raw: &mut [u8], size: Option<u32>) {
    let headers = PeHeaders::from_slice(raw).unwrap();
    let start = headers.section_headers[0].pointer_to_raw_data;
    let size = size.unwrap_or(u32::try_from(raw.len()).unwrap() - start);
    for index in 0..headers.section_headers.len() {
        let header = section_header_offset(&headers, index);
        put32(raw, header + 16, size);
        put32(raw, header + 20, start);
    }
}

#[test]
fn validation_reports_each_overlapping_section_once() {
    let mut raw = many_sections(1000);
    share_the_first_raw_range(&mut raw, Some(0x200));

    let image = PeImage::parse(&raw).unwrap();
    let overlaps = image
        .validate()
        .issues
        .iter()
        .filter(|issue| issue.code == ValidationCode::OverlappingSections)
        .count();
    assert_eq!(overlaps, 999);
}

#[test]
fn section_data_is_limited_to_96_times_the_source() {
    // Each section reads the complete source, so 96 sections are the limit.
    let mut raw = many_sections(96);
    share_the_first_raw_range(&mut raw, None);
    assert!(PeImage::parse(&raw).is_ok());

    let mut raw = many_sections(200);
    share_the_first_raw_range(&mut raw, None);
    assert!(PeImage::parse(&raw).is_err());
}

#[test]
fn raw_data_past_the_end_of_the_file_reads_as_zero() {
    let raw = test_image().try_build().unwrap();
    // The file ends 0x100 bytes into the raw data of `.rdata`.
    let truncated = &raw[..raw.len() - 0x100];

    let image = PeImage::parse(truncated).unwrap();
    assert_eq!(image.sections[1].data, [0x5a; 0x100]);
    // The loader maps zeros for the bytes after the end of the file.
    let rva = image.sections[1].header.virtual_address + 0xf0;
    let expected = [[0x5a; 0x10], [0; 0x10]].concat();
    assert_eq!(image.read_rva(rva, 0x20), Some(expected.clone()));
    assert_eq!(
        PeFile::parse(truncated).unwrap().try_build().unwrap(),
        truncated
    );

    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.read_rva(rva, 0x20), Some(expected));
}

#[test]
fn a_huge_size_of_raw_data_reads_up_to_the_end_of_the_file() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    put32(
        &mut raw,
        section_header_offset(&headers, 1) + 16,
        0xffff_0200,
    );

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.sections[1].data.len(), 0x200);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn size_of_headers_past_the_end_of_the_file_keeps_the_file() {
    let mut raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    put32(&mut raw, optional_offset(&headers) + 60, 0x1000_0000);

    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn an_unaligned_pointer_to_raw_data_reads_where_the_loader_reads() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let rdata = &headers.section_headers[1];
    put32(
        &mut raw,
        section_header_offset(&headers, 1) + 20,
        rdata.pointer_to_raw_data + 5,
    );

    // The loader rounds PointerToRawData down to a multiple of 0x200.
    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.sections[1].data[..0x180], [0x5a; 0x180]);
    assert_eq!(
        image.rva_to_offset(rdata.virtual_address),
        Some(rdata.pointer_to_raw_data)
    );

    // The build writes the section data at the rounded offset, so the file stays the same.
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn a_malformed_debug_directory_does_not_stop_the_build() {
    let mut image = test_image();
    let rdata = image.sections[1].header.virtual_address;
    // A debug directory size that is not a multiple of 28.
    image.set_data_directory(DataDirectoryType::Debug, rdata, 29);

    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.sections[1].data[..0x180], [0x5a; 0x180]);
}

#[test]
fn a_file_that_ends_inside_its_headers_reads_them_as_zeros() {
    // A data-file DLL: the PE signature follows "MZ", and the file ends inside the optional
    // header. The `e_lfanew` field at 0x3C is also a field of the optional header.
    let mut raw = vec![0; 0x40];
    raw[..2].copy_from_slice(b"MZ");
    raw[2..6].copy_from_slice(b"PE\0\0");
    put32(&mut raw, 0x3c, 2);

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.dos_header.e_lfanew, 2);
    // The machine type and the magic are 0. The parser uses the PE32 layout and keeps the magic.
    let OptionalHeader::Pe32(optional) = &image.optional_header else {
        panic!("an unknown magic uses the PE32 layout");
    };
    assert_eq!(optional.magic, 0);
    assert!(
        image
            .validate()
            .issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidOptionalMagic)
    );
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn a_section_with_raw_size_and_no_file_offset_reads_as_zeros() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let rva = headers.section_headers[1].virtual_address;
    let header = section_header_offset(&headers, 1);
    // A VirtualSize of 0 makes SizeOfRawData the extent of the section.
    put32(&mut raw, header + 8, 0);
    put32(&mut raw, header + 16, 0x1000);
    put32(&mut raw, header + 20, 0);

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.sections[1].data, []);
    // The read adds more zero bytes than the image holds. That is allowed up to 1 MiB.
    assert_eq!(image.read_rva(rva, 0x1000), Some(vec![0; 0x1000]));
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn section_data_in_the_optional_header_padding_round_trips() {
    // Move the section table to the end of the file. Then `SizeOfOptionalHeader` covers the
    // raw data of the sections.
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let old_table = section_header_offset(&headers, 0);
    let length = headers.section_headers.len() * SectionHeader::SIZE;
    let table = raw[old_table..old_table + length].to_vec();
    raw[old_table..old_table + length].fill(0);
    let new_table = raw.len();
    raw.extend_from_slice(&table);
    let size_of_optional_header = u16::try_from(new_table - optional_offset(&headers)).unwrap();
    put16(
        &mut raw,
        pe_offset(&headers) + 4 + 16,
        size_of_optional_header,
    );

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.sections[1].data[..0x180], [0x5a; 0x180]);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn an_invalid_section_alignment_keeps_the_current_layout() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    put32(&mut raw, optional_offset(&headers) + 32, 0);

    let image = PeImage::parse(&raw).unwrap();
    // No new layout can use a SectionAlignment of 0, so the build keeps the current layout.
    assert_eq!(image.try_build().unwrap(), raw);
    let mapped = PeImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
    assert_eq!(mapped.sections[1].data[..0x180], [0x5a; 0x180]);
}

fn base_of_code(header: &OptionalHeader) -> u32 {
    match header {
        OptionalHeader::Pe32(header) => header.base_of_code,
        OptionalHeader::Pe32Plus(header) => header.base_of_code,
    }
}

fn number_of_rva_and_sizes(header: &OptionalHeader) -> u32 {
    match header {
        OptionalHeader::Pe32(header) => header.number_of_rva_and_sizes,
        OptionalHeader::Pe32Plus(header) => header.number_of_rva_and_sizes,
    }
}

#[test]
fn an_unknown_magic_with_an_overlapping_section_table_builds() {
    let mut raw = section_table_over_the_optional_header();
    let optional = optional_offset(&PeHeaders::from_slice(&raw).unwrap());
    put16(&mut raw, optional, 0x107);

    let image = PeImage::parse(&raw).unwrap();
    assert!(image.contains_rva_range(0, 0x40));
    assert_eq!(image.read_rva(0, 0x40).as_deref(), Some(&raw[..0x40]));
    assert_eq!(image.to_mapped_image().unwrap()[..0x200], raw[..0x200]);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn a_signed_file_keeps_a_large_number_of_rva_and_sizes() {
    let mut file = PeFile::parse(&test_image().try_build().unwrap()).unwrap();
    file.set_security(&SecurityDirectory {
        certificates: vec![Certificate {
            length: 8,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: Vec::new(),
        }],
    })
    .unwrap();
    let mut signed = file.try_build().unwrap();
    let optional = optional_offset(&PeHeaders::from_slice(&signed).unwrap());
    put32(&mut signed, optional + 108, 0x20);

    let rebuilt = PeFile::parse(&signed).unwrap().try_build().unwrap();
    let headers = PeHeaders::from_slice(&rebuilt).unwrap();
    assert_eq!(number_of_rva_and_sizes(&headers.optional_header), 0x20);
    assert_eq!(rebuilt, signed);
}

#[test]
fn a_read_across_overlapping_sections_uses_the_first_section_in_the_table() {
    let mut builder = PeBuilder::new().machine(MachineType::Amd64);
    for (name, byte) in [(".a", 0xaa), (".b", 0xbb), (".c", 0xcc)] {
        builder = builder.add_section(name, vec![byte; 0x200], characteristics::READ);
    }
    let mut raw = builder.try_build().unwrap().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    // `.a` covers 0x1000..0x2000. `.c` covers 0x1800..0x2800, so it overlaps `.b` at 0x2000.
    put32(&mut raw, section_header_offset(&headers, 0) + 8, 0x1000);
    put32(&mut raw, section_header_offset(&headers, 2) + 8, 0x1000);
    put32(&mut raw, section_header_offset(&headers, 2) + 12, 0x1800);

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.section_by_rva(0x2000).unwrap().name(), ".b");
    let short = image.read_rva(0x2000, 0x100).unwrap();
    assert_eq!(short, [0xbb; 0x100]);
    assert_eq!(image.read_rva(0x1000, 0x1100).unwrap()[0x1000..], short);
}

#[test]
fn an_overlay_after_a_truncated_source_follows_the_section_data() {
    let raw = test_image().try_build().unwrap();
    let rdata =
        PeHeaders::from_slice(&raw).unwrap().section_headers[1].pointer_to_raw_data as usize;
    // The file ends 0x100 bytes into the raw data of `.rdata`.
    let truncated = &raw[..raw.len() - 0x100];
    let mut file = PeFile::parse(truncated).unwrap();
    file.set_overlay(b"OVERLAYDATA".to_vec());

    let rebuilt = PeFile::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.overlay(), b"OVERLAYDATA");
    assert_eq!(rebuilt.sections[1].data[..0x100], raw[rdata..rdata + 0x100]);
}

#[test]
fn a_certificate_after_a_truncated_source_stays_a_certificate() {
    let raw = test_image().try_build().unwrap();
    let mut file = PeFile::parse(&raw[..raw.len() - 0x100]).unwrap();
    let security = SecurityDirectory {
        certificates: vec![Certificate {
            length: 8,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: Vec::new(),
        }],
    };
    file.set_security(&security).unwrap();

    let rebuilt = PeFile::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.security().unwrap(), Some(security));
}

#[test]
fn a_mapped_image_of_edited_overlapping_headers_has_the_edits() {
    let mut image = PeImage::parse(&section_table_over_the_optional_header()).unwrap();
    image.sections[0].header.set_name(".code");
    let mapped = PeImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
    assert_eq!(mapped.sections[0].name(), ".code");

    let mut image = PeImage::parse(&nt_headers_in_the_dos_header()).unwrap();
    set_base_of_code(&mut image, 0x1000);
    let mapped = PeImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
    assert_eq!(base_of_code(&mapped.optional_header), 0x1000);
}

#[test]
fn a_mapped_image_after_a_data_edit_has_the_new_layout() {
    let mut image = test_image();
    image.sections[1].data = vec![0x77; 0x3000];

    let mapped = image.to_mapped_image().unwrap();
    let parsed = PeImage::parse_mapped(&mapped).unwrap();
    assert_eq!(
        parsed.optional_header.size_of_image() as usize,
        mapped.len()
    );
    assert_eq!(parsed.sections[1].header.size_of_raw_data, 0x3000);
    assert!(
        parsed
            .validate()
            .issues
            .iter()
            .all(|issue| issue.code != ValidationCode::InconsistentImageSize)
    );
}

#[test]
fn a_huge_size_of_image_does_not_size_the_mapped_image() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&PeHeaders::from_slice(&raw).unwrap());
    put32(&mut raw, optional + 56, 0x8000_0000);

    let mapped = PeImage::parse(&raw).unwrap().to_mapped_image().unwrap();
    assert_eq!(mapped.len(), 0x3000);
}

#[test]
fn a_new_data_directory_in_a_short_directory_array_survives_the_build() {
    let mut raw = test_image().try_build().unwrap();
    let optional = optional_offset(&PeHeaders::from_slice(&raw).unwrap());
    put32(&mut raw, optional + 108, 2);

    let mut file = PeFile::parse(&raw).unwrap();
    file.set_data_directory(DataDirectoryType::Iat, 0x2000, 0x10);
    let rebuilt = PeImage::parse(&file.try_build().unwrap()).unwrap();
    let iat = rebuilt.data_directory(DataDirectoryType::Iat).unwrap();
    assert_eq!((iat.virtual_address, iat.size), (0x2000, 0x10));
}

#[test]
fn validation_compares_raw_ranges_where_the_loader_reads_them() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let text = headers.section_headers[0].pointer_to_raw_data;
    // `.text` covers 0x300 bytes. The loader reads `.rdata` from 0x200 bytes after the start of
    // `.text`, not from 0x3FF bytes after it.
    put32(&mut raw, section_header_offset(&headers, 0) + 16, 0x300);
    put32(
        &mut raw,
        section_header_offset(&headers, 1) + 20,
        text + 0x3ff,
    );

    let result = PeImage::parse(&raw).unwrap().validate();
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ValidationCode::OverlappingSections)
    );
}

#[test]
fn a_directory_that_crosses_two_sections_parses() {
    // The first 16 bytes of a debug directory entry are at the end of `.a`, and the other 12
    // bytes are at the start of `.b`.
    let mut entry = [0u8; 28];
    entry[4..8].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    entry[12..16].copy_from_slice(&2u32.to_le_bytes());
    entry[24..28].copy_from_slice(&0x5566u32.to_le_bytes());
    let mut a = vec![0; 0x1000];
    a[0xff0..].copy_from_slice(&entry[..16]);
    let mut b = vec![0; 0x200];
    b[..12].copy_from_slice(&entry[16..]);
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(".a", a, characteristics::READ)
        .add_section(".b", b, characteristics::READ)
        .try_build()
        .unwrap();
    assert_eq!(image.sections[1].header.virtual_address, 0x2000);
    image.set_data_directory(DataDirectoryType::Debug, 0x1ff0, 28);

    let info = image.debug_info().unwrap().unwrap();
    assert_eq!(info.directories.len(), 1);
    let directory = &info.directories[0];
    assert_eq!(directory.time_date_stamp, 0x1122_3344);
    assert_eq!(directory.debug_type, 2);
    assert_eq!(directory.pointer_to_raw_data, 0x5566);
}

/// Build a file with data directory `index` of `size` bytes at the start of `.rdata`.
///
/// The `.rdata` section has 0x200 bytes of raw data, a `VirtualSize` of 0xFFFF0000, and a
/// `SizeOfImage` that covers it. Thus the loader fills almost 4 GiB of the section with zeros.
fn zero_filled_directory(machine: MachineType, index: usize, size: u32) -> Vec<u8> {
    let mut raw = PeBuilder::new()
        .machine(machine)
        .add_section(".text", vec![0xcc; 0x180], characteristics::READ)
        .add_section(".rdata", vec![0; 0x180], characteristics::READ)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let optional = optional_offset(&headers);
    let rdata = headers.section_headers[1].virtual_address;
    put32(&mut raw, optional + 32, 0xffff_0000);
    put32(&mut raw, optional + 56, 0xffff_f000);
    put32(
        &mut raw,
        section_header_offset(&headers, 1) + 8,
        0xffff_0000,
    );
    // The PE32+ data directories start at offset 112.
    put32(&mut raw, optional + 112 + index * 8, rdata);
    put32(&mut raw, optional + 112 + index * 8 + 4, size);
    raw
}

#[test]
fn a_huge_zero_filled_exception_table_is_one_bounded_read() {
    // Before the fix, the parse read each 12-byte or 8-byte record separately. It made
    // hundreds of millions of reads for this size.
    let exception = DataDirectoryType::Exception as usize;
    let size = 0xffff_0000 / 24 * 24;
    for machine in [MachineType::Amd64, MachineType::Arm64] {
        let image = PeImage::parse(&zero_filled_directory(machine, exception, size)).unwrap();
        let error = image.exception_table().unwrap_err();
        assert!(
            matches!(error.kind, portex::ErrorKind::InvalidDataDirectory(_)),
            "{machine:?}: {error}"
        );

        // A small table in the zero bytes after the raw data has only null records.
        let image = PeImage::parse(&zero_filled_directory(machine, exception, 0x1_0008)).unwrap();
        assert!(image.exception_table().unwrap().unwrap().is_empty());
    }
}

#[test]
fn a_huge_zero_filled_debug_directory_is_one_bounded_read() {
    // Before the fix, the parse read each 28-byte entry separately, and kept each zero entry.
    // It made about 153 million reads and entries for this size.
    let debug = DataDirectoryType::Debug as usize;
    let size = 0xffff_0000 / 28 * 28;
    let image = PeImage::parse(&zero_filled_directory(MachineType::Amd64, debug, size)).unwrap();
    let error = image.debug_info().unwrap_err();
    assert!(
        matches!(error.kind, portex::ErrorKind::InvalidDataDirectory(_)),
        "{error}"
    );

    // A small directory in the zero bytes after the raw data has only zero entries.
    let image = PeImage::parse(&zero_filled_directory(
        MachineType::Amd64,
        debug,
        28 * 0x100,
    ))
    .unwrap();
    assert_eq!(
        image.debug_info().unwrap().unwrap().directories.len(),
        0x100
    );
}

#[test]
fn a_huge_zero_filled_relocation_table_is_an_invalid_data_directory() {
    // The RVA is valid, but the table is larger than the data that the image holds.
    let reloc = DataDirectoryType::BaseReloc as usize;
    let image = PeImage::parse(&zero_filled_directory(
        MachineType::Amd64,
        reloc,
        0xffff_0000,
    ))
    .unwrap();
    let error = image.relocations().unwrap_err();
    assert!(
        matches!(error.kind, portex::ErrorKind::InvalidDataDirectory(_)),
        "{error}"
    );

    // A small table in the zero bytes after the raw data ends at the first null block.
    let image =
        PeImage::parse(&zero_filled_directory(MachineType::Amd64, reloc, 0x1_0000)).unwrap();
    assert!(image.relocations().is_ok());
}
