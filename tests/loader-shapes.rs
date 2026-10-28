//! Regression tests for malformed image shapes that portex reads, and builds back.
//!
//! Each test builds its image with `PeBuilder` or explicit bytes, and then changes the bytes.

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
