//! Regression tests for unusual image layouts that the Windows loader accepts.

use portex::headers::{CoffHeader, DataDirectoryType, MachineType, OptionalHeader, SectionHeader};
use portex::image::{PeBuilder, PeFile, PeHeaders, PeImage};
use portex::section::characteristics;
use portex::{ParseOptions, Subsystem, ValidationCode};

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

fn optional_header_offset(headers: &PeHeaders) -> usize {
    usize::try_from(headers.pe_offset).expect("PE offset fits usize") + 4 + CoffHeader::SIZE
}

fn section_table_offset(headers: &PeHeaders) -> usize {
    optional_header_offset(headers) + headers.coff_header.size_of_optional_header as usize
}

/// Write a PE32+ data-directory entry in raw bytes.
fn put_directory(raw: &mut [u8], headers: &PeHeaders, index: usize, rva: u32, size: u32) {
    let entry = optional_header_offset(headers) + 112 + index * 8;
    raw[entry..entry + 4].copy_from_slice(&rva.to_le_bytes());
    raw[entry + 4..entry + 8].copy_from_slice(&size.to_le_bytes());
}

/// Write the `SizeOfHeaders` field of a PE32+ optional header in raw bytes.
fn put_size_of_headers(raw: &mut [u8], headers: &PeHeaders, size: u32) {
    let field = optional_header_offset(headers) + 60;
    raw[field..field + 4].copy_from_slice(&size.to_le_bytes());
}

/// Write the `SizeOfImage` field of a PE32+ optional header in raw bytes.
fn put_size_of_image(raw: &mut [u8], headers: &PeHeaders, size: u32) {
    let field = optional_header_offset(headers) + 56;
    raw[field..field + 4].copy_from_slice(&size.to_le_bytes());
}

/// Build a file with a bound import table directly after the section table, as linkers do.
fn bound_import_file() -> Vec<u8> {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let table_offset =
        section_table_offset(&headers) + headers.section_headers.len() * SectionHeader::SIZE;
    let mut table = Vec::new();
    table.extend_from_slice(&0x4243_7794u32.to_le_bytes());
    table.extend_from_slice(&16u16.to_le_bytes());
    table.extend_from_slice(&0u16.to_le_bytes());
    table.extend_from_slice(&[0; 8]);
    table.extend_from_slice(b"KERNEL32.DLL\0");
    assert!(table_offset + table.len() <= headers.optional_header.size_of_headers() as usize);
    raw[table_offset..table_offset + table.len()].copy_from_slice(&table);
    put_directory(
        &mut raw,
        &headers,
        DataDirectoryType::BoundImport.as_index(),
        u32::try_from(table_offset).unwrap(),
        u32::try_from(table.len()).unwrap(),
    );
    raw
}

fn bound_import_names(image: &PeImage) -> Vec<String> {
    image
        .bound_imports()
        .unwrap()
        .unwrap()
        .descriptors
        .into_iter()
        .map(|descriptor| descriptor.module_name)
        .collect()
}

fn count_module_names(bytes: &[u8]) -> usize {
    bytes
        .windows(12)
        .filter(|window| *window == b"KERNEL32.DLL")
        .count()
}

#[test]
fn validation_reports_an_unverifiable_checksum_without_a_panic() {
    let mut image = test_image();
    // An `e_lfanew` of 1 puts the PE signature over `e_magic`, so no build can succeed.
    image.dos_header.e_lfanew = 1;
    match &mut image.optional_header {
        OptionalHeader::Pe32(header) => header.check_sum = 1,
        OptionalHeader::Pe32Plus(header) => header.check_sum = 1,
    }
    assert!(image.try_build().is_err());

    let result = image.validate();
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidChecksum)
    );
}

#[test]
fn pe_file_keeps_a_short_data_directory_array() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let count = optional_header_offset(&headers) + 108;
    raw[count..count + 4].copy_from_slice(&2u32.to_le_bytes());

    let file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.optional_header.data_directories().len(), 2);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn bound_imports_in_the_header_slack_survive_parse_and_build() {
    let raw = bound_import_file();
    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(bound_import_names(&image), ["KERNEL32.DLL"]);
    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(bound_import_names(&rebuilt), ["KERNEL32.DLL"]);
    let mapped = PeImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
    assert_eq!(bound_import_names(&mapped), ["KERNEL32.DLL"]);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);
}

#[test]
fn clearing_bound_imports_removes_the_table_from_the_headers() {
    let mut image = PeImage::parse(&bound_import_file()).unwrap();
    image.clear_data_directory(DataDirectoryType::BoundImport);

    let output = image.try_build().unwrap();
    assert_eq!(count_module_names(&output), 0);
    assert!(
        PeImage::parse(&output)
            .unwrap()
            .bound_imports()
            .unwrap()
            .is_none()
    );
}

#[test]
fn moving_bound_imports_removes_the_old_table_from_the_headers() {
    let mut image = PeImage::parse(&bound_import_file()).unwrap();
    let directory = image.bound_imports().unwrap().unwrap();
    // The table cannot be written in place in the headers, so it moves to `.rdata`.
    image
        .update_bound_imports(&directory, Some(".rdata"))
        .unwrap();

    let output = image.try_build().unwrap();
    assert_eq!(count_module_names(&output), 1);
    assert_eq!(
        bound_import_names(&PeImage::parse(&output).unwrap()),
        ["KERNEL32.DLL"]
    );
}

#[test]
fn a_section_table_that_replaces_bound_imports_clears_the_directory() {
    let mut image = PeImage::parse(&bound_import_file()).unwrap();
    // The new section header needs the bytes of the bound import table.
    image
        .try_add_section_with_data(
            ".new",
            vec![1; 0x10],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .unwrap();

    let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert!(rebuilt.bound_imports().unwrap().is_none());
}

#[test]
fn rva_reads_do_not_zero_fill_section_bytes_that_the_parser_could_not_read() {
    let image = test_image();
    let rdata = image.sections[1].header.virtual_address;
    // A remote reader cannot read the pages of `.rdata`.
    let mapped = image.to_mapped_image().unwrap();
    let parsed = PeImage::parse_with_options(
        &mapped[..rdata as usize],
        ParseOptions::mapped().allow_missing_section_data(),
    )
    .unwrap();

    assert_eq!(parsed.sections[1].data, []);
    assert!(!parsed.contains_rva_range(rdata, 16));
    assert_eq!(parsed.read_rva(rdata, 16), None);
}

#[test]
fn rva_reads_limit_the_zero_fill_of_a_large_section() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let rdata = &headers.section_headers[1];
    // A small file declares 16 MiB of zero-filled virtual space.
    let virtual_size = 0x0100_0000u32;
    let rdata_header = section_table_offset(&headers) + SectionHeader::SIZE;
    raw[rdata_header + 8..rdata_header + 12].copy_from_slice(&virtual_size.to_le_bytes());
    put_size_of_image(&mut raw, &headers, rdata.virtual_address + virtual_size);
    let tail = rdata.virtual_address + 0x1000;
    let size = virtual_size - 0x2000;
    put_directory(
        &mut raw,
        &headers,
        DataDirectoryType::BaseReloc.as_index(),
        tail,
        size,
    );

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.read_rva(tail, 0x100), Some(vec![0; 0x100]));
    assert_eq!(image.read_rva(tail, size as usize), None);
    assert!(image.relocations().is_err());
}

#[test]
fn rva_reads_limit_the_zero_fill_of_large_headers() {
    let mut raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    // A small file declares 16 MiB of headers.
    let size = 0x0100_0000u32;
    put_size_of_headers(&mut raw, &headers, size);
    put_size_of_image(&mut raw, &headers, size);

    let image = PeImage::parse(&raw).unwrap();
    assert_eq!(image.read_rva(0x300, 0x40), Some(vec![0; 0x40]));
    assert_eq!(image.read_rva(0x1000, size as usize - 0x1000), None);
}

#[test]
fn raw_and_mapped_views_read_the_zero_filled_section_tail() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let rdata = &headers.section_headers[1];
    let raw_size = rdata.size_of_raw_data;
    // The loader maps zeros after the raw bytes, up to the virtual size.
    let rdata_header = section_table_offset(&headers) + SectionHeader::SIZE;
    raw[rdata_header + 8..rdata_header + 12].copy_from_slice(&(raw_size + 0x100).to_le_bytes());

    // The relocation block starts in the raw bytes and ends in the zero-filled tail.
    let block_offset = (rdata.pointer_to_raw_data + raw_size - 12) as usize;
    raw[block_offset..block_offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    raw[block_offset + 4..block_offset + 8].copy_from_slice(&16u32.to_le_bytes());
    raw[block_offset + 8..block_offset + 10].copy_from_slice(&0xa008u16.to_le_bytes());
    raw[block_offset + 10..block_offset + 12].copy_from_slice(&0u16.to_le_bytes());
    put_directory(
        &mut raw,
        &headers,
        DataDirectoryType::BaseReloc.as_index(),
        rdata.virtual_address + raw_size - 12,
        16,
    );

    let image = PeImage::parse(&raw).unwrap();
    let mapped = PeImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
    let relocations = image.relocations().unwrap();
    assert_eq!(relocations.blocks.len(), 1);
    assert_eq!(relocations.blocks[0].entries.len(), 4);
    assert_eq!(relocations, mapped.relocations().unwrap());
}

#[test]
fn pe_file_round_trips_headers_that_overlap_section_data() {
    // Packers such as UPX declare a `SizeOfHeaders` that covers the first section.
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let text = &headers.section_headers[0];
    put_size_of_headers(&mut raw, &headers, text.pointer_to_raw_data + 0x200);
    let slack =
        section_table_offset(&headers) + headers.section_headers.len() * SectionHeader::SIZE;
    raw[slack..slack + 4].copy_from_slice(b"UPX!");

    let file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn pe_file_round_trips_sections_that_share_raw_bytes() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let text = &headers.section_headers[0];
    let rdata_header = section_table_offset(&headers) + SectionHeader::SIZE;
    raw[rdata_header + 20..rdata_header + 24]
        .copy_from_slice(&text.pointer_to_raw_data.to_le_bytes());

    let file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn pe_file_keeps_an_edit_to_a_section_that_shares_raw_bytes() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let text = &headers.section_headers[0];
    let rdata_header = section_table_offset(&headers) + SectionHeader::SIZE;
    raw[rdata_header + 20..rdata_header + 24]
        .copy_from_slice(&text.pointer_to_raw_data.to_le_bytes());

    let mut file = PeFile::parse(&raw).unwrap();
    file.sections[1].data[0] = 0x11;
    let rebuilt = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert_eq!(rebuilt.sections[0].data[0], 0xcc);
    assert_eq!(rebuilt.sections[1].data[0], 0x11);
}

#[test]
fn pe_file_ignores_the_file_offset_of_a_section_without_raw_data() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let rdata_header = section_table_offset(&headers) + SectionHeader::SIZE;
    // The loader ignores `PointerToRawData` if `SizeOfRawData` is zero.
    raw[rdata_header + 16..rdata_header + 20].copy_from_slice(&0u32.to_le_bytes());
    raw[rdata_header + 20..rdata_header + 24].copy_from_slice(&0x0010_0000u32.to_le_bytes());

    let file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn pe_file_round_trips_a_section_table_after_size_of_headers() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let table_end =
        section_table_offset(&headers) + headers.section_headers.len() * SectionHeader::SIZE;
    // The loader reads the complete section table, also after `SizeOfHeaders`.
    put_size_of_headers(&mut raw, &headers, u32::try_from(table_end - 8).unwrap());

    let file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn pe_file_overlay_starts_after_the_section_table() {
    let mut raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let table_end = section_table_offset(&headers);
    // The headers end after `SizeOfHeaders`, and no section follows them.
    put_size_of_headers(&mut raw, &headers, u32::try_from(table_end - 8).unwrap());
    raw.extend_from_slice(b"overlay");

    let file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.overlay(), &raw[table_end..]);
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn image_size_covers_headers_without_sections() {
    // A file can put the PE header after the first page, with no sections after it.
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .try_build()
        .unwrap();
    image.dos_header.e_lfanew = 0x1200;
    image.dos_stub.resize(0x1200 - 64, 0);
    image.try_update_layout().unwrap();
    assert!(image.optional_header.size_of_image() >= image.optional_header.size_of_headers());

    let mapped = PeImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
    assert_eq!(mapped.dos_header.e_lfanew, 0x1200);
}
