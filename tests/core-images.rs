//! Regression tests for core executable images.

use portex::directories::{
    Certificate, CertificateRevision, CertificateType, ExportAddress, ExportDirectory, ExportTable,
    ExportTableBuilder, ExportedFunction, LoadConfigBuilder, LoadConfigDirectory,
    LoadConfigDirectory32, LoadConfigDirectory64, RelocationBlock, RelocationEntry,
    RelocationTable, RelocationType, RuntimeFunction, SecurityDirectory, TlsDirectory,
    TlsDirectory64, TlsInfo, UnwindInfo,
};
use portex::headers::{CoffHeader, DataDirectoryType, MachineType, OptionalHeader, SectionHeader};
use portex::image::{MissingSectionData, ParseOptions, PeBuilder, PeFile, PeHeaders, PeImage};
use portex::io::{Cursor, ReadAt, SeekReader};
use portex::resource::{ResourceDirectory, ResourceDirectoryEntry, ResourceDirectoryHeader};
use portex::section::characteristics;
use portex::{ExceptionTable, PackedRuntimeFunction, SourceLayout, Subsystem, ValidationCode};

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

fn section_table_offset(headers: &PeHeaders) -> usize {
    usize::try_from(headers.pe_offset).expect("PE offset fits usize")
        + 4
        + CoffHeader::SIZE
        + headers.coff_header.size_of_optional_header as usize
}

fn raw_image_end(bytes: &[u8]) -> usize {
    let headers = PeHeaders::from_slice(bytes).unwrap();
    headers
        .section_headers
        .iter()
        .filter(|section| section.pointer_to_raw_data != 0)
        .map(|section| section.pointer_to_raw_data as usize + section.size_of_raw_data as usize)
        .fold(
            headers.optional_header.size_of_headers() as usize,
            usize::max,
        )
}

fn read_from_blob(blob: &[u8], base_rva: u32, rva: u32, len: usize) -> Option<Vec<u8>> {
    let start = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
    let end = start.checked_add(len)?;
    blob.get(start..end).map(<[u8]>::to_vec)
}

#[test]
fn strict_and_lenient_mapped_parsing_are_explicit() {
    let image = test_image();
    let mapped = image.to_mapped_image().unwrap();
    // A remote reader cannot read the pages of the sections.
    let truncated = &mapped[..image.optional_header.size_of_headers() as usize];

    assert!(PeImage::parse_mapped(truncated).is_err());
    let parsed = PeImage::parse_with_options(
        truncated,
        ParseOptions::mapped().allow_missing_section_data(),
    )
    .unwrap();
    assert_eq!(parsed.source_layout(), SourceLayout::Mapped);
    assert!(
        parsed
            .sections
            .iter()
            .all(|section| section.data.is_empty())
    );
    assert_eq!(
        ParseOptions::mapped().missing_section_data,
        MissingSectionData::Error
    );
}

#[test]
fn nonstandard_pe_header_offset_round_trips() {
    let mut image = test_image();
    image.dos_header.e_lfanew = 0x240;
    image.dos_stub.resize(0x240 - 64, 0xa5);
    let raw = image.try_build().unwrap();
    let parsed = PeImage::parse(&raw).unwrap();
    assert_eq!(parsed.dos_header.e_lfanew, 0x240);
    assert_eq!(parsed.dos_stub.len(), 0x240 - 64);
    assert_eq!(parsed.try_build().unwrap(), raw);
}

#[test]
fn mapped_virtual_tail_does_not_implicitly_become_raw_data() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let rdata_index = headers
        .section_headers
        .iter()
        .position(|section| section.name_str() == ".rdata")
        .unwrap();
    let rdata_header = section_table_offset(&headers) + rdata_index * SectionHeader::SIZE;
    raw[rdata_header + 8..rdata_header + 12].copy_from_slice(&0x380u32.to_le_bytes());

    let raw_image = PeImage::parse(&raw).unwrap();
    let mapped = raw_image.to_mapped_image().unwrap();
    let mut mapped_image = PeImage::parse_mapped(&mapped).unwrap();
    let rebuilt = mapped_image.try_build().unwrap();
    let rebuilt_headers = PeHeaders::from_slice(&rebuilt).unwrap();
    assert_eq!(
        rebuilt_headers.section_headers[rdata_index].size_of_raw_data,
        headers.section_headers[rdata_index].size_of_raw_data
    );

    mapped_image
        .section_by_name_mut(".rdata")
        .unwrap()
        .materialize_virtual_data();
    let materialized = mapped_image.try_build().unwrap();
    let materialized_headers = PeHeaders::from_slice(&materialized).unwrap();
    assert!(materialized_headers.section_headers[rdata_index].size_of_raw_data >= 0x380);
}

#[test]
fn bss_remains_virtual_only_across_raw_and_mapped_forms() {
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".bss",
            Vec::new(),
            characteristics::UNINITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
        )
        .try_build()
        .unwrap();
    image.sections[0].header.virtual_size = 0x300;
    image.try_update_layout().unwrap();
    let raw = image.try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    assert_eq!(headers.section_headers[0].size_of_raw_data, 0);
    assert_eq!(headers.section_headers[0].pointer_to_raw_data, 0);

    let mapped = image.to_mapped_image().unwrap();
    let parsed = PeImage::parse_mapped(&mapped).unwrap();
    assert_eq!(parsed.sections[0].data.len(), 0x300);
    assert!(parsed.sections[0].data.iter().all(|byte| *byte == 0));
    assert_eq!(
        PeHeaders::from_slice(&parsed.try_build().unwrap())
            .unwrap()
            .section_headers[0]
            .size_of_raw_data,
        0
    );
}

#[test]
fn pe_file_preserves_noncanonical_gaps_and_overlay_exactly() {
    let mut raw = test_image().try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let second_header = section_table_offset(&headers) + SectionHeader::SIZE;
    let old_start = headers.section_headers[1].pointer_to_raw_data as usize;
    let gap = vec![0x7b; 0x200];
    raw.splice(old_start..old_start, gap);
    let new_start = u32::try_from(old_start + 0x200).unwrap();
    raw[second_header + 20..second_header + 24].copy_from_slice(&new_start.to_le_bytes());
    raw.extend_from_slice(b"overlay\0bytes");

    let file = PeFile::parse(&raw).unwrap();
    assert!(file.preserves_source_gaps());
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn certificates_preserve_unknown_values_and_other_overlay_bytes() {
    let mut raw = test_image().try_build().unwrap();
    raw.extend_from_slice(b"user-overlay");
    let mut file = PeFile::parse(&raw).unwrap();
    let security = SecurityDirectory {
        certificates: vec![Certificate {
            length: 11,
            revision: CertificateRevision::Unknown(0x3456),
            certificate_type: CertificateType::Unknown(0x789a),
            data: vec![1, 2, 3],
        }],
    };
    file.set_security(&security).unwrap();
    let rebuilt = file.try_build().unwrap();
    let reparsed = PeFile::parse(&rebuilt).unwrap();
    assert!(reparsed.overlay().starts_with(b"user-overlay"));
    assert_eq!(reparsed.security().unwrap(), Some(security));

    let mut cleared = reparsed;
    cleared.clear_security();
    let cleared_bytes = cleared.try_build().unwrap();
    let cleared_file = PeFile::parse(&cleared_bytes).unwrap();
    assert!(cleared_file.security().unwrap().is_none());
    assert!(cleared_file.overlay().starts_with(b"user-overlay"));
}

#[test]
fn misaligned_certificate_file_offset_is_ignored_and_kept() {
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
    let mut raw = file.try_build().unwrap();
    let headers = PeHeaders::from_slice(&raw).unwrap();
    let security =
        headers.optional_header.data_directories()[DataDirectoryType::Security.as_index()];
    let optional =
        usize::try_from(headers.pe_offset).expect("PE offset fits usize") + 4 + CoffHeader::SIZE;
    let entry = optional + portex::OptionalHeader64::BASE_SIZE + 4 * 8;
    raw[entry..entry + 4].copy_from_slice(&(security.virtual_address + 1).to_le_bytes());

    // The loader does not use the Security directory, so a bad entry does not stop the parse.
    let mut file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.security().unwrap(), None);
    assert_eq!(file.try_build().unwrap(), raw);

    // An explicit clear removes the entry.
    file.clear_security();
    let cleared = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert!(
        !cleared
            .data_directory(DataDirectoryType::Security)
            .is_some_and(|directory| directory.is_present())
    );
}

#[test]
fn relocation_materializes_a_rebased_mapped_image() {
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".text",
            vec![0; 0x100],
            characteristics::CODE | characteristics::READ | characteristics::WRITE,
        )
        .add_section(
            ".reloc",
            vec![0; 0x40],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    let preferred = image.image_base();
    image.sections[0].data[..8].copy_from_slice(&(preferred + 0x1234).to_le_bytes());
    image
        .update_relocations(
            &RelocationTable {
                blocks: vec![RelocationBlock {
                    page_rva: 0x1000,
                    block_size: 0,
                    entries: vec![RelocationEntry {
                        reloc_type: RelocationType::Dir64,
                        offset: 0,
                    }],
                }],
            },
            Some(".reloc"),
        )
        .unwrap();
    let runtime = preferred + 0x20_0000;
    let mapped = image.to_mapped_image_at(runtime).unwrap();
    assert_eq!(
        u64::from_le_bytes(mapped[0x1000..0x1008].try_into().unwrap()),
        runtime + 0x1234
    );
    let parsed = PeImage::parse_mapped_at(&mapped, runtime).unwrap();
    assert_eq!(parsed.runtime_image_base(), runtime);
}

#[test]
fn relocated_mapped_tls_uses_the_runtime_base() {
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".text",
            vec![0xcc; 0x100],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".rdata",
            vec![0; 0x100],
            characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
        )
        .add_section(
            ".reloc",
            vec![0; 0x40],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    let preferred = image.image_base();
    let tls = TlsInfo {
        directory: Some(TlsDirectory::Tls64(TlsDirectory64 {
            start_address_of_raw_data: preferred + 0x2000,
            end_address_of_raw_data: preferred + 0x2010,
            address_of_index: 0,
            address_of_callbacks: 0,
            size_of_zero_fill: 7,
            characteristics: 0x1234,
        })),
        callback_rvas: vec![0x1000],
        image_base: preferred,
    };
    let tls_rva = image.update_tls(&tls, Some(".rdata")).unwrap();
    let page = tls_rva & !0xfff;
    let offsets = [0u32, 8, 16, 24, 48]
        .into_iter()
        .map(|relative| RelocationEntry {
            reloc_type: RelocationType::Dir64,
            offset: u16::try_from((tls_rva + relative) - page).unwrap(),
        })
        .collect();
    image
        .update_relocations(
            &RelocationTable {
                blocks: vec![RelocationBlock {
                    page_rva: page,
                    block_size: 0,
                    entries: offsets,
                }],
            },
            Some(".reloc"),
        )
        .unwrap();

    let runtime = preferred + 0x10_0000;
    let mapped = image.to_mapped_image_at(runtime).unwrap();
    let parsed = PeImage::parse_mapped_at(&mapped, runtime).unwrap();
    let parsed_tls = parsed.tls().unwrap().unwrap();
    assert_eq!(parsed_tls.image_base, runtime);
    assert_eq!(parsed_tls.callback_rvas, vec![0x1000]);
    match parsed_tls.directory.unwrap() {
        TlsDirectory::Tls64(directory) => {
            assert_eq!(directory.start_address_of_raw_data, runtime + 0x2000);
            assert_eq!(directory.size_of_zero_fill, 7);
            assert_eq!(directory.characteristics, 0x1234);
        }
        TlsDirectory::Tls32(_) => panic!("expected PE32+ TLS"),
    }
}

#[test]
fn sparse_exports_and_aliases_round_trip() {
    let base = 0x5000;
    let table = ExportTable {
        directory: ExportDirectory {
            base: 10,
            ..Default::default()
        },
        dll_name: "sample.dll".to_string(),
        exports: vec![
            ExportedFunction {
                ordinal: 10,
                name: Some("Primary".to_string()),
                aliases: vec!["Alias".to_string()],
                address: ExportAddress::Rva(0x1000),
            },
            ExportedFunction {
                ordinal: 12,
                name: Some("Forwarded".to_string()),
                aliases: Vec::new(),
                address: ExportAddress::Forwarder("OTHER.Target".to_string()),
            },
        ],
    };
    let (bytes, size) = ExportTableBuilder::new(base).try_build(&table).unwrap();
    let parsed = ExportTable::parse(base, size, |rva, len| {
        read_from_blob(&bytes, base, rva, len)
    })
    .unwrap();
    assert_eq!(parsed.directory.number_of_functions, 3);
    assert_eq!(parsed.find_by_name("Alias").unwrap().ordinal, 10);
    assert!(matches!(
        parsed.find_by_ordinal(12).unwrap().address,
        ExportAddress::Forwarder(_)
    ));
}

#[test]
fn short_directory_callback_is_an_error_not_a_panic() {
    let base = 0x6000;
    let table = ExportTable {
        directory: ExportDirectory {
            base: 1,
            ..Default::default()
        },
        dll_name: "x.dll".to_string(),
        exports: vec![ExportedFunction {
            ordinal: 1,
            name: Some("X".to_string()),
            aliases: Vec::new(),
            address: ExportAddress::Rva(0x1000),
        }],
    };
    let (bytes, size) = ExportTableBuilder::new(base).try_build(&table).unwrap();
    let header = ExportDirectory::parse(&bytes).unwrap();
    let result = ExportTable::parse(base, size, |rva, len| {
        if rva == header.address_of_functions {
            Some(vec![0; 1])
        } else {
            read_from_blob(&bytes, base, rva, len)
        }
    });
    assert!(result.is_err());
}

#[test]
fn malformed_resource_entry_order_is_rejected() {
    let base = 0x3000;
    let mut bytes = vec![0u8; ResourceDirectoryHeader::SIZE + ResourceDirectoryEntry::SIZE];
    let header = ResourceDirectoryHeader {
        number_of_named_entries: 1,
        ..Default::default()
    };
    bytes[..ResourceDirectoryHeader::SIZE].copy_from_slice(&header.to_bytes());
    let numeric_entry = ResourceDirectoryEntry {
        name_or_id: 1,
        offset_to_data: 0x8000_0018,
    };
    bytes[ResourceDirectoryHeader::SIZE..].copy_from_slice(&numeric_entry.to_bytes());
    assert!(
        ResourceDirectory::parse(base, u32::try_from(bytes.len()).unwrap(), |rva, len| {
            read_from_blob(&bytes, base, rva, len)
        })
        .is_err()
    );
}

#[test]
fn load_config_preserves_versioned_tail_and_checks_pe32_values() {
    let config = LoadConfigDirectory32 {
        security_cookie: 0x0040_1000,
        trailing_data: vec![9, 8, 7, 6, 5],
        ..Default::default()
    };
    let bytes = config.try_to_bytes().unwrap();
    let parsed = LoadConfigDirectory32::parse(&bytes).unwrap();
    assert_eq!(parsed.trailing_data, config.trailing_data);
    assert_eq!(parsed.size as usize, bytes.len());

    let builder = LoadConfigBuilder::new(false);
    assert!(
        builder
            .try_build_with_cookie(u64::from(u32::MAX) + 1)
            .is_err()
    );
    assert!(
        builder
            .try_build(&LoadConfigDirectory::Config64(
                LoadConfigDirectory64::default()
            ))
            .is_err()
    );
}

#[test]
fn chained_unwind_info_requires_a_complete_runtime_function() {
    let function = RuntimeFunction {
        begin_address: 0x1000,
        end_address: 0x1100,
        unwind_info_address: 0x2000,
    };
    let info = UnwindInfo {
        version_flags: 1 | (portex::exception::UNW_FLAG_CHAININFO << 3),
        chained_info: Some(function.begin_address),
        chained_function: Some(function),
        ..Default::default()
    };
    let bytes = info.try_to_bytes().unwrap();
    assert_eq!(bytes.len(), 16);
    assert_eq!(UnwindInfo::parse(&bytes).unwrap(), info);

    let incomplete = UnwindInfo {
        version_flags: info.version_flags,
        chained_info: Some(0x1000),
        ..Default::default()
    };
    assert!(incomplete.try_to_bytes().is_err());
}

#[test]
fn arm64_exception_records_are_architecture_aware() {
    let record = PackedRuntimeFunction {
        begin_address: 0x1000,
        unwind_data: 1,
    }
    .to_bytes();
    let parsed = ExceptionTable::parse(
        MachineType::Arm64 as u16,
        0x7000,
        u32::try_from(record.len()).unwrap(),
        |rva, len| read_from_blob(&record, 0x7000, rva, len),
    )
    .unwrap();
    assert!(matches!(parsed, ExceptionTable::Arm64(_)));

    let reserved = PackedRuntimeFunction {
        begin_address: 0x1000,
        unwind_data: 3,
    }
    .to_bytes();
    assert!(
        ExceptionTable::parse(
            MachineType::Arm64 as u16,
            0x7000,
            u32::try_from(reserved.len()).unwrap(),
            |rva, len| read_from_blob(&reserved, 0x7000, rva, len),
        )
        .is_err()
    );
}

#[test]
fn nostdio_cursor_and_positional_adapter_round_trip() {
    let raw = test_image().try_build().unwrap();
    let file = PeFile::parse(&raw).unwrap();
    let mut output = Cursor::new(Vec::new());
    file.write_to(&mut output).unwrap();
    output.set_position(0);
    let streamed = PeFile::from_stream(&mut output).unwrap();
    assert_eq!(streamed.try_build().unwrap(), raw);

    let reader = SeekReader::with_discovered_size(Cursor::new(raw)).unwrap();
    let parsed = PeImage::read_from(&reader, 0, SourceLayout::File).unwrap();
    assert_eq!(parsed.entry_point(), 0x1000);
}

#[test]
fn stream_errors_keep_the_nostdio_error() {
    let raw = test_image().try_build().unwrap();
    let file = PeFile::parse(&raw).unwrap();
    let mut small = [0u8; 16];
    let error = file.write_to(&mut Cursor::new(&mut small[..])).unwrap_err();
    assert!(matches!(error.kind, portex::ErrorKind::Io(_)));
    assert!(core::error::Error::source(&error).is_some());
}

struct OverReportingReader;

impl ReadAt for OverReportingReader {
    fn read_at(&self, _offset: u64, buffer: &mut [u8]) -> portex::Result<usize> {
        Ok(buffer.len() + 1)
    }

    fn size(&self) -> Option<u64> {
        None
    }
}

#[test]
fn positional_reader_rejects_an_impossible_read_count() {
    let error = OverReportingReader.read_u32_at(0).unwrap_err();
    assert!(matches!(error.kind, portex::error::ErrorKind::Generic(_)));
}

#[test]
fn validation_reports_derived_image_size_mismatch() {
    let mut image = test_image();
    match &mut image.optional_header {
        OptionalHeader::Pe32(header) => header.size_of_image = 0x1000,
        OptionalHeader::Pe32Plus(header) => header.size_of_image = 0x1000,
    }
    let result = image.validate();
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InconsistentImageSize)
    );
}

#[test]
fn linker_aggregate_differences_are_advisory() {
    let mut image = test_image();
    match &mut image.optional_header {
        OptionalHeader::Pe32(header) => header.size_of_initialized_data += 0x200,
        OptionalHeader::Pe32Plus(header) => header.size_of_initialized_data += 0x200,
    }

    let result = image.validate();
    assert!(!result.has_errors());
    assert!(result.issues.iter().any(|issue| {
        issue.code == ValidationCode::InconsistentOptionalHeader
            && issue.level == portex::ValidationLevel::Warning
    }));
}

#[test]
fn builder_rejects_machine_and_optional_header_width_mismatch() {
    assert!(
        PeBuilder::new()
            .machine(MachineType::Amd64)
            .pe32_plus(false)
            .try_build()
            .is_err()
    );
}

#[test]
fn ebc_builder_uses_the_required_pe32_plus_header() {
    let image = PeBuilder::new()
        .machine(MachineType::Ebc)
        .try_build()
        .unwrap();
    assert!(image.is_64bit());
}

#[test]
fn pe_file_overlay_starts_after_all_raw_sections() {
    let mut raw = test_image().try_build().unwrap();
    let end = raw_image_end(&raw);
    assert_eq!(end, raw.len());
    raw.extend_from_slice(b"tail");
    let file = PeFile::parse(&raw).unwrap();
    assert_eq!(file.overlay(), b"tail");
}
