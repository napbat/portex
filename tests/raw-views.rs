//! Tests for the raw views of `portex::raw`: offsets, end rules and reads of a changed buffer.

use portex::headers::{CoffHeader, MachineType, OptionalHeader, SectionHeader};
use portex::image::{PeBuilder, PeHeaders};
use portex::raw::{
    ImportTableEnd, RawAddressTable, RawCursor, RawExportDirectory, RawField, RawImportByName,
    RawImportDescriptor, RawImportDescriptors, RawLoadConfigDirectory, RawRelocationBlock,
    RawRelocationBlocks, RawResourceDataEntry, RawResourceDirectory, RawResourceEntry,
    RawRuntimeFunctions, RawUnwindInfo,
};
use portex::section::characteristics;
use portex::{ErrorKind, ExportDirectory, RelocationType, Subsystem};

/// Build a raw file with two sections.
fn raw_file(is_64bit: bool) -> Vec<u8> {
    let machine = if is_64bit {
        MachineType::Amd64
    } else {
        MachineType::I386
    };
    PeBuilder::new()
        .machine(machine)
        .pe32_plus(is_64bit)
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
        .try_build()
        .unwrap()
}

/// Write a little-endian `u32` at `offset`.
fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write a little-endian `u16` at `offset`.
fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Make a buffer from little-endian `u32` values.
fn words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// Read all records of `cursor` from `data`.
fn collect<C: RawCursor>(cursor: C, data: &[u8]) -> Vec<C::Item> {
    cursor.iter(data).collect::<Result<_, _>>().unwrap()
}

#[test]
fn strict_headers_reject_a_section_table_after_the_end_of_the_file() {
    let raw = raw_file(true);
    let full = PeHeaders::from_slice_strict(&raw).unwrap();
    assert_eq!(full, PeHeaders::from_slice(&raw).unwrap());

    let offsets = full.header_offsets().unwrap();
    let cut = &raw[..offsets.section_header(1).unwrap() + 8];
    // The lenient parser reads the missing bytes as zeros.
    let padded = PeHeaders::from_slice(cut).unwrap();
    assert_eq!(padded.section_headers[1].size_of_raw_data, 0);
    let error = PeHeaders::from_slice_strict(cut).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::BufferTooSmall { .. }));
}

#[test]
fn strict_headers_keep_the_rules_of_the_lenient_parser() {
    let mut raw = raw_file(false);
    // An `e_lfanew` of 1 puts the PE signature over `e_magic`.
    put_u32(&mut raw, 0x3c, 1);
    assert!(PeHeaders::from_slice_strict(&raw).is_err());
    assert!(PeHeaders::from_slice(&raw).is_err());
}

#[test]
fn header_offsets_point_to_the_parsed_fields() {
    for is_64bit in [false, true] {
        let mut raw = raw_file(is_64bit);
        let headers = PeHeaders::from_slice(&raw).unwrap();
        let offsets = headers.header_offsets().unwrap();
        assert_eq!(
            offsets.nt_headers,
            usize::try_from(headers.pe_offset).unwrap()
        );
        assert_eq!(
            offsets.optional_header,
            offsets.coff_header + CoffHeader::SIZE
        );
        assert_eq!(&raw[offsets.nt_headers..offsets.nt_headers + 4], b"PE\0\0");

        put_u32(&mut raw, offsets.time_date_stamp, 0x1111_1111);
        put_u32(&mut raw, offsets.image_base, 0x2222_0000);
        put_u32(&mut raw, offsets.size_of_image, 0x3333_3000);
        put_u32(&mut raw, offsets.size_of_headers, 0x400);
        put_u32(&mut raw, offsets.check_sum, 0x4444_4444);
        let entry = offsets.data_directory(8).unwrap();
        put_u32(&mut raw, entry, 0x5555_5555);
        let section = offsets.section_header(1).unwrap();
        put_u32(&mut raw, section + 36, 0x6666_6666);

        let changed = PeHeaders::from_slice(&raw).unwrap();
        let optional = &changed.optional_header;
        assert_eq!(changed.coff_header.time_date_stamp, 0x1111_1111);
        assert_eq!(optional.image_base() & 0xffff_ffff, 0x2222_0000);
        assert_eq!(optional.size_of_image(), 0x3333_3000);
        assert_eq!(optional.size_of_headers(), 0x400);
        let check_sum = match optional {
            OptionalHeader::Pe32(header) => header.check_sum,
            OptionalHeader::Pe32Plus(header) => header.check_sum,
        };
        assert_eq!(check_sum, 0x4444_4444);
        assert_eq!(optional.data_directories()[8].virtual_address, 0x5555_5555);
        assert_eq!(changed.section_headers[1].characteristics, 0x6666_6666);
        assert_eq!(
            offsets.section_header(1).unwrap() - offsets.section_table,
            SectionHeader::SIZE
        );
        assert_eq!(offsets.data_directory(usize::MAX), None);
    }
}

#[test]
fn import_descriptors_follow_the_selected_end_rule() {
    // The second descriptor has no `OriginalFirstThunk`, but it is not a null descriptor.
    let data = words(&[
        0x2000, 0, 0, 0x3000, 0x4000, //
        0, 0, 0, 0x3100, 0x4100, //
        0, 0, 0, 0, 0, //
        0x2200, 0, 0, 0x3200, 0x4200,
    ]);
    let loader = collect(
        RawImportDescriptors::new(0, data.len(), ImportTableEnd::NullDescriptor),
        &data,
    );
    assert_eq!(loader.len(), 2);
    assert_eq!(
        loader[1].name_rva,
        RawField {
            offset: 32,
            value: 0x3100
        }
    );
    assert_eq!(loader[1].first_thunk.offset, 36);
    assert_eq!(loader[0].descriptor().first_thunk, 0x4000);

    let first_zero = collect(
        RawImportDescriptors::new(0, data.len(), ImportTableEnd::ZeroOriginalFirstThunk),
        &data,
    );
    assert_eq!(first_zero.len(), 1);

    // The size limit ends the list before a partial descriptor.
    let short = collect(
        RawImportDescriptors::new(0, 39, ImportTableEnd::NullDescriptor),
        &data,
    );
    assert_eq!(short.len(), 1);
    assert!(RawImportDescriptor::parse(&data, data.len() - 19).is_err());
}

#[test]
fn address_tables_end_at_zero_or_after_the_count() {
    let data = words(&[0x10, 0x20, 0, 0x40, 0x8000_0001]);
    let thunks = collect(
        RawAddressTable::zero_terminated(0, data.len(), false),
        &data,
    );
    let values: Vec<u64> = thunks.iter().map(|entry| entry.value).collect();
    assert_eq!(values, [0x10, 0x20]);
    assert_eq!(thunks[1].offset, 4);

    // A partial entry at the end of the size does not count.
    let limited = collect(RawAddressTable::zero_terminated(0, 7, false), &data);
    assert_eq!(limited.len(), 1);

    let counted = collect(RawAddressTable::counted(0, 4, false), &data);
    let values: Vec<u64> = counted.iter().map(|entry| entry.value).collect();
    assert_eq!(values, [0x10, 0x20, 0, 0x40]);

    let zero = words(&[1, 0, 0, 0]);
    let wide = collect(RawAddressTable::zero_terminated(0, zero.len(), true), &zero);
    assert_eq!(wide.len(), 1);
    let wide = collect(RawAddressTable::zero_terminated(12, 8, true), &data);
    assert_eq!(wide[0].value, 0x8000_0001_0000_0040);
    assert_eq!(RawAddressTable::counted(0, 1, true).entry_size(), 8);

    let error = RawAddressTable::counted(16, 2, false)
        .iter(&data)
        .nth(1)
        .unwrap()
        .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::OffsetOutOfBounds { .. }));
}

#[test]
fn a_cursor_reads_the_buffer_that_the_caller_changed() {
    let mut data = words(&[0x10, 0x20, 0x30, 0]);
    let mut table = RawAddressTable::zero_terminated(0, data.len(), false);
    let first = table.read_next(&data).unwrap().unwrap();
    assert_eq!(first.value, 0x10);
    // Clear the next entry: the cursor sees the zero and ends.
    put_u32(&mut data, 4, 0);
    assert_eq!(table.read_next(&data).unwrap(), None);
    assert_eq!(table.read_next(&data).unwrap(), None);
}

#[test]
fn import_by_name_needs_a_terminator_in_the_limit() {
    let mut data = vec![0x07, 0x00];
    data.extend_from_slice(b"Sleep\0");
    data.extend_from_slice(b"xx");
    let entry = RawImportByName::parse(&data, 0, 8).unwrap().unwrap();
    assert_eq!(entry.hint.value, 7);
    assert_eq!(entry.name(&data), Some(&b"Sleep"[..]));
    assert_eq!(entry.size(), 8);
    assert_eq!(entry.name_offset, 2);

    // The terminator is at index 7, so a limit of 7 bytes does not include it.
    assert_eq!(RawImportByName::parse(&data, 0, 7).unwrap(), None);
    assert_eq!(RawImportByName::parse(&data, 0, 2).unwrap(), None);
    // A limit after the end of the buffer reads until the first missing byte.
    assert!(RawImportByName::parse(&data[..6], 0, 100).is_err());
}

#[test]
fn export_directory_keeps_the_field_offsets() {
    let directory = ExportDirectory {
        name_rva: 0x3000,
        base: 1,
        number_of_functions: 3,
        number_of_names: 2,
        address_of_functions: 0x3100,
        address_of_names: 0x3200,
        address_of_name_ordinals: 0x3300,
        ..ExportDirectory::default()
    };
    let mut data = vec![0xee; 8];
    data.extend_from_slice(&directory.to_bytes());
    let raw = RawExportDirectory::parse(&data, 8).unwrap();
    assert_eq!(raw.directory(), directory);
    assert_eq!(raw.address_of_functions.offset, 8 + 28);
    assert_eq!(raw.address_of_name_ordinals.offset, 8 + 36);
    assert_eq!(raw.address_table_size(), Some(12));
    assert_eq!(raw.name_table_size(), Some(8));
    assert_eq!(raw.ordinal_table_size(), Some(4));

    put_u32(&mut data, 8 + 20, 0x4000_0000);
    put_u32(&mut data, 8 + 24, 0x8000_0000);
    let raw = RawExportDirectory::parse(&data, 8).unwrap();
    assert_eq!(raw.address_table_size(), None);
    assert_eq!(raw.name_table_size(), None);
    assert_eq!(raw.ordinal_table_size(), None);
    assert!(RawExportDirectory::parse(&data, 9).is_err());
}

#[test]
fn relocation_blocks_end_at_a_bad_block_size() {
    let mut data = words(&[0x1000, 12, 0x3001_3002, 0x2000, 8, 0x3000, 4, 0]);
    let blocks = collect(RawRelocationBlocks::new(0, data.len()), &data);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[1].virtual_address.offset, 12);
    assert_eq!(blocks[1].size_of_block.value, 8);

    // A block larger than the rest of the table ends the table.
    put_u32(&mut data, 16, 100);
    assert_eq!(
        collect(RawRelocationBlocks::new(0, data.len()), &data).len(),
        1
    );
    // The size limit also ends the table.
    assert_eq!(collect(RawRelocationBlocks::new(0, 11), &data).len(), 0);
}

#[test]
fn relocation_entries_read_padding_and_highadj_parameters() {
    let mut data = words(&[0x1000, 16]);
    for word in [0x3010u16, 0x4020, 0x1234, 0x0000, 0x4030] {
        data.extend_from_slice(&word.to_le_bytes());
    }
    data.push(0xff);
    // `SizeOfBlock` 19 has an odd last byte, which the cursor ignores.
    put_u32(&mut data, 4, 19);
    let block = RawRelocationBlock::parse(&data, 0).unwrap();
    let entries = collect(block.entries(), &data);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].entry.reloc_type, RelocationType::HighLow);
    assert_eq!(entries[0].offset, 8);
    assert_eq!(entries[1].entry.reloc_type, RelocationType::HighAdj);
    assert_eq!(
        entries[1].parameter,
        Some(RawField {
            offset: 12,
            value: 0x1234
        })
    );
    assert!(entries[2].entry.is_padding());
    // The last word is a `HIGHADJ` entry without a parameter word.
    assert_eq!(entries[3].entry.reloc_type, RelocationType::HighAdj);
    assert_eq!(entries[3].parameter, None);

    // The cursor reads each word when the caller asks for it.
    let mut cursor = block.entries();
    cursor.read_next(&data).unwrap();
    put_u16(&mut data, 10, 0xa040);
    let next = cursor.read_next(&data).unwrap().unwrap();
    assert_eq!(next.entry.reloc_type, RelocationType::Dir64);
    assert_eq!(next.parameter, None);
}

#[test]
fn runtime_functions_keep_zero_records_and_drop_a_partial_record() {
    let data = words(&[
        0x1000, 0x1010, 0x2000, 0, 0, 0, 0x1020, 0x1030, 0x2010, 0xdead,
    ]);
    let cursor = RawRuntimeFunctions::new(4, data.len() - 4);
    assert_eq!(cursor.len(), 3);
    assert!(!cursor.is_empty());
    let functions = collect(cursor, &data);
    assert_eq!(functions[0].begin_address.value, 0x1010);
    assert_eq!(functions[0].unwind_info_address.offset, 12);
    assert_eq!(functions[1].function().begin_address, 0);

    let all = collect(RawRuntimeFunctions::new(0, data.len()), &data);
    assert_eq!(all.len(), 3);
    assert_eq!(all[1].function().unwind_info_address, 0);
    assert_eq!(all[2].end_address.value, 0x1030);
}

#[test]
fn unwind_info_finds_the_trailer_after_the_codes() {
    // Version 1, `UNW_FLAG_EHANDLER`, three unwind codes.
    let mut data = vec![0x09, 0x04, 0x03, 0x00];
    data.extend_from_slice(&[0; 8]);
    let info = RawUnwindInfo::parse(&data, 0).unwrap();
    assert_eq!(info.version(), 1);
    assert_eq!(info.flags(), 1);
    assert!(info.has_trailer());
    assert_eq!(info.size_without_trailer(), 12);
    assert_eq!(info.trailer_offset(), Some(12));
    assert_eq!(info.count_of_codes.offset, 2);

    for (codes, size) in [(0u8, 4usize), (1, 8), (2, 8), (4, 12)] {
        data[2] = codes;
        let info = RawUnwindInfo::parse(&data, 0).unwrap();
        assert_eq!(info.size_without_trailer(), size);
    }
    data[0] = 0x01;
    assert!(!RawUnwindInfo::parse(&data, 0).unwrap().has_trailer());
    // `UNW_FLAG_CHAININFO` also has a trailer.
    data[0] = 0x21;
    assert!(RawUnwindInfo::parse(&data, 0).unwrap().has_trailer());
    assert!(RawUnwindInfo::parse(&data, data.len() - 3).is_err());
}

#[test]
fn resource_views_keep_the_field_offsets() {
    let mut data = words(&[0, 0, 0, 0x0002_0001]);
    data.extend_from_slice(&words(&[0x8000_0040, 0x8000_0018, 3, 0x30]));
    data.extend_from_slice(&words(&[0x2000, 0x10, 1252, 0]));
    let directory = RawResourceDirectory::parse(&data, 0).unwrap();
    assert_eq!(directory.number_of_named_entries.value, 1);
    assert_eq!(directory.number_of_id_entries.value, 2);
    assert_eq!(directory.entry_count(), 3);
    assert_eq!(directory.entries_offset(), Some(16));

    let named = RawResourceEntry::parse(&data, 16).unwrap();
    assert!(named.is_named());
    assert!(named.is_directory());
    assert_eq!(named.name_offset(), 0x40);
    assert_eq!(named.child_offset(), 0x18);
    assert_eq!(named.offset_to_data.offset, 20);
    let id = RawResourceEntry::parse(&data, 24).unwrap();
    assert!(!id.is_named());
    assert!(!id.is_directory());

    let entry = RawResourceDataEntry::parse(&data, 32).unwrap();
    assert_eq!(entry.offset_to_data.value, 0x2000);
    assert_eq!(entry.code_page.value, 1252);
    assert_eq!(entry.size.offset, 36);
    assert!(RawResourceDataEntry::parse(&data, 40).is_err());
}

#[test]
fn load_config_view_ignores_the_size_field() {
    let mut data = vec![0; 0x30];
    // A `Size` of 8 does not cover `LockPrefixTable`.
    put_u32(&mut data, 0, 8);
    put_u32(&mut data, 0x20, 0x0040_1000);
    let config = RawLoadConfigDirectory::parse(&data, 0, false).unwrap();
    assert_eq!(config.size.value, 8);
    assert_eq!(
        config.lock_prefix_table,
        RawField {
            offset: 0x20,
            value: 0x0040_1000
        }
    );

    put_u32(&mut data, 0x28, 0x1000);
    put_u32(&mut data, 0x2c, 0x1);
    let config = RawLoadConfigDirectory::parse(&data, 0, true).unwrap();
    assert_eq!(config.lock_prefix_table.offset, 0x28);
    assert_eq!(config.lock_prefix_table.value, 0x1_0000_1000);
    assert!(RawLoadConfigDirectory::parse(&data[..0x2f], 0, true).is_err());
}
