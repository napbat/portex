use super::*;

#[test]
fn test_import_descriptor_size() {
    assert_eq!(ImportDescriptor::SIZE, 20);
}

#[test]
fn test_import_descriptor_roundtrip() {
    let original = ImportDescriptor {
        original_first_thunk: 0x1000,
        time_date_stamp: 0,
        forwarder_chain: 0xFFFF_FFFF,
        name_rva: 0x2000,
        first_thunk: 0x3000,
    };

    let bytes = original.to_bytes();
    let parsed = ImportDescriptor::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_import_descriptor_is_null() {
    let null = ImportDescriptor::default();
    assert!(null.is_null());

    let not_null = ImportDescriptor {
        first_thunk: 0x1000,
        ..Default::default()
    };
    assert!(!not_null.is_null());
}

#[test]
fn test_thunk_ordinal_check() {
    assert!(ImportThunk::is_ordinal_entry_32(0x8000_0001));
    assert!(!ImportThunk::is_ordinal_entry_32(0x0000_1000));
    assert!(ImportThunk::is_ordinal_entry_64(0x8000_0000_0000_0001));
    assert!(!ImportThunk::is_ordinal_entry_64(0x0000_0000_0000_1000));
}

#[test]
fn test_import_table_builder_roundtrip() {
    // Create an import table.
    let mut table = ImportTable::default();
    table.add_named_import("kernel32.dll", "VirtualAlloc", 0);
    table.add_named_import("kernel32.dll", "VirtualFree", 0);
    table.add_ordinal_import("user32.dll", 123);

    assert_eq!(table.dlls.len(), 2);
    assert_eq!(table.dlls[0].imports.len(), 2);
    assert_eq!(table.dlls[1].imports.len(), 1);

    // Build the section for PE32+.
    let base_rva = 0x3000u32;
    let builder = ImportTableBuilder::new(true, base_rva);
    let size = builder.calculate_size(&table);
    assert!(size > 0);

    let (data, iat_rva, iat_size) = builder.build(&table);
    assert_eq!(data.len(), size);
    assert!(iat_rva >= base_rva);
    assert!(iat_size > 0);

    // Parse the built data again.
    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        if rva < base_rva {
            return None;
        }
        let offset = (rva - base_rva) as usize;
        if offset >= data.len() {
            return None;
        }
        // Return the available data, up to the requested length.
        let available = (data.len() - offset).min(len);
        Some(data[offset..offset + available].to_vec())
    };

    let parsed = ImportTable::parse(base_rva, true, read_fn).unwrap();
    assert_eq!(parsed.dlls.len(), 2);
    assert_eq!(parsed.dlls[0].name.to_lowercase(), "kernel32.dll");
    assert_eq!(parsed.dlls[0].imports.len(), 2);
    assert_eq!(parsed.dlls[1].name.to_lowercase(), "user32.dll");
    assert_eq!(parsed.dlls[1].imports.len(), 1);

    // Check the import names.
    if let ImportThunk::Name { name, .. } = &parsed.dlls[0].imports[0] {
        assert_eq!(name, "VirtualAlloc");
    } else {
        panic!("Expected named import");
    }
    if let ImportThunk::Ordinal(ord) = &parsed.dlls[1].imports[0] {
        assert_eq!(*ord, 123);
    } else {
        panic!("Expected ordinal import");
    }
}

#[test]
fn test_import_table_builder_pe32_thunks() {
    let mut table = ImportTable::default();
    table.add_named_import("kernel32.dll", "Sleep", 7);
    table.add_ordinal_import("kernel32.dll", 42);

    let base_rva = 0x2000u32;
    let (data, iat_rva, iat_size) = ImportTableBuilder::new(false, base_rva).build(&table);
    // Two thunks plus a null terminator, 4 bytes each.
    assert_eq!(iat_size, 12);

    let iat = usize::try_from(iat_rva - base_rva).unwrap();
    let thunk = |index: usize| {
        let at = iat + index * 4;
        u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
    };
    assert_eq!(thunk(1), IMAGE_ORDINAL_FLAG32 | 0x2A);
    assert_eq!(thunk(2), 0);

    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let offset = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
        let end = offset.checked_add(len)?.min(data.len());
        data.get(offset..end).map(<[u8]>::to_vec)
    };
    let parsed = ImportTable::parse(base_rva, false, read_fn).unwrap();
    assert_eq!(
        parsed.dlls[0].imports,
        vec![
            ImportThunk::Name {
                hint: 7,
                name: "Sleep".to_string()
            },
            ImportThunk::Ordinal(42),
        ]
    );
}

#[test]
fn test_import_table_builder_pe32_layout() {
    let mut table = ImportTable::default();
    table.add_named_import("kernel32.dll", "Sleep", 7);
    table.add_ordinal_import("kernel32.dll", 42);

    let (data, iat_rva, iat_size) = ImportTableBuilder::new(false, 0x2000).build(&table);
    // Descriptors 0..40, ILT 40..52, IAT 52..64, hint/name 64..72, DLL name 72..85.
    assert_eq!(data.len(), 85);
    assert_eq!((iat_rva, iat_size), (0x2034, 12));
    let descriptor = ImportDescriptor::parse(&data).unwrap();
    assert_eq!(
        descriptor,
        ImportDescriptor {
            original_first_thunk: 0x2028,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: 0x2048,
            first_thunk: 0x2034,
        }
    );
    assert!(data[20..40].iter().all(|&byte| byte == 0));
    let thunks: Vec<u8> = [0x2040u32, 0x8000_002A, 0]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(&data[40..52], thunks.as_slice());
    assert_eq!(&data[52..64], thunks.as_slice());
    assert_eq!(&data[64..72], b"\x07\x00Sleep\0");
    assert_eq!(&data[72..], b"kernel32.dll\0");
}

#[test]
fn test_import_descriptor_write_short_buffer() {
    let mut buf = [0u8; ImportDescriptor::SIZE - 1];
    assert!(ImportDescriptor::default().write(&mut buf).is_err());
    assert!(ImportDescriptor::parse(&buf).is_err());
}

/// Return a reader for an image in which each RVA is the offset in `data`. The reader fails
/// for a range that is not fully in `data`, as the reader of `PeImage` does.
fn flat_reader(data: &[u8]) -> impl Fn(u32, usize) -> Option<Vec<u8>> + '_ {
    move |rva, len| {
        let start = usize::try_from(rva).ok()?;
        data.get(start..start.checked_add(len)?).map(<[u8]>::to_vec)
    }
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write `count` descriptors at offset 0, and the DLL name after the terminator. Each
/// descriptor has the thunk table at `thunks` (as the ILT and the IAT). Return the RVA of the
/// DLL name.
fn put_shared_descriptors(data: &mut [u8], count: usize, thunks: u32) -> u32 {
    let name = (count + 1) * ImportDescriptor::SIZE;
    let name_rva = u32::try_from(name).unwrap();
    for index in 0..count {
        let at = index * ImportDescriptor::SIZE;
        let descriptor = ImportDescriptor {
            original_first_thunk: thunks,
            name_rva,
            first_thunk: thunks,
            ..ImportDescriptor::default()
        };
        data[at..at + ImportDescriptor::SIZE].copy_from_slice(&descriptor.to_bytes());
    }
    data[name..name + 6].copy_from_slice(b"a.dll\0");
    name_rva
}

fn name_bytes(table: &ImportTable) -> usize {
    table
        .dlls
        .iter()
        .flat_map(|dll| &dll.imports)
        .map(|thunk| match thunk {
            ImportThunk::Name { name, .. } => name.len(),
            ImportThunk::Ordinal(_) => 0,
        })
        .sum()
}

/// Make an image with `thunk_count` PE32 thunks at 0x2000 that all point at one hint/name
/// entry at 0x8000 with a name of 4000 bytes.
fn shared_long_name_image(descriptors: usize, thunk_count: usize) -> Vec<u8> {
    let mut data = vec![0u8; 0x8000 + 2 + 4000 + 1];
    put_shared_descriptors(&mut data, descriptors, 0x2000);
    for index in 0..thunk_count {
        put32(&mut data, 0x2000 + index * 4, 0x8000);
    }
    data[0x8002..0x8002 + 4000].fill(b'A');
    data
}

#[test]
fn shared_hint_name_entries_are_limited_by_the_name_budget() {
    // Before the fix, each thunk made a new copy of the 4000-byte name without a limit. The
    // reviewer's shape (10 descriptors, 20,000 thunks) gave 819 MB of names.
    let data = shared_long_name_image(2, 300);
    let error = ImportTable::parse(0, false, flat_reader(&data)).unwrap_err();
    assert!(error.to_string().contains("names repeat"), "{error}");

    // A smaller output than the 1 MiB floor is permitted.
    let data = shared_long_name_image(1, 200);
    let table = ImportTable::parse(0, false, flat_reader(&data)).unwrap();
    assert_eq!(table.import_count(), 200);
    assert_eq!(name_bytes(&table), 200 * 4000);
}

#[test]
fn overlapping_names_are_limited_by_their_distinct_source_bytes() {
    // Each thunk points at a different offset in one run of 4000 bytes. Before the fix, the
    // 1000 names had about 3 MB in total.
    let mut data = vec![0u8; 0x8000 + 4000 + 1];
    put_shared_descriptors(&mut data, 1, 0x2000);
    for index in 0..1000u32 {
        put32(
            &mut data,
            0x2000 + usize::try_from(index).unwrap() * 4,
            0x8000 + index * 2,
        );
    }
    data[0x8000..0x8000 + 4000].fill(b'A');
    let error = ImportTable::parse(0, false, flat_reader(&data)).unwrap_err();
    assert!(error.to_string().contains("names repeat"), "{error}");
}

#[test]
fn shared_thunk_tables_have_one_total_budget_and_are_read_once() {
    // Before the fix, the limit of 1,048,576 thunks applied to each descriptor, and each
    // descriptor read the shared table again, one thunk for each read.
    const THUNKS: usize = 16_384;
    let mut data = vec![0u8; 0x2000 + (THUNKS + 1) * 4];
    put_shared_descriptors(&mut data, 65, 0x2000);
    for index in 0..THUNKS {
        put32(&mut data, 0x2000 + index * 4, 0x8000_0001);
    }
    // 65 descriptors give 1,064,960 thunks: more than the total budget.
    let (result, _) = parse_counting_reads(&data);
    let error = result.unwrap_err();
    assert!(error.to_string().contains("in total"), "{error}");

    // 64 descriptors give exactly the budget. Each descriptor uses the table that the parser
    // read for the first descriptor.
    data[64 * ImportDescriptor::SIZE..65 * ImportDescriptor::SIZE].fill(0);
    let (result, reads) = parse_counting_reads(&data);
    assert_eq!(result.unwrap().import_count(), 64 * THUNKS);
    assert!(reads < 200, "{reads} reads");
}

/// Parse the PE32 import table at RVA 0 of `data`, and count the reads.
fn parse_counting_reads(data: &[u8]) -> (Result<ImportTable>, usize) {
    let reads = core::cell::Cell::new(0usize);
    let reader = flat_reader(data);
    let result = ImportTable::parse(0, false, |rva, len| {
        reads.set(reads.get() + 1);
        reader(rva, len)
    });
    (result, reads.get())
}

#[test]
fn ordinal_thunks_ignore_the_reserved_bits_as_the_loader_does() {
    for is_64bit in [false, true] {
        let mut data = vec![0u8; 0x300];
        put_shared_descriptors(&mut data, 1, 0x200);
        if is_64bit {
            data[0x200..0x208].copy_from_slice(&0x8000_0000_1234_0007u64.to_le_bytes());
        } else {
            put32(&mut data, 0x200, 0x8001_0007);
        }
        // Before the fix, the parse failed with "nonzero reserved bits".
        let table = ImportTable::parse(0, is_64bit, flat_reader(&data)).unwrap();
        assert_eq!(table.dlls[0].imports, [ImportThunk::Ordinal(7)]);
    }
}

#[test]
fn the_descriptor_table_ends_at_a_zero_name_or_first_thunk() {
    let mut data = vec![0u8; 0x300];
    let name_rva = put_shared_descriptors(&mut data, 2, 0x200);
    put32(&mut data, 0x200, 0x8000_0001);
    // The second descriptor has a zero `Name` and other nonzero fields. Before the fix, the
    // parse failed. The loader ends the table there.
    put32(&mut data, ImportDescriptor::SIZE + 12, 0);
    let table = ImportTable::parse(0, false, flat_reader(&data)).unwrap();
    assert_eq!(table.dlls.len(), 1);

    // A zero `FirstThunk` also ends the table. Before the fix, the parse read the DLL.
    put32(&mut data, ImportDescriptor::SIZE + 12, name_rva);
    put32(&mut data, ImportDescriptor::SIZE + 16, 0);
    let table = ImportTable::parse(0, false, flat_reader(&data)).unwrap();
    assert_eq!(table.dlls.len(), 1);
}

#[test]
fn pe32_plus_thunk_tables_have_8_byte_alignment() {
    let mut table = ImportTable::default();
    table.add_named_import("a.dll", "A", 0);
    table.add_named_import("b.dll", "B", 0);
    let (data, iat_rva, _) = ImportTableBuilder::new(true, 0x1000).build(&table);
    // Before the fix, the ILT was at 0x103C and the IAT at 0x105C.
    assert_eq!(iat_rva % 8, 0);
    let descriptor = ImportDescriptor::parse(&data).unwrap();
    assert_eq!(descriptor.original_first_thunk, 0x1040);
    assert_eq!(descriptor.first_thunk % 8, 0);
}

#[test]
fn the_builder_keeps_the_iat_of_each_unchanged_dll() {
    let existing = ImportTable {
        dlls: vec![
            ImportedDll {
                name: "a.dll".to_string(),
                descriptor: ImportDescriptor {
                    first_thunk: 0x5000,
                    ..ImportDescriptor::default()
                },
                imports: vec![ImportThunk::Ordinal(1), ImportThunk::Ordinal(2)],
            },
            ImportedDll {
                name: "b.dll".to_string(),
                descriptor: ImportDescriptor {
                    first_thunk: 0x5100,
                    ..ImportDescriptor::default()
                },
                imports: vec![ImportThunk::Ordinal(3)],
            },
        ],
    };
    let mut table = existing.clone();
    // `b.dll` gets a new function, so it needs a new IAT.
    table.dlls[1].imports.push(ImportThunk::Ordinal(4));
    table.add_ordinal_import("c.dll", 5);
    let builder = ImportTableBuilder::new(false, 0x9000).keep_unchanged_iats(&existing);
    let (data, iat_rva, iat_size) = builder.build(&table);
    assert_eq!(data.len(), builder.calculate_size(&table));

    let parsed = ImportTable::parse(0x9000, false, |rva, len| {
        let start = usize::try_from(rva.checked_sub(0x9000)?).ok()?;
        data.get(start..start.checked_add(len)?).map(<[u8]>::to_vec)
    })
    .unwrap();
    let first_thunks: Vec<_> = parsed
        .dlls
        .iter()
        .map(|dll| dll.descriptor.first_thunk)
        .collect();
    assert_eq!(first_thunks[0], 0x5000);
    assert!(first_thunks[1] >= 0x9000 && first_thunks[2] >= 0x9000);
    assert_eq!(parsed.dlls[1].imports, table.dlls[1].imports);
    // The IAT range goes from the kept IAT to the end of the new IATs. The new IATs have 3 + 2
    // entries, with the terminators.
    assert_eq!(iat_rva, 0x5000);
    assert_eq!(iat_rva + iat_size, first_thunks[1] + 5 * 4);

    // A builder without the existing table writes a new IAT for each DLL.
    let (data, iat_rva, iat_size) = ImportTableBuilder::new(false, 0x9000).build(&existing);
    let descriptor = ImportDescriptor::parse(&data).unwrap();
    assert!(descriptor.first_thunk >= 0x9000);
    assert_eq!((iat_rva, iat_size), (descriptor.first_thunk, 5 * 4));

    // A kept IAT must not overlap the built data.
    let builder = ImportTableBuilder::new(false, 0x4FF0).keep_unchanged_iats(&existing);
    assert!(builder.try_build(&existing).is_err());
}
