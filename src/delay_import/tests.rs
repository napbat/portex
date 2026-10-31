use super::*;

#[test]
fn test_delay_load_descriptor_size() {
    assert_eq!(DelayLoadDescriptor::SIZE, 32);
}

#[test]
fn test_null_terminator() {
    let data = [0u8; 32];
    let desc = DelayLoadDescriptor::parse(&data).unwrap();
    assert!(desc.is_null());
}

#[test]
fn test_buffer_too_small() {
    let data = [0u8; 31];
    assert!(DelayLoadDescriptor::parse(&data).is_err());
}

#[test]
fn test_builder_empty() {
    let builder = DelayImportBuilder::new(false, 0x1000);
    let (data, size) = builder.build(&[]);
    assert_eq!(data, Vec::<u8>::new());
    assert_eq!(size, 0);
}

#[test]
fn test_builder_calculates_size() {
    let builder = DelayImportBuilder::new(false, 0x1000);
    let dlls = vec![DelayLoadedDll {
        descriptor: DelayLoadDescriptor {
            attributes: 1,
            dll_name_rva: 0,
            module_handle_rva: 0,
            import_address_table_rva: 0,
            import_name_table_rva: 0,
            bound_import_address_table_rva: 0,
            unload_information_table_rva: 0,
            time_date_stamp: 0,
        },
        name: "test.dll".to_string(),
        imports: vec![ImportThunk::Name {
            hint: 0,
            name: "TestFunc".to_string(),
        }],
    }];
    let size = builder.calculate_size(&dlls);
    assert!(size > 0);
}

#[test]
fn test_builder_roundtrip_both_widths() {
    let dlls = vec![DelayLoadedDll {
        descriptor: DelayLoadDescriptor {
            attributes: 1,
            dll_name_rva: 0,
            module_handle_rva: 0,
            import_address_table_rva: 0,
            import_name_table_rva: 0,
            bound_import_address_table_rva: 0,
            unload_information_table_rva: 0,
            time_date_stamp: 0,
        },
        name: "test.dll".to_string(),
        imports: vec![
            ImportThunk::Name {
                hint: 3,
                name: "TestFunc".to_string(),
            },
            ImportThunk::Ordinal(42),
        ],
    }];
    for is_64bit in [false, true] {
        let base_rva = 0x4000u32;
        let (data, size) = DelayImportBuilder::new(is_64bit, base_rva).build(&dlls);
        assert_eq!(usize::try_from(size).unwrap(), data.len());
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
            let end = offset.checked_add(len)?.min(data.len());
            data.get(offset..end).map(<[u8]>::to_vec)
        };
        let parsed = DelayImportDirectory::parse(base_rva, is_64bit, read_fn).unwrap();
        assert_eq!(parsed.dlls.len(), 1);
        assert_eq!(parsed.dlls[0].name, "test.dll");
        assert_eq!(parsed.dlls[0].imports, dlls[0].imports);
    }
}

#[test]
fn test_builder_pe32_layout() {
    let dlls = vec![DelayLoadedDll {
        descriptor: DelayLoadDescriptor::parse(&[1; 32]).unwrap(),
        name: "test.dll".to_string(),
        imports: vec![
            ImportThunk::Name {
                hint: 3,
                name: "TestFunc".to_string(),
            },
            ImportThunk::Ordinal(42),
        ],
    }];
    let (data, size) = DelayImportBuilder::new(false, 0x4000).build(&dlls);
    // Descriptors 0..64, IAT 64..76, INT 76..88, handle 88..92,
    // hint/name 92..104, DLL name 104..113.
    assert_eq!((data.len(), size), (113, 113));
    let descriptor = DelayLoadDescriptor::parse(&data).unwrap();
    assert_eq!(
        descriptor,
        DelayLoadDescriptor {
            attributes: 1,
            dll_name_rva: 0x4068,
            module_handle_rva: 0x4058,
            import_address_table_rva: 0x4040,
            import_name_table_rva: 0x404C,
            bound_import_address_table_rva: 0,
            unload_information_table_rva: 0,
            time_date_stamp: 0,
        }
    );
    assert_eq!(descriptor.to_array().as_slice(), &data[..32]);
    assert!(data[32..64].iter().all(|&byte| byte == 0));
    let thunks: Vec<u8> = [0x405Cu32, 0x8000_002A, 0]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(&data[64..76], thunks.as_slice());
    assert_eq!(&data[76..88], thunks.as_slice());
    assert_eq!(&data[88..92], &[0; 4]);
    assert_eq!(&data[92..104], b"\x03\x00TestFunc\0\0");
    assert_eq!(&data[104..], b"test.dll\0");
}

/// Return a reader for an image in which each RVA is the offset in `data`.
fn flat_reader(data: &[u8]) -> impl Fn(u32, usize) -> Option<Vec<u8>> + '_ {
    move |rva, len| {
        let start = usize::try_from(rva).ok()?;
        data.get(start..start.checked_add(len)?).map(<[u8]>::to_vec)
    }
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Make an image with one delay-load descriptor at offset 0. Each address in the image is
/// `base` plus the offset: use 0 for RVAs, or the image base for a legacy descriptor.
/// The DLL name is at 0x100, the IAT at 0x200 and the INT at 0x300, with one PE32 entry
/// `entry`. A hint/name entry with `name` is at 0x400.
fn delay_image(attributes: u32, base: u32, entry: u32, name: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x400 + 2 + name.len() + 1];
    put32(&mut data, 0, attributes);
    put32(&mut data, 4, base + 0x100);
    put32(&mut data, 12, base + 0x200);
    put32(&mut data, 16, base + 0x300);
    data[0x100..0x106].copy_from_slice(b"a.dll\0");
    put32(&mut data, 0x300, entry);
    data[0x402..0x402 + name.len()].copy_from_slice(name);
    data
}

#[test]
fn delay_import_names_can_have_more_than_255_bytes() {
    // Before the fix, the limit was 256 bytes, and C++ decorated names failed the parse.
    let name = [b'?'; 300];
    let data = delay_image(1, 0, 0x400, &name);
    let directory = DelayImportDirectory::parse(0, false, flat_reader(&data)).unwrap();
    assert_eq!(
        directory.dlls[0].imports,
        [ImportThunk::Name {
            hint: 0,
            name: "?".repeat(300),
        }]
    );
}

#[test]
fn legacy_delay_import_name_entries_are_vas() {
    // In a legacy (version 1) descriptor, the INT entries are VAs. Before the fix, the parser
    // read them as RVAs and failed with an invalid RVA.
    let image_base = 0x40_0000;
    let data = delay_image(0, image_base, image_base + 0x400, b"Func");
    let directory = DelayImportDirectory::parse_with_image_base(
        0,
        u64::from(image_base),
        false,
        flat_reader(&data),
    )
    .unwrap();
    let dll = &directory.dlls[0];
    assert_eq!(dll.name, "a.dll");
    assert_eq!(dll.descriptor.import_name_table_rva, 0x300);
    assert_eq!(
        dll.imports,
        [ImportThunk::Name {
            hint: 0,
            name: "Func".to_string(),
        }]
    );

    // A VA below the image base is not in the image.
    let data = delay_image(0, image_base, 0x400, b"Func");
    assert!(
        DelayImportDirectory::parse_with_image_base(
            0,
            u64::from(image_base),
            false,
            flat_reader(&data)
        )
        .is_err()
    );
}

#[test]
fn delay_ordinal_thunks_ignore_the_reserved_bits() {
    // Before the fix, the parse failed with "nonzero reserved bits".
    let data = delay_image(1, 0, 0x8001_0009, b"");
    let directory = DelayImportDirectory::parse(0, false, flat_reader(&data)).unwrap();
    assert_eq!(directory.dlls[0].imports, [ImportThunk::Ordinal(9)]);
}

#[test]
fn shared_delay_import_names_are_limited_by_the_name_budget() {
    // 300 INT entries point at one 4000-byte name. Before the fix, each entry made a new copy
    // of the name without a limit.
    let name = [b'A'; 4000];
    let mut data = delay_image(1, 0, 0x400, &name);
    data.resize(0x400 + 2 + name.len() + 1 + 0x500, 0);
    let int = data.len() - 0x4F0;
    put32(&mut data, 16, u32::try_from(int).unwrap());
    for index in 0..300 {
        put32(&mut data, int + index * 4, 0x400);
    }
    let error = DelayImportDirectory::parse(0, false, flat_reader(&data)).unwrap_err();
    assert!(error.to_string().contains("names repeat"), "{error}");
}

fn kept_test_dll(imports: Vec<ImportThunk>) -> DelayLoadedDll {
    DelayLoadedDll {
        descriptor: DelayLoadDescriptor {
            attributes: 1,
            dll_name_rva: 0x5000,
            module_handle_rva: 0x6000,
            import_address_table_rva: 0x5100,
            import_name_table_rva: 0x5200,
            bound_import_address_table_rva: 0x5300,
            unload_information_table_rva: 0x5400,
            time_date_stamp: 0x1234,
        },
        name: "a.dll".to_string(),
        imports,
    }
}

#[test]
fn the_delay_builder_keeps_the_tables_of_each_unchanged_dll() {
    let existing = DelayImportDirectory {
        dlls: vec![kept_test_dll(vec![ImportThunk::Ordinal(1)])],
    };
    let builder = DelayImportBuilder::new(false, 0x9000).keep_unchanged(&existing);
    let (data, size) = builder.build(&existing.dlls);
    assert_eq!(usize::try_from(size).unwrap(), data.len());
    let descriptor = DelayLoadDescriptor::parse(&data).unwrap();
    // Before the fix, the builder wrote a new IAT and module handle, and zeroed the bound IAT,
    // the unload IAT and the time stamp.
    assert_eq!(
        descriptor,
        DelayLoadDescriptor {
            dll_name_rva: descriptor.dll_name_rva,
            import_name_table_rva: descriptor.import_name_table_rva,
            ..existing.dlls[0].descriptor
        }
    );
    assert!(descriptor.dll_name_rva >= 0x9000 && descriptor.import_name_table_rva >= 0x9000);
    // No new IAT and no new module handle: descriptors, INT (2 entries) and the DLL name.
    assert_eq!(data.len(), 64 + 8 + 6);

    // A changed function list gets new tables.
    let changed = [kept_test_dll(vec![ImportThunk::Ordinal(2)])];
    let (data, _) = builder.build(&changed);
    let descriptor = DelayLoadDescriptor::parse(&data).unwrap();
    assert!(descriptor.import_address_table_rva >= 0x9000);
    assert!(descriptor.module_handle_rva >= 0x9000);
    assert_eq!(descriptor.time_date_stamp, 0);

    // A kept IAT must not overlap the built data.
    let builder = DelayImportBuilder::new(false, 0x50F0).keep_unchanged(&existing);
    assert!(builder.try_build(&existing.dlls).is_err());
}
