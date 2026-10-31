use super::*;

/// Return a reader over `data` that starts at the RVA `base_rva`.
fn reader(data: &[u8], base_rva: u32) -> impl Fn(u32, usize) -> Option<Vec<u8>> + '_ {
    move |rva: u32, len: usize| {
        let offset = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
        let rest = data.get(offset..)?;
        if rest.is_empty() {
            return None;
        }
        Some(rest.get(..len.min(rest.len()))?.to_vec())
    }
}

#[test]
fn test_export_directory_size() {
    assert_eq!(ExportDirectory::SIZE, 40);
}

#[test]
fn test_export_directory_roundtrip() {
    let original = ExportDirectory {
        characteristics: 0,
        time_date_stamp: 0x1234_5678,
        major_version: 1,
        minor_version: 0,
        name_rva: 0x1000,
        base: 1,
        number_of_functions: 10,
        number_of_names: 8,
        address_of_functions: 0x2000,
        address_of_names: 0x3000,
        address_of_name_ordinals: 0x4000,
    };

    let bytes = original.to_bytes();
    let parsed = ExportDirectory::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_export_table_builder_roundtrip() {
    // Create an export table.
    let mut table = ExportTable::default();
    table.set_dll_name("test.dll");
    table.set_base(1);
    table.add_export(Some("FunctionA"), 0x1000);
    table.add_export(Some("FunctionB"), 0x2000);
    table.add_export(None, 0x3000); // Export by ordinal only.

    assert_eq!(table.exports.len(), 3);
    assert_eq!(table.dll_name, "test.dll");

    // Build the export data.
    let base_rva = 0x4000u32;
    let builder = ExportTableBuilder::new(base_rva);
    let size = ExportTableBuilder::calculate_size(&table);
    assert!(size > 0);

    let (data, export_size) = builder.build(&table);
    assert_eq!(data.len(), size);
    assert!(export_size > 0);

    // Parse the built data again.
    let parsed = ExportTable::parse(base_rva, export_size, reader(&data, base_rva)).unwrap();
    assert_eq!(parsed.dll_name, "test.dll");
    assert_eq!(parsed.exports.len(), 3);

    // Check the named exports.
    let func_a = parsed.find_by_name("FunctionA");
    assert!(func_a.is_some());
    if let ExportAddress::Rva(rva) = &func_a.unwrap().address {
        assert_eq!(*rva, 0x1000);
    } else {
        panic!("Expected RVA export");
    }

    let func_b = parsed.find_by_name("FunctionB");
    assert!(func_b.is_some());
}

#[test]
fn try_add_export_rejects_ordinal_overflow() {
    let mut table = ExportTable::default();
    table.set_base(u32::MAX);
    table.try_add_export(Some("Last"), 0x1000).unwrap();
    assert_eq!(table.exports[0].ordinal, u32::MAX);

    let err = table.try_add_export(Some("Next"), 0x2000).unwrap_err();
    assert!(matches!(
        err.kind(),
        crate::ErrorKind::InvalidDataDirectory(_)
    ));
    let err = table.try_add_forwarder(None, "OTHER.Func").unwrap_err();
    assert!(matches!(
        err.kind(),
        crate::ErrorKind::InvalidDataDirectory(_)
    ));
    assert_eq!(table.exports.len(), 1);
}

#[test]
fn try_build_accepts_unnamed_export_above_u16_index() {
    let high_ordinal = 1 + 70_000;
    let table = ExportTable {
        directory: ExportDirectory {
            base: 1,
            ..ExportDirectory::default()
        },
        dll_name: "sparse.dll".to_string(),
        exports: vec![
            ExportedFunction {
                ordinal: 1,
                name: Some("First".to_string()),
                aliases: Vec::new(),
                address: ExportAddress::Rva(0x1000),
            },
            ExportedFunction {
                ordinal: high_ordinal,
                name: None,
                aliases: Vec::new(),
                address: ExportAddress::Rva(0x2000),
            },
        ],
    };

    let base_rva = 0x10_0000u32;
    let (data, export_size) = ExportTableBuilder::new(base_rva).try_build(&table).unwrap();
    let parsed = ExportTable::parse(base_rva, export_size, reader(&data, base_rva)).unwrap();
    assert_eq!(parsed.exports.len(), 2);
    assert_eq!(
        parsed.find_by_ordinal(high_ordinal).map(|e| &e.address),
        Some(&ExportAddress::Rva(0x2000))
    );
    assert_eq!(parsed.find_by_name("First").map(|e| e.ordinal), Some(1));
}

#[test]
fn try_build_writes_forwarders_and_aliases() {
    let mut table = ExportTable::default();
    table.set_dll_name("fwd.dll");
    table.set_base(5);
    table
        .try_add_forwarder(Some("Alloc"), "NTDLL.RtlAllocateHeap")
        .unwrap();
    table.try_add_export(Some("Beta"), 0x3000).unwrap();
    table.exports[1].aliases.push("Alpha".to_string());
    // Three names refer to two functions.

    let base_rva = 0x2000u32;
    let (data, export_size) = ExportTableBuilder::new(base_rva).try_build(&table).unwrap();
    let parsed = ExportTable::parse(base_rva, export_size, reader(&data, base_rva)).unwrap();
    assert_eq!(parsed.dll_name, "fwd.dll");
    assert_eq!(
        parsed.find_by_name("Alloc").map(|e| &e.address),
        Some(&ExportAddress::Forwarder(
            "NTDLL.RtlAllocateHeap".to_string()
        ))
    );
    assert_eq!(parsed.find_by_name("Alpha").map(|e| e.ordinal), Some(6));
    assert_eq!(parsed.find_by_name("Beta").map(|e| e.ordinal), Some(6));
}

/// Build raw export data at `base_rva` with `functions` EAT slots that all hold `0x00F0_0000`.
///
/// That RVA is outside the export data, so no slot is a forwarder.
///
/// Name entry `i` has the name RVA `name_rvas[i]` and the EAT index `ordinals[i]`. `strings`
/// follows the tables, and the function returns the RVA of `strings` and the data.
fn raw_exports(
    base_rva: u32,
    functions: u32,
    name_rvas: impl Fn(u32, u32) -> u32,
    ordinals: impl Fn(u32) -> u16,
    names: u32,
    strings: &[u8],
) -> Vec<u8> {
    let eat = 40 + functions * 4;
    let ords = eat + names * 4;
    let dll = ords + names * 2;
    let strings_rva = base_rva + dll + 2;
    let mut data = vec![0u8; (dll + 2) as usize];
    let dir = ExportDirectory {
        name_rva: base_rva + dll,
        base: 1,
        number_of_functions: functions,
        number_of_names: names,
        address_of_functions: base_rva + 40,
        address_of_names: base_rva + eat,
        address_of_name_ordinals: base_rva + ords,
        ..ExportDirectory::default()
    };
    dir.write(&mut data).unwrap();
    for i in 0..functions {
        let at = (40 + i * 4) as usize;
        data[at..at + 4].copy_from_slice(&0x00F0_0000u32.to_le_bytes());
    }
    for i in 0..names {
        let at = (eat + i * 4) as usize;
        data[at..at + 4].copy_from_slice(&name_rvas(i, strings_rva).to_le_bytes());
        let at = (ords + i * 2) as usize;
        data[at..at + 2].copy_from_slice(&ordinals(i).to_le_bytes());
    }
    data[dll as usize] = b'x';
    data.extend_from_slice(strings);
    data
}

#[test]
fn parse_binds_names_to_sparse_slots_through_the_slot_map() {
    // Names refer to EAT indexes in reverse order, so each name binds to a different export.
    let mut strings = Vec::new();
    for i in 0..4u8 {
        strings.extend_from_slice(&[b'a' + i, 0]);
    }
    let data = raw_exports(
        0x1000,
        4,
        |i, s| s + i * 2,
        |i| 3 - u16::try_from(i).unwrap(),
        4,
        &strings,
    );
    let size = u32::try_from(data.len()).unwrap();
    let table = ExportTable::parse(0x1000, size, reader(&data, 0x1000)).unwrap();
    for (i, export) in table.exports.iter().enumerate() {
        let expected = char::from(b'd' - u8::try_from(i).unwrap()).to_string();
        assert_eq!(export.name.as_deref(), Some(expected.as_str()));
        assert_eq!(export.aliases, Vec::<String>::new());
    }
}

#[test]
fn parse_limits_names_that_share_one_string() {
    // Every name entry points at one 4095-byte string and at the last EAT slot. The aliases
    // need more than 16 MiB, which is much more than the export data. Before the fix, the
    // parser copied the string once for each name without a limit.
    let names = 4200;
    let mut strings = vec![b'A'; 4095];
    strings.push(0);
    let data = raw_exports(
        0x1000,
        names,
        |_, s| s,
        |_| u16::try_from(names - 1).unwrap(),
        names,
        &strings,
    );
    let size = u32::try_from(data.len()).unwrap();
    let err = ExportTable::parse(0x1000, size, reader(&data, 0x1000)).unwrap_err();
    assert!(
        matches!(err.kind(), crate::ErrorKind::InvalidDataDirectory(msg) if msg.contains("name byte limit")),
        "{err:?}"
    );
}

#[test]
fn parse_reads_each_name_rva_once() {
    // 100 names point at one string. Before the fix, the parser read the string 100 times.
    let names = 100;
    let data = raw_exports(
        0x1000,
        names,
        |_, s| s,
        |i| u16::try_from(i).unwrap(),
        names,
        b"a\0",
    );
    let size = u32::try_from(data.len()).unwrap();
    let string_rva = 0x1000 + size - 2;
    let string_reads = core::cell::Cell::new(0u32);
    let inner = reader(&data, 0x1000);
    let table = ExportTable::parse(0x1000, size, |rva, len| {
        if rva == string_rva {
            string_reads.set(string_reads.get() + 1);
        }
        inner(rva, len)
    })
    .unwrap();
    assert_eq!(table.exports.len(), 100);
    assert_eq!(string_reads.get(), 1);
}

#[test]
fn parse_accepts_function_count_below_name_count() {
    // The parse docs used to say that this is an error. Two names are aliases of one slot.
    let data = raw_exports(0x1000, 1, |i, s| s + i * 2, |_| 0, 2, b"a\0b\0");
    let size = u32::try_from(data.len()).unwrap();
    let table = ExportTable::parse(0x1000, size, reader(&data, 0x1000)).unwrap();
    assert_eq!(table.exports[0].name.as_deref(), Some("a"));
    assert_eq!(table.exports[0].aliases, ["b"]);
}

#[test]
fn add_export_uses_the_ordinal_after_the_last_export() {
    // Before the fix, each addition scanned all exports for the highest ordinal. Now it only
    // reads the last export, so this table gets ordinal 3 and not 6.
    let mut table = ExportTable::default();
    table.set_base(1);
    table.exports.push(ExportedFunction {
        ordinal: 5,
        name: None,
        aliases: Vec::new(),
        address: ExportAddress::Rva(0x1000),
    });
    table.exports.push(ExportedFunction {
        ordinal: 2,
        name: None,
        aliases: Vec::new(),
        address: ExportAddress::Rva(0x2000),
    });
    table.add_export(None, 0x3000);
    assert_eq!(table.exports[2].ordinal, 3);
}

fn assert_build_rejects(table: &ExportTable, needle: &str) {
    let err = ExportTableBuilder::new(0x4000)
        .try_build(table)
        .unwrap_err();
    assert!(
        matches!(err.kind(), crate::ErrorKind::InvalidDataDirectory(msg) if msg.contains(needle)),
        "{err:?}"
    );
    assert!(ExportTableBuilder::try_calculate_size(table).is_err());
}

#[test]
fn try_build_rejects_named_rva_zero() {
    let mut table = ExportTable::default();
    table.set_dll_name("x.dll");
    table.add_export(Some("Zero"), 0);
    assert_build_rejects(&table, "RVA 0");
    // An unnamed export with RVA 0 is an empty slot, and stays valid.
    let mut table = ExportTable::default();
    table.set_dll_name("x.dll");
    table.add_export(None, 0);
    ExportTableBuilder::new(0x4000).try_build(&table).unwrap();
}

#[test]
fn try_build_rejects_duplicate_names() {
    let mut table = ExportTable::default();
    table.set_dll_name("x.dll");
    table.add_export(Some("Same"), 0x1000);
    table.add_export(Some("Same"), 0x2000);
    assert_build_rejects(&table, "duplicate export name");

    let mut table = ExportTable::default();
    table.set_dll_name("x.dll");
    table.add_export(Some("Same"), 0x1000);
    table.add_export(Some("Other"), 0x2000);
    table.exports[1].aliases.push("Same".to_string());
    assert_build_rejects(&table, "duplicate export name");
}

#[test]
fn try_build_rejects_empty_names() {
    let mut table = ExportTable::default();
    table.set_dll_name("x.dll");
    table.add_export(Some(""), 0x1000);
    assert_build_rejects(&table, "empty name");
}
