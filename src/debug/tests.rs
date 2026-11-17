use super::*;

fn codeview(path: &[u8]) -> CodeViewRsds {
    CodeViewRsds {
        guid: [5; 16],
        age: 1,
        pdb_path: path.to_vec(),
    }
}

fn entry(debug_type: DebugType, size: usize, rva: u32) -> [u8; DebugDirectory::SIZE] {
    DebugDirectory {
        debug_type: debug_type.as_u32(),
        size_of_data: u32::try_from(size).unwrap(),
        address_of_raw_data: rva,
        ..DebugDirectory::default()
    }
    .to_bytes()
}

/// Return a reader of `bytes`, which start at RVA 0.
fn reader(bytes: &[u8]) -> impl Fn(u32, usize) -> Option<Vec<u8>> + '_ {
    |rva, len| {
        let start = usize::try_from(rva).ok()?;
        bytes
            .get(start..start.checked_add(len)?)
            .map(<[u8]>::to_vec)
    }
}

#[test]
fn test_debug_directory_size() {
    assert_eq!(DebugDirectory::SIZE, 28);
}

#[test]
fn test_debug_directory_roundtrip() {
    let original = DebugDirectory {
        characteristics: 0,
        time_date_stamp: 0x1234_5678,
        major_version: 1,
        minor_version: 0,
        debug_type: DebugType::CodeView.as_u32(),
        size_of_data: 100,
        address_of_raw_data: 0x1000,
        pointer_to_raw_data: 0x400,
    };

    let bytes = original.to_bytes();
    let parsed = DebugDirectory::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn known_debug_types_map_and_unknown_values_do_not() {
    for value in 0..=21 {
        assert_eq!(DebugType::from_u32(value).unwrap().as_u32(), value);
    }
    assert_eq!(DebugType::from_u32(0), Some(DebugType::Unknown));
    assert_eq!(
        DebugType::from_u32(17),
        Some(DebugType::EmbeddedPortablePdb)
    );
    assert_eq!(DebugType::from_u32(19), Some(DebugType::PdbChecksum));
    assert_eq!(DebugType::from_u32(21), Some(DebugType::PerfMap));
    assert_eq!(DebugType::from_u32(22), None);
    let directory = DebugDirectory {
        debug_type: 0x1234,
        ..DebugDirectory::default()
    };
    assert_eq!(directory.get_type(), None);
}

#[test]
fn set_codeview_replaces_the_first_rsds_payload() {
    let first = codeview(b"first.pdb").to_bytes();
    let second = codeview(b"second.pdb").to_bytes();
    let mut info = DebugInfo::default();
    for payload in [&first, &second] {
        info.directories.push(DebugDirectory {
            debug_type: DebugType::CodeView.as_u32(),
            size_of_data: u32::try_from(payload.len()).unwrap(),
            ..DebugDirectory::default()
        });
        info.data.push(Some(payload.clone()));
    }
    assert_eq!(info.pdb_path().as_deref(), Some("first.pdb"));

    info.set_codeview(&codeview(b"changed-name.pdb")).unwrap();
    assert_eq!(info.directories.len(), 2);
    assert_eq!(info.pdb_path().as_deref(), Some("changed-name.pdb"));
    assert_eq!(
        info.directories[0].size_of_data as usize,
        info.data[0].as_ref().unwrap().len()
    );
    assert_eq!(info.data[1].as_ref(), Some(&second));
}

#[test]
fn set_codeview_adds_an_entry_when_no_rsds_record_exists() {
    let mut info = DebugInfo::default();
    info.directories.push(DebugDirectory {
        debug_type: DebugType::Repro.as_u32(),
        ..DebugDirectory::default()
    });
    info.set_codeview(&codeview(b"new.pdb")).unwrap();
    assert_eq!(info.directories.len(), 2);
    assert_eq!(info.data.len(), 2);
    assert_eq!(info.data[0], None);
    assert_eq!(info.codeview().unwrap(), Some(codeview(b"new.pdb")));
}

#[test]
fn a_malformed_codeview_record_fails_only_its_decode() {
    let mut record = codeview(b"a.pdb").to_bytes();
    record.pop();
    let mut bytes = entry(DebugType::CodeView, record.len(), 0x40).to_vec();
    bytes.resize(0x40, 0);
    bytes.extend_from_slice(&record);

    let info = DebugInfo::parse(0, 28, reader(&bytes)).unwrap();
    assert_eq!(info.data[0].as_deref(), Some(record.as_slice()));
    assert!(info.codeview().is_err());
    assert_eq!(info.pdb_path(), None);
}

#[test]
fn file_offset_payloads_share_the_payload_budget() {
    // Each entry has no RVA, so `parse_with_file` reads its payload at the file offset.
    let size = 1 << 20;
    let count = DebugInfo::MAX_PAYLOAD_BYTES / size + 1;
    let mut table = Vec::new();
    for _ in 0..count {
        let mut directory = DebugDirectory::parse(&entry(DebugType::Coff, size, 0)).unwrap();
        directory.pointer_to_raw_data = 0x1000;
        table.extend_from_slice(&directory.to_bytes());
    }
    let file = vec![0x11; 0x1000 + size];
    let table_size = u32::try_from(table.len()).unwrap();

    // The last payload goes past the budget. Its entry stays, without a payload.
    let info = DebugInfo::parse_with_file(0, table_size, reader(&table), reader(&file)).unwrap();
    assert_eq!(info.directories.len(), count);
    assert!(info.data[..count - 1].iter().all(Option::is_some));
    assert_eq!(info.data[count - 1], None);
}

#[test]
fn a_payload_larger_than_the_budget_is_not_read() {
    let size = DebugInfo::MAX_PAYLOAD_BYTES + 1;
    let bytes = entry(DebugType::Coff, size, 0x40).to_vec();
    let read_count = core::cell::Cell::new(0);
    let read = |rva: u32, len: usize| {
        read_count.set(read_count.get() + 1);
        reader(&bytes)(rva, len)
    };

    let info = DebugInfo::parse(0, 28, read).unwrap();
    assert_eq!(info.directories.len(), 1);
    assert_eq!(info.data, [None]);
    // Only the table is read.
    assert_eq!(read_count.get(), 1);
}
