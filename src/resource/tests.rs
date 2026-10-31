use super::*;

#[test]
fn test_resource_directory_header_size() {
    assert_eq!(ResourceDirectoryHeader::SIZE, 16);
}

#[test]
fn test_resource_directory_entry_size() {
    assert_eq!(ResourceDirectoryEntry::SIZE, 8);
}

#[test]
fn test_resource_data_entry_size() {
    assert_eq!(ResourceDataEntry::SIZE, 16);
}

#[test]
fn test_resource_directory_header_roundtrip() {
    let original = ResourceDirectoryHeader {
        characteristics: 0,
        time_date_stamp: 0x1234_5678,
        major_version: 1,
        minor_version: 0,
        number_of_named_entries: 2,
        number_of_id_entries: 5,
    };

    let bytes = original.to_bytes();
    let parsed = ResourceDirectoryHeader::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
    assert_eq!(parsed.total_entries(), 7);
}

#[test]
fn test_resource_entry_flags() {
    // Test a directory entry that has a name.
    let entry = ResourceDirectoryEntry {
        name_or_id: 0x8000_1000,     // The high bit is set: the entry is named.
        offset_to_data: 0x8000_2000, // The high bit is set: the entry is a directory.
    };
    assert!(entry.is_named());
    assert!(entry.is_directory());
    assert_eq!(entry.name_offset(), 0x1000);
    assert_eq!(entry.data_offset(), 0x2000);

    // Test an ID entry that points to data.
    let entry2 = ResourceDirectoryEntry {
        name_or_id: 16, // RT_VERSION
        offset_to_data: 0x3000,
    };
    assert!(!entry2.is_named());
    assert!(!entry2.is_directory());
    assert_eq!(entry2.id(), 16);
}

#[test]
fn test_resource_type_names() {
    assert_eq!(ResourceType::Manifest.name(), "MANIFEST");
    assert_eq!(ResourceType::Version.name(), "VERSION");
    assert_eq!(ResourceType::Icon.name(), "ICON");
}

#[test]
fn test_resource_builder_single_resource() {
    let mut builder = ResourceBuilder::new();
    builder.add_manifest(b"<xml>test</xml>".to_vec());

    let (data, size) = builder.build(0x3000);
    assert!(size > 0);
    assert_eq!(data.len(), size as usize);

    // Make sure that the parser can read the built data.
    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let offset = (rva - 0x3000) as usize;
        if offset + len <= data.len() {
            Some(data[offset..offset + len].to_vec())
        } else {
            None
        }
    };

    let parsed = ResourceDirectory::parse(0x3000, size, read_fn).unwrap();
    assert_eq!(parsed.len(), 1);
    assert!(parsed.manifest().is_some());
}

#[test]
fn test_resource_builder_multiple_resources() {
    let mut builder = ResourceBuilder::new();
    builder
        .add_manifest(b"manifest data".to_vec())
        .add_version_info(b"version data".to_vec())
        .add_resource(ResourceType::RcData, 100, 0x0409, b"custom data".to_vec());

    let (data, size) = builder.build(0x4000);
    assert!(size > 0);

    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let offset = (rva - 0x4000) as usize;
        if offset + len <= data.len() {
            Some(data[offset..offset + len].to_vec())
        } else {
            None
        }
    };

    let parsed = ResourceDirectory::parse(0x4000, size, read_fn).unwrap();
    assert_eq!(parsed.len(), 3);
    assert!(parsed.manifest().is_some());
    assert!(parsed.version_info().is_some());
}

#[test]
fn test_resource_builder_named_round_trip() {
    let named = |text: &str| ResourceId::Name(text.into());
    let mut builder = ResourceBuilder::new();
    builder
        .add(ResourceEntry {
            type_id: named("MYTYPE"),
            name: named("FIRST"),
            language: 0x0409,
            code_page: 1252,
            data: vec![1, 2, 3],
        })
        .add(ResourceEntry {
            type_id: named("MYTYPE"),
            name: ResourceId::Id(7),
            language: 0x0407,
            code_page: 0,
            data: vec![4; 9],
        })
        .add(ResourceEntry {
            type_id: ResourceId::Id(10),
            name: named("Ünïcode"),
            language: 0x0409,
            code_page: 0,
            data: vec![5; 16],
        })
        .add(ResourceEntry::new(10, 1, 0x0409, vec![6]))
        .add(ResourceEntry::new(10, 1, 0x0407, vec![7, 8]));

    let base_rva = 0x5000;
    let (data, size) = builder.try_build(base_rva).unwrap();
    assert_eq!(data.len(), usize::try_from(size).unwrap());
    assert_eq!(data.len(), builder.try_calculate_size().unwrap());

    let read_at_rva = |rva: u32, len: usize| {
        let start = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
        data.get(start..start.checked_add(len)?).map(<[u8]>::to_vec)
    };
    let directory = ResourceDirectory::parse_with_data(base_rva, size, read_at_rva).unwrap();

    // Named entries come first in each directory. Languages are sorted. The builder stores
    // names in uppercase.
    let summary: Vec<_> = directory
        .resources
        .iter()
        .map(|resource| {
            (
                resource.type_id.clone(),
                resource.name.clone(),
                resource.language,
                resource.code_page,
                resource.data.clone().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (named("MYTYPE"), named("FIRST"), 0x0409, 1252, vec![1, 2, 3]),
            (named("MYTYPE"), ResourceId::Id(7), 0x0407, 0, vec![4; 9]),
            (ResourceId::Id(10), named("ÜNÏCODE"), 0x0409, 0, vec![5; 16]),
            (ResourceId::Id(10), ResourceId::Id(1), 0x0407, 0, vec![7, 8]),
            (ResourceId::Id(10), ResourceId::Id(1), 0x0409, 0, vec![6]),
        ]
    );
    // Each payload starts on an 8-byte boundary.
    assert!(
        directory
            .resources
            .iter()
            .all(|resource| resource.data_rva % 8 == 0)
    );
}
