//! Regression tests for the resource directory parser and builder.

use portex::ErrorKind;
use portex::headers::DataDirectoryType;
use portex::image::{PeBuilder, PeImage};
use portex::resource::{
    ResourceBuilder, ResourceDataEntry, ResourceDirectory, ResourceDirectoryEntry,
    ResourceDirectoryHeader, ResourceEntry, ResourceId, ResourceType,
};
use portex::section::characteristics;

/// The high bit of a directory entry: a named entry or a subdirectory.
const HIGH_BIT: u32 = 0x8000_0000;

fn read_from_blob(blob: &[u8], base_rva: u32, rva: u32, len: usize) -> Option<Vec<u8>> {
    let start = usize::try_from(rva.checked_sub(base_rva)?).ok()?;
    let end = start.checked_add(len)?;
    blob.get(start..end).map(<[u8]>::to_vec)
}

fn blob_size(blob: &[u8]) -> u32 {
    u32::try_from(blob.len()).unwrap()
}

fn push_header(blob: &mut Vec<u8>, named: u16, ids: u16) {
    let header = ResourceDirectoryHeader {
        number_of_named_entries: named,
        number_of_id_entries: ids,
        ..ResourceDirectoryHeader::default()
    };
    blob.extend_from_slice(&header.to_bytes());
}

fn push_entry(blob: &mut Vec<u8>, name_or_id: u32, offset_to_data: u32) {
    let entry = ResourceDirectoryEntry {
        name_or_id,
        offset_to_data,
    };
    blob.extend_from_slice(&entry.to_bytes());
}

fn push_data_entry(blob: &mut Vec<u8>, offset_to_data: u32, size: u32) {
    let entry = ResourceDataEntry {
        offset_to_data,
        size,
        code_page: 0,
        reserved: 0,
    };
    blob.extend_from_slice(&entry.to_bytes());
}

/// Offset of the language directory in the trees from [`numeric_tree`].
const LANGUAGE_DIR: u32 = 0x30;

/// Make the start of a tree with type 10, name 1 and a language directory of `languages`
/// entries. Language `i` points to the data entry that `data_entry(i)` gives. The data
/// entries are not part of the result.
fn numeric_tree(languages: u16, data_entry: impl Fn(u16) -> u32) -> Vec<u8> {
    let mut blob = Vec::new();
    push_header(&mut blob, 0, 1);
    push_entry(&mut blob, 10, HIGH_BIT | 0x18);
    push_header(&mut blob, 0, 1);
    push_entry(&mut blob, 1, HIGH_BIT | LANGUAGE_DIR);
    assert_eq!(blob.len(), LANGUAGE_DIR as usize);
    push_header(&mut blob, 0, languages);
    for language in 0..languages {
        push_entry(&mut blob, u32::from(language), data_entry(language));
    }
    blob
}

/// Return the offset after the language entries of a tree from [`numeric_tree`].
fn after_languages(languages: u16) -> u32 {
    LANGUAGE_DIR + 16 + 8 * u32::from(languages)
}

/// Build an image with one `.rsrc` section. `make_blob(rva)` gives the section data for the
/// section RVA `rva`. The resource directory covers the full blob.
fn image_with_resources(make_blob: impl Fn(u32) -> Vec<u8>) -> (PeImage, u32) {
    let section = |data| {
        PeBuilder::new()
            .add_section(
                ".rsrc",
                data,
                characteristics::INITIALIZED_DATA | characteristics::READ,
            )
            .try_build()
            .unwrap()
    };
    let rva = section(vec![0; 0x200])
        .section_by_name(".rsrc")
        .unwrap()
        .header
        .virtual_address;
    let blob = make_blob(rva);
    let size = blob_size(&blob);
    let mut pe = section(blob);
    assert_eq!(
        pe.section_by_name(".rsrc").unwrap().header.virtual_address,
        rva
    );
    pe.set_data_directory(DataDirectoryType::Resource, rva, size);
    (pe, rva)
}

#[test]
fn shared_payload_has_a_total_budget() {
    const LANGUAGES: u16 = 300;
    const PAYLOAD: u32 = 0x1_0000;
    let base = 0x4000;
    let mut blob = numeric_tree(LANGUAGES, |_| after_languages(LANGUAGES));
    // All languages share one data entry. Its payload is the full 64-KiB blob.
    push_data_entry(&mut blob, base, PAYLOAD);
    blob.resize(PAYLOAD as usize, 0xab);
    let read = |rva, len| read_from_blob(&blob, base, rva, len);

    let directory = ResourceDirectory::parse(base, blob_size(&blob), read).unwrap();
    assert_eq!(directory.len(), usize::from(LANGUAGES));

    let error = ResourceDirectory::parse_with_data(base, blob_size(&blob), read).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidDataDirectory(_)));
    let mut partial = directory.clone();
    assert!(matches!(
        partial.try_load_data(read).unwrap_err().kind(),
        ErrorKind::InvalidDataDirectory(_)
    ));

    // The lenient loader stops at the budget.
    let mut lenient = directory;
    lenient.load_data(read);
    let loaded = lenient.resources.iter().filter(|r| r.has_data()).count();
    assert!(loaded > 0);
    assert!(loaded * (PAYLOAD as usize) <= 2 * 0x10_0000 + PAYLOAD as usize);
}

#[test]
fn shared_payload_inside_the_budget_loads() {
    let base = 0x4000;
    let mut blob = numeric_tree(2, |_| after_languages(2));
    let payload = after_languages(2) + 16;
    push_data_entry(&mut blob, base + payload, 4);
    blob.extend_from_slice(&[1, 2, 3, 4]);
    let read = |rva, len| read_from_blob(&blob, base, rva, len);

    let directory = ResourceDirectory::parse_with_data(base, blob_size(&blob), read).unwrap();
    assert_eq!(directory.len(), 2);
    for resource in &directory.resources {
        assert_eq!(resource.data.as_deref(), Some(&[1, 2, 3, 4][..]));
    }
}

#[test]
fn image_payload_budget_counts_zero_fill() {
    const LANGUAGES: u16 = 48;
    const PAYLOAD: u32 = 0x10_0000;
    let (mut pe, rva) = image_with_resources(|rva| {
        let first_data_entry = after_languages(LANGUAGES);
        let mut blob = numeric_tree(LANGUAGES, |language| {
            first_data_entry + 16 * u32::from(language)
        });
        // Each language has its own 1-MiB payload in the zero-filled tail of the section.
        for language in 0..u32::from(LANGUAGES) {
            push_data_entry(&mut blob, rva + 0x1000 + language * PAYLOAD, PAYLOAD);
        }
        // Fill the raw data up to the file alignment, so that the raw tail is known.
        blob.resize(blob.len().next_multiple_of(0x200), 0);
        blob
    });
    let virtual_size = 0x1000 + u32::from(LANGUAGES) * PAYLOAD;
    pe.section_by_name_mut(".rsrc").unwrap().header.virtual_size = virtual_size;
    pe.try_update_layout().unwrap();
    assert_eq!(
        pe.section_by_name(".rsrc").unwrap().header.virtual_size,
        virtual_size
    );
    // Each payload is in the image.
    let resources = pe.resources().unwrap();
    assert_eq!(resources.len(), usize::from(LANGUAGES));
    let last = resources.resources.last().unwrap();
    assert_eq!(
        pe.read_resource_data(last).map(|data| data.len()),
        Some(PAYLOAD as usize)
    );
    assert!(rva + virtual_size > last.data_rva);

    let error = pe.resources_with_data().unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidDataDirectory(_)));
}

#[test]
fn name_clones_have_a_total_budget() {
    const LANGUAGES: u16 = 300;
    const UNITS: u16 = 30_000;
    let base = 0x4000;
    let string_offset = after_languages(LANGUAGES) + 16;
    // The type and the name are the same long string.
    let mut blob = Vec::new();
    push_header(&mut blob, 1, 0);
    push_entry(&mut blob, HIGH_BIT | string_offset, HIGH_BIT | 0x18);
    push_header(&mut blob, 1, 0);
    push_entry(&mut blob, HIGH_BIT | string_offset, HIGH_BIT | LANGUAGE_DIR);
    push_header(&mut blob, 0, LANGUAGES);
    for language in 0..LANGUAGES {
        push_entry(&mut blob, u32::from(language), after_languages(LANGUAGES));
    }
    push_data_entry(&mut blob, base, 0);
    blob.extend_from_slice(&UNITS.to_le_bytes());
    for _ in 0..UNITS {
        blob.extend_from_slice(&u16::from(b'A').to_le_bytes());
    }
    let read = |rva, len| read_from_blob(&blob, base, rva, len);

    let error = ResourceDirectory::parse(base, blob_size(&blob), read).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidDataDirectory(_)));
}

#[test]
fn duplicate_sibling_entries_are_rejected() {
    let base = 0x4000;
    // Two language entries in one language directory have the same language.
    let mut blob = numeric_tree(2, |_| after_languages(2));
    let language_entry = LANGUAGE_DIR as usize + 16 + 8;
    blob[language_entry..language_entry + 4].copy_from_slice(&0u32.to_le_bytes());
    push_data_entry(&mut blob, base, 0);
    let read = |rva, len| read_from_blob(&blob, base, rva, len);
    assert!(ResourceDirectory::parse(base, blob_size(&blob), read).is_err());

    // Two type entries have the same type and point to the same name directory.
    let mut blob = Vec::new();
    push_header(&mut blob, 0, 2);
    push_entry(&mut blob, 10, HIGH_BIT | 0x20);
    push_entry(&mut blob, 10, HIGH_BIT | 0x20);
    push_header(&mut blob, 0, 1);
    push_entry(&mut blob, 1, HIGH_BIT | 0x38);
    push_header(&mut blob, 0, 1);
    push_entry(&mut blob, 0x0409, 0x50);
    push_data_entry(&mut blob, base, 0);
    let read = |rva, len| read_from_blob(&blob, base, rva, len);
    assert!(ResourceDirectory::parse(base, blob_size(&blob), read).is_err());
}

/// Build `builder` at `base` and parse the result with the payloads.
fn round_trip(builder: &ResourceBuilder, base: u32) -> ResourceDirectory {
    let (data, size) = builder.try_build(base).unwrap();
    ResourceDirectory::parse_with_data(base, size, |rva, len| read_from_blob(&data, base, rva, len))
        .unwrap()
}

fn named(text: &str) -> ResourceId {
    ResourceId::Name(text.into())
}

fn named_entry(type_id: ResourceId, name: &str, language: u16) -> ResourceEntry {
    ResourceEntry {
        type_id,
        name: named(name),
        language,
        code_page: 0,
        data: vec![1],
    }
}

#[test]
fn builder_stores_names_in_uppercase() {
    let mut builder = ResourceBuilder::new();
    builder
        .add(named_entry(named("myType"), "b", 0))
        .add(named_entry(named("myType"), "A", 0))
        .add(named_entry(ResourceId::Id(10), "straße", 0))
        .add(named_entry(ResourceId::Id(10), "\u{10428}x", 0));
    let directory = round_trip(&builder, 0x3000);
    let names: Vec<_> = directory
        .resources
        .iter()
        .map(|resource| (resource.type_id.clone(), resource.name.clone()))
        .collect();
    // The builder uses the simple uppercase mapping of each UTF-16 unit, as Windows does.
    // `ß` has no simple uppercase form. A character outside the BMP keeps its case.
    assert_eq!(
        names,
        vec![
            (named("MYTYPE"), named("A")),
            (named("MYTYPE"), named("B")),
            (ResourceId::Id(10), named("STRAßE")),
            (ResourceId::Id(10), named("\u{10428}X")),
        ]
    );
}

#[test]
fn builder_sorts_names_by_utf16_units() {
    let mut builder = ResourceBuilder::new();
    builder
        .add(named_entry(ResourceId::Id(10), "\u{FFFD}", 0))
        .add(named_entry(ResourceId::Id(10), "\u{10000}", 0))
        .add(named_entry(ResourceId::Id(10), "AB", 0))
        .add(named_entry(ResourceId::Id(10), "A", 0));
    let directory = round_trip(&builder, 0x3000);
    let names: Vec<_> = directory
        .resources
        .iter()
        .map(|resource| resource.name.clone())
        .collect();
    // U+10000 is the surrogate pair D800 DC00, which comes before FFFD.
    assert_eq!(
        names,
        vec![
            named("A"),
            named("AB"),
            named("\u{10000}"),
            named("\u{FFFD}")
        ]
    );
}

#[test]
fn builder_rejects_names_that_differ_only_in_case() {
    let mut builder = ResourceBuilder::new();
    builder
        .add(named_entry(ResourceId::Id(10), "abc", 0x0409))
        .add(named_entry(ResourceId::Id(10), "ABC", 0x0409));
    assert!(builder.try_calculate_size().is_err());
    assert!(builder.try_build(0x3000).is_err());

    let mut builder = ResourceBuilder::new();
    builder
        .add(named_entry(named("type"), "A", 0))
        .add(named_entry(named("TYPE"), "A", 0));
    assert!(builder.try_build(0x3000).is_err());
}

#[test]
fn zero_size_resources_round_trip() {
    let mut builder = ResourceBuilder::new();
    builder
        .add_resource(ResourceType::RcData, 1, 0, Vec::new())
        .add_resource(ResourceType::RcData, 2, 0, vec![1, 2, 3]);
    let directory = round_trip(&builder, 0x3000);
    assert_eq!(directory.resources[0].data, Some(Vec::new()));
    assert_eq!(directory.resources[1].data, Some(vec![1, 2, 3]));
    assert!(ResourceBuilder::from_directory(&directory).is_some());

    // A zero-size resource needs no read.
    let (data, size) = builder.try_build(0x3000).unwrap();
    let mut lenient = ResourceDirectory::parse(0x3000, size, |rva, len| {
        read_from_blob(&data, 0x3000, rva, len)
    })
    .unwrap();
    lenient.load_data(|_, _| None);
    assert_eq!(lenient.resources[0].data, Some(Vec::new()));
    assert_eq!(lenient.resources[1].data, None);
    let mut strict = lenient.clone();
    strict.resources.truncate(1);
    strict.resources[0].data = None;
    strict.try_load_data(|_, _| None).unwrap();
    assert_eq!(strict.resources[0].data, Some(Vec::new()));

    let (mut pe, _) = image_with_resources(|_| vec![0; 0x200]);
    pe.update_resources_from_builder(&builder, None).unwrap();
    let parsed = pe.resources_with_data().unwrap();
    pe.update_resources(&parsed, None).unwrap();
    pe.rebuild_supported_directories(None).unwrap();
    let rebuilt = pe.resources_with_data().unwrap();
    assert_eq!(rebuilt.resources[0].data, Some(Vec::new()));
    assert_eq!(rebuilt.resources[1].data, Some(vec![1, 2, 3]));
}

#[test]
fn root_directory_header_survives_a_rebuild() {
    let mut builder = ResourceBuilder::new();
    builder.add_resource(ResourceType::RcData, 1, 0, vec![1, 2, 3]);
    let base = 0x3000;
    let (mut data, size) = builder.try_build(base).unwrap();
    // Characteristics, TimeDateStamp, MajorVersion and MinorVersion of the root.
    let fields = [1, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 4, 0, 2, 0];
    data[..12].copy_from_slice(&fields);

    let directory = ResourceDirectory::parse_with_data(base, size, |rva, len| {
        read_from_blob(&data, base, rva, len)
    })
    .unwrap();
    let rebuilt = ResourceBuilder::from_directory(&directory).unwrap();
    let (bytes, _) = rebuilt.try_build(base).unwrap();
    assert_eq!(bytes[..12], fields);
    // The builder calculates the counts.
    assert_eq!(bytes[12..16], [0, 0, 1, 0]);
}

#[test]
fn builder_root_header_fields() {
    let mut builder = ResourceBuilder::new();
    builder
        .set_root_header(ResourceDirectoryHeader {
            characteristics: 1,
            time_date_stamp: 0x1234_5678,
            major_version: 4,
            minor_version: 2,
            number_of_named_entries: 9,
            number_of_id_entries: 9,
        })
        .add_resource(ResourceType::Toolbar, 1, 0, vec![1]);
    // The builder ignores the counts.
    assert_eq!(builder.root_header().number_of_id_entries, 0);
    let directory = round_trip(&builder, 0x3000);
    assert_eq!(
        directory.root_header,
        ResourceDirectoryHeader {
            characteristics: 1,
            time_date_stamp: 0x1234_5678,
            major_version: 4,
            minor_version: 2,
            number_of_named_entries: 0,
            number_of_id_entries: 1,
        }
    );
    assert_eq!(
        directory.resources[0].get_type(),
        Some(ResourceType::Toolbar)
    );
}

#[test]
fn resource_types_include_the_mfc_and_obsolete_types() {
    for (value, resource_type, name) in [
        (15, ResourceType::NameTable, "NAMETABLE"),
        (240, ResourceType::DlgInit, "DLGINIT"),
        (241, ResourceType::Toolbar, "TOOLBAR"),
        (24, ResourceType::Manifest, "MANIFEST"),
    ] {
        assert_eq!(ResourceType::from_u16(value), Some(resource_type));
        assert_eq!(resource_type.as_u16(), value);
        assert_eq!(resource_type.name(), name);
    }
    assert_eq!(ResourceType::from_u16(13), None);
}
