use super::{BoundForwarderRef, BoundImportBuilder, BoundImportDescriptor, BoundImportDirectory};
use crate::prelude::{ToString, Vec, vec};

#[test]
fn test_bound_import_descriptor_size() {
    assert_eq!(BoundImportDescriptor::SIZE, 8);
}

#[test]
fn test_bound_forwarder_ref_size() {
    assert_eq!(BoundForwarderRef::SIZE, 8);
}

#[test]
fn test_null_terminator() {
    let data = [0u8; 8];
    let desc = BoundImportDescriptor::parse(&data).unwrap();
    assert!(desc.is_null());
}

#[test]
fn test_buffer_too_small() {
    let data = [0u8; 7];
    assert!(BoundImportDescriptor::parse(&data).is_err());
}

#[test]
fn test_builder_empty() {
    let dir = BoundImportDirectory::default();
    let (data, size) = BoundImportBuilder::build(&dir);
    assert_eq!(data, Vec::<u8>::new());
    assert_eq!(size, 0);
}

#[test]
fn test_builder_roundtrip() {
    let dir = BoundImportDirectory {
        descriptors: vec![BoundImportDescriptor {
            time_date_stamp: 0x1234_5678,
            offset_module_name: 0,
            number_of_module_forwarder_refs: 0,
            module_name: "kernel32.dll".to_string(),
            forwarder_refs: vec![],
        }],
    };

    let (data, _size) = BoundImportBuilder::build(&dir);

    // Parse it back
    let parsed = BoundImportDirectory::parse(&data).unwrap();
    assert_eq!(parsed.descriptors.len(), 1);
    assert_eq!(parsed.descriptors[0].module_name, "kernel32.dll");
    assert_eq!(parsed.descriptors[0].time_date_stamp, 0x1234_5678);
}

#[test]
fn test_builder_layout_with_forwarders() {
    let descriptor = |time_date_stamp, name: &str, forwarder_refs| BoundImportDescriptor {
        time_date_stamp,
        offset_module_name: 0,
        number_of_module_forwarder_refs: 0,
        module_name: name.to_string(),
        forwarder_refs,
    };
    let forwarder = BoundForwarderRef {
        time_date_stamp: 2,
        offset_module_name: 0,
        reserved: 0,
        module_name: "b.dll".to_string(),
    };
    let dir = BoundImportDirectory {
        descriptors: vec![
            descriptor(1, "a.dll", vec![forwarder]),
            descriptor(3, "c.dll", vec![]),
        ],
    };

    let (data, size) = BoundImportBuilder::try_build(&dir).unwrap();
    // Four 8-byte records (with the terminator), then three 6-byte names.
    assert_eq!(data.len(), 50);
    assert_eq!(size, 50);
    assert_eq!(BoundImportBuilder::try_calculate_size(&dir).unwrap(), 50);
    assert_eq!(data[0..8], [1, 0, 0, 0, 32, 0, 1, 0]);
    assert_eq!(data[8..16], [2, 0, 0, 0, 38, 0, 0, 0]);
    assert_eq!(data[16..24], [3, 0, 0, 0, 44, 0, 0, 0]);
    assert_eq!(data[24..32], [0; 8]);
    assert_eq!(&data[32..], b"a.dll\0b.dll\0c.dll\0");

    let parsed = BoundImportDirectory::parse(&data).unwrap();
    assert_eq!(parsed.descriptors.len(), 2);
    assert_eq!(parsed.descriptors[0].forwarder_refs[0].module_name, "b.dll");
    assert_eq!(parsed.descriptors[1].module_name, "c.dll");
}

#[test]
fn test_parse_rejects_bad_names() {
    // The name at offset 16 has no null terminator.
    let mut data = vec![1, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'a'];
    assert!(BoundImportDirectory::parse(&data).is_err());
    // The name offset is past the end of the data.
    data[4] = 0x40;
    assert!(BoundImportDirectory::parse(&data).is_err());
    // A truncated descriptor.
    assert!(BoundImportDirectory::parse(&data[..4]).is_err());
}

/// Make a directory with `count` descriptors that all point at one name of `name_len`
/// bytes after the terminator.
fn shared_name_directory(count: usize, name_len: usize) -> Vec<u8> {
    let name_offset = u16::try_from((count + 1) * 8).unwrap();
    let mut data = Vec::new();
    for _ in 0..count {
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&name_offset.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    data.extend_from_slice(&[0; 8]);
    data.resize(data.len() + name_len, b'A');
    data.push(0);
    data
}

#[test]
fn test_parse_limits_shared_names() {
    // Before the fix, each descriptor made a new copy of the name without a limit. The
    // reviewer's shape (7000 descriptors, a 100,000-byte name) gave 700 MB of names.
    let data = shared_name_directory(300, 4000);
    let error = BoundImportDirectory::parse(&data).unwrap_err();
    assert!(error.to_string().contains("names repeat"), "{error}");

    // A smaller output than the 1 MiB floor is permitted.
    let data = shared_name_directory(200, 4000);
    let parsed = BoundImportDirectory::parse(&data).unwrap();
    let total: usize = parsed
        .descriptors
        .iter()
        .map(|descriptor| descriptor.module_name.len())
        .sum();
    assert_eq!(total, 200 * 4000);
}

#[test]
fn test_parse_limits_the_name_length() {
    // Before the fix, a name had no length limit.
    let data = shared_name_directory(1, 4097);
    assert!(BoundImportDirectory::parse(&data).is_err());
    let data = shared_name_directory(1, 4096);
    let parsed = BoundImportDirectory::parse(&data).unwrap();
    assert_eq!(parsed.descriptors[0].module_name.len(), 4096);
}
