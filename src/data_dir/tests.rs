use super::*;

#[test]
fn test_data_directory_size() {
    assert_eq!(DataDirectory::SIZE, 8);
}

#[test]
fn test_data_directory_roundtrip() {
    let dir = DataDirectory {
        virtual_address: 0x1000,
        size: 0x200,
    };

    let mut buf = [0u8; 8];
    dir.write(&mut buf).unwrap();

    let parsed = DataDirectory::parse(&buf).unwrap();
    assert_eq!(dir, parsed);
    assert!(parsed.is_present());
}

#[test]
fn test_data_directory_to_bytes_roundtrip() {
    let dir = DataDirectory {
        virtual_address: 0xABCD_1234,
        size: 0x5678,
    };

    let bytes = dir.to_bytes();
    let parsed = DataDirectory::parse(&bytes).unwrap();
    assert_eq!(dir, parsed);
}

#[test]
fn test_data_directory_not_present() {
    let dir = DataDirectory::default();
    assert!(!dir.is_present());
}

#[test]
fn test_data_directory_type_roundtrip() {
    for dir_type in DataDirectoryType::all() {
        let index = dir_type.as_index();
        let recovered = DataDirectoryType::from_index(index).unwrap();
        assert_eq!(dir_type, recovered);
        assert_ne!(dir_type.name(), "");
    }
}

#[test]
fn test_data_directory_type_values() {
    assert_eq!(DataDirectoryType::Export.as_index(), 0);
    assert_eq!(DataDirectoryType::Import.as_index(), 1);
    assert_eq!(DataDirectoryType::Resource.as_index(), 2);
    assert_eq!(DataDirectoryType::BaseReloc.as_index(), 5);
    assert_eq!(DataDirectoryType::Tls.as_index(), 9);
    assert_eq!(DataDirectoryType::LoadConfig.as_index(), 10);
}
