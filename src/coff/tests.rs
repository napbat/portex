use super::*;

#[test]
fn test_coff_header_size() {
    assert_eq!(CoffHeader::SIZE, 20);
}

#[test]
fn test_machine_type_from_u16() {
    assert_eq!(MachineType::from_u16(0x8664), Some(MachineType::Amd64));
    assert_eq!(MachineType::from_u16(0x014C), Some(MachineType::I386));
    assert_eq!(MachineType::from_u16(0xFFFF), None);
}

#[test]
fn test_coff_header_roundtrip() {
    let header = CoffHeader {
        machine: MachineType::Amd64 as u16,
        number_of_sections: 5,
        time_date_stamp: 0x1234_5678,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: 240,
        characteristics: characteristics::EXECUTABLE_IMAGE | characteristics::LARGE_ADDRESS_AWARE,
    };

    let mut buf = [0u8; 20];
    header.write(&mut buf).unwrap();

    let parsed = CoffHeader::parse(&buf).unwrap();
    assert_eq!(header, parsed);
    assert!(parsed.is_executable());
    assert!(!parsed.is_dll());
}
