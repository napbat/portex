use super::*;

#[test]
fn test_dos_header_size() {
    assert_eq!(DosHeader::SIZE, 64);
}

#[test]
fn test_dos_header_parse_too_small() {
    let data = [0u8; 32];
    let result = DosHeader::parse(&data);
    assert!(matches!(
        result,
        Err(ref e) if matches!(e.kind, crate::error::ErrorKind::BufferTooSmall { .. })
    ));
}

#[test]
fn test_dos_header_invalid_signature() {
    let mut data = [0u8; 64];
    data[0] = 0x00;
    data[1] = 0x00;
    let result = DosHeader::parse(&data);
    assert!(matches!(
        result,
        Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
    ));
}

#[test]
fn test_dos_header_roundtrip() {
    let mut data = [0u8; 64];
    data[0] = 0x4D; // 'M'
    data[1] = 0x5A; // 'Z'
    data[60..64].copy_from_slice(&0x80i32.to_le_bytes());

    let header = DosHeader::parse(&data).unwrap();
    assert_eq!(header.e_magic, DOS_SIGNATURE);
    assert_eq!(header.e_lfanew, 0x80);

    let mut output = [0u8; 64];
    header.write(&mut output).unwrap();
    assert_eq!(data, output);
}
