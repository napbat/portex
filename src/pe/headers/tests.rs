use super::*;
use crate::PeImage;

#[test]
fn test_parse_invalid_dos_signature() {
    let data = vec![0u8; 256];
    let result = PeImage::parse(&data);
    assert!(matches!(
        result,
        Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
    ));
}

#[test]
fn test_parse_dos_signature_only() {
    // The missing DOS header bytes read as zeros, so `e_lfanew` is 0 and no PE header follows.
    let data = vec![0x4D, 0x5A];
    let result = PeImage::parse(&data);
    assert!(matches!(
        &result,
        Err(e) if matches!(e.kind, crate::error::ErrorKind::InvalidHeader(_))
    ));
}

#[test]
fn test_headers_parse_invalid() {
    let data = vec![0u8; 256];
    let result = PeHeaders::from_slice(&data);
    assert!(matches!(
        result,
        Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
    ));
}
