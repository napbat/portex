use super::*;

#[test]
fn test_certificate_header_size() {
    assert_eq!(Certificate::HEADER_SIZE, 8);
}

#[test]
fn test_certificate_revision() {
    assert_eq!(
        CertificateRevision::from_u16(0x0100),
        CertificateRevision::Revision1
    );
    assert_eq!(
        CertificateRevision::from_u16(0x0200),
        CertificateRevision::Revision2
    );
    assert_eq!(
        CertificateRevision::from_u16(0x0300),
        CertificateRevision::Unknown(0x0300)
    );
}

#[test]
fn test_certificate_type() {
    assert_eq!(
        CertificateType::from_u16(0x0002),
        CertificateType::PkcsSignedData
    );
    assert_eq!(
        CertificateType::from_u16(0x0000),
        CertificateType::Unknown(0x0000)
    );
}

#[test]
fn test_certificate_buffer_too_small() {
    let data = [0u8; 7];
    assert!(Certificate::parse(&data).is_err());
}

#[test]
fn test_builder_empty() {
    let dir = SecurityDirectory::default();
    let data = SecurityBuilder::build(&dir);
    assert_eq!(data, [] as [u8; 0]);
    assert_eq!(SecurityBuilder::calculate_size(&dir), 0);
}

#[test]
fn test_builder_roundtrip() {
    let cert = Certificate {
        length: 0, // The builder calculates the length.
        revision: CertificateRevision::Revision2,
        certificate_type: CertificateType::PkcsSignedData,
        data: vec![0x30, 0x82, 0x01, 0x00], // A fake ASN.1 header.
    };

    let dir = SecurityDirectory {
        certificates: vec![cert],
    };

    let data = SecurityBuilder::build(&dir);

    // Parse the data again.
    let parsed = SecurityDirectory::parse(&data).unwrap();
    assert_eq!(parsed.certificates.len(), 1);
    assert_eq!(
        parsed.certificates[0].revision,
        CertificateRevision::Revision2
    );
    assert_eq!(
        parsed.certificates[0].certificate_type,
        CertificateType::PkcsSignedData
    );
    assert_eq!(parsed.certificates[0].data, vec![0x30, 0x82, 0x01, 0x00]);
}

#[test]
fn test_builder_alignment() {
    // Each certificate must be aligned to 8 bytes.
    let cert = Certificate {
        length: 0,
        revision: CertificateRevision::Revision2,
        certificate_type: CertificateType::PkcsSignedData,
        data: vec![1, 2, 3], // 3 data bytes + 8 header bytes = 11, rounded up to 16.
    };

    let dir = SecurityDirectory {
        certificates: vec![cert],
    };

    let size = SecurityBuilder::calculate_size(&dir);
    assert_eq!(size % 8, 0); // The size must be aligned to 8 bytes.
    assert_eq!(size, 16); // 11, rounded up to 16.
}

#[test]
fn test_builder_two_certificates_layout() {
    let first = Certificate {
        length: 0,
        revision: CertificateRevision::Revision2,
        certificate_type: CertificateType::PkcsSignedData,
        data: vec![1, 2, 3],
    };
    let second = Certificate {
        length: 0,
        revision: CertificateRevision::Revision1,
        certificate_type: CertificateType::X509,
        data: vec![4; 8],
    };
    let dir = SecurityDirectory {
        certificates: vec![first, second],
    };

    let data = SecurityBuilder::try_build(&dir).unwrap();
    assert_eq!(
        data.len(),
        SecurityBuilder::try_calculate_size(&dir).unwrap()
    );
    assert_eq!(data.len(), 32);
    assert_eq!(&data[0..4], &11u32.to_le_bytes());
    assert_eq!(&data[11..16], &[0; 5]);
    assert_eq!(&data[16..20], &16u32.to_le_bytes());

    let parsed = SecurityDirectory::parse(&data).unwrap();
    assert_eq!(parsed.certificates.len(), 2);
    assert_eq!(parsed.certificates[1].data, vec![4; 8]);
}

#[test]
fn test_certificate_length_out_of_range() {
    let mut data = [0u8; 16];
    data[0..4].copy_from_slice(&4u32.to_le_bytes());
    assert!(Certificate::parse(&data).is_err());
    data[0..4].copy_from_slice(&17u32.to_le_bytes());
    assert!(Certificate::parse(&data).is_err());
    assert!(SecurityDirectory::parse(&data[..12]).is_err());
}

#[test]
fn a_last_certificate_without_padding_parses() {
    // Two certificates of 11 and 13 bytes. Only the first one has its padding.
    let mut data = vec![0u8; 16 + 13];
    data[0..4].copy_from_slice(&11u32.to_le_bytes());
    data[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
    data[6..8].copy_from_slice(&0x0002u16.to_le_bytes());
    data[16..20].copy_from_slice(&13u32.to_le_bytes());
    data[20..22].copy_from_slice(&0x0200u16.to_le_bytes());
    data[22..24].copy_from_slice(&0x0EF1u16.to_le_bytes());
    data[24..29].copy_from_slice(&[1, 2, 3, 4, 5]);

    let (_, consumed) = Certificate::parse(&data[16..]).unwrap();
    assert_eq!(consumed, 13);
    let parsed = SecurityDirectory::parse(&data).unwrap();
    assert_eq!(parsed.certificates.len(), 2);
    assert_eq!(parsed.certificates[1].length, 13);
    assert_eq!(
        parsed.certificates[1].certificate_type,
        CertificateType::EfiGuid
    );
    assert_eq!(parsed.certificates[1].data, [1, 2, 3, 4, 5]);
}

#[test]
fn efi_certificate_types_have_names() {
    for (value, name) in [
        (0x0EF0, CertificateType::EfiPkcs115),
        (0x0EF1, CertificateType::EfiGuid),
    ] {
        assert_eq!(CertificateType::from_u16(value), name);
        assert_eq!(name.as_u16(), value);
    }
}
