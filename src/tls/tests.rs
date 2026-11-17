use super::*;

#[test]
fn test_tls_directory_32_size() {
    assert_eq!(TlsDirectory32::SIZE, 24);
}

#[test]
fn test_tls_directory_64_size() {
    assert_eq!(TlsDirectory64::SIZE, 40);
}

#[test]
fn test_tls_directory_32_roundtrip() {
    let original = TlsDirectory32 {
        start_address_of_raw_data: 0x0040_1000,
        end_address_of_raw_data: 0x0040_1100,
        address_of_index: 0x0040_2000,
        address_of_callbacks: 0x0040_3000,
        size_of_zero_fill: 256,
        characteristics: 0,
    };

    let bytes = original.to_bytes();
    let parsed = TlsDirectory32::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_tls_directory_64_roundtrip() {
    let original = TlsDirectory64 {
        start_address_of_raw_data: 0x0000_0001_4000_1000,
        end_address_of_raw_data: 0x0000_0001_4000_1100,
        address_of_index: 0x0000_0001_4000_2000,
        address_of_callbacks: 0x0000_0001_4000_3000,
        size_of_zero_fill: 512,
        characteristics: 0,
    };

    let bytes = original.to_bytes();
    let parsed = TlsDirectory64::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

/// Before the fix, the rebuild pointed `AddressOfIndex` to a new slot in the block. The
/// code of the image still read the original `_tls_index`.
#[test]
fn rebuild_keeps_the_original_index_address() {
    let base = 0x0000_0001_4000_0000;
    let info = TlsInfo {
        directory: Some(TlsDirectory::Tls64(TlsDirectory64 {
            start_address_of_raw_data: base + 0x2000,
            end_address_of_raw_data: base + 0x2010,
            address_of_index: base + 0x2100,
            ..TlsDirectory64::default()
        })),
        callback_rvas: vec![0x1000],
        image_base: base,
    };
    let new_base = 0x0000_0001_8000_0000;
    let builder = TlsBuilder::new(0x3000, new_base, true);
    let (block, _) = builder.try_build_from_info(&info).unwrap();
    let TlsDirectory::Tls64(directory) = TlsDirectory::parse(&block, true).unwrap() else {
        panic!("expected a PE32+ directory");
    };
    assert_eq!(directory.address_of_index, new_base + 0x2100);
    assert_eq!(directory.start_address_of_raw_data, new_base + 0x2000);

    // Without an index, the block gets its own slot.
    let empty = TlsInfo {
        directory: None,
        ..info
    };
    let (block, _) = builder.try_build_from_info(&empty).unwrap();
    let TlsDirectory::Tls64(directory) = TlsDirectory::parse(&block, true).unwrap() else {
        panic!("expected a PE32+ directory");
    };
    assert_eq!(directory.address_of_index, new_base + 0x3000 + 40);
}

#[test]
fn va_offsets_list_the_directory_fields_and_callbacks() {
    let builder = TlsBuilder::new(0x3000, 0x0040_0000, false);
    let (block, _) = builder
        .try_build(0x2000, 0x2010, &[0x1000, 0x1010])
        .unwrap();
    // Start, end, index, callbacks, then two callbacks at offset 28 (24 + 4).
    assert_eq!(builder.va_offsets(&block), [0, 4, 8, 12, 28, 32]);
    let (block, _) = builder.try_build(0, 0, &[]).unwrap();
    assert_eq!(builder.va_offsets(&block), [8]);
}
