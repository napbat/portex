use super::*;
use crate::prelude::{Vec, vec};

#[test]
fn test_checksum_field_offset() {
    // Minimal PE-like structure
    let mut data = vec![0u8; 256];
    // DOS signature
    data[0] = b'M';
    data[1] = b'Z';
    // e_lfanew pointing to PE header at 0x80
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // PE signature
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x82] = 0;
    data[0x83] = 0;

    let offset = checksum_field_offset(&data);
    // PE offset (0x80) + signature (4) + COFF (20) + checksum offset in optional (64)
    assert_eq!(offset, Some(0x80 + 4 + 20 + 64));
}

#[test]
fn test_calculate_checksum() {
    // Simple test with known data
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    // No checksum field to skip (use offset beyond data)
    let checksum = calculate_checksum(&data, 1000);
    // Sum of words: 0x0201 + 0x0403 + 0x0605 + 0x0807 = 0x1410
    // Plus file size: 0x1410 + 8 = 0x1418
    assert_eq!(checksum, 0x1418);
}

/// Make a fixed byte pattern of `len` bytes.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 37 + 11) % 256).unwrap())
        .collect()
}

/// Zero the 4 field bytes in a copy, then sum the words.
fn reference(data: &[u8], offset: usize) -> u32 {
    let mut copy = data.to_vec();
    for byte in copy.iter_mut().skip(offset).take(4) {
        *byte = 0;
    }
    calculate_checksum(&copy, usize::MAX - 8)
}

#[test]
fn test_odd_offset_skips_the_byte_before_the_field() {
    // Skip byte 2 and the field bytes 3..7. Pair again from byte 7. The file size is odd, so
    // add the last byte again as a low byte:
    // 0x0201 + 0x0908 + 0x0B0A + 0x0B = 0x161E, plus the size 11.
    let data: Vec<u8> = (1..=11).collect();
    assert_eq!(calculate_checksum(&data, 3), 0x161E + 11);
    // The last byte 0x0A has no pair, so skip it: 0x0201 + 0x0908 = 0x0B09, plus the size 10.
    assert_eq!(calculate_checksum(&data[..10], 3), 0x0B09 + 10);
    // The field ends at the end of the file. The file size is odd, so add the last field
    // byte: 0x0201 + 0x07 = 0x0208, plus the size 7.
    assert_eq!(calculate_checksum(&data[..7], 3), 0x0208 + 7);
}

/// Make a small file with the `CheckSum` field at the odd offset 0x99.
fn odd_offset_file(len: usize) -> Vec<u8> {
    let mut data = pattern(len);
    data[..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x41u32.to_le_bytes());
    data[0x41..0x45].copy_from_slice(b"PE\0\0");
    // IMAGE_NT_OPTIONAL_HDR64_MAGIC.
    data[0x59..0x5B].copy_from_slice(&0x20Bu16.to_le_bytes());
    data
}

#[test]
fn test_odd_offset_matches_windows() {
    // `CheckSumMappedFile` in Windows `imagehlp.dll` returned these values for these files.
    for (len, windows) in [
        (0x9D, 0xAB00),
        (0x9E, 0xAA6A),
        (0xA8, 0xF606),
        (0xA9, 0x4989),
    ] {
        let data = odd_offset_file(len);
        assert_eq!(checksum_field_offset(&data), Some(0x99));
        assert_eq!(compute_pe_checksum(&data), Some(windows));
    }
}

#[test]
fn test_checksum_is_stable_after_write() {
    // A field that ends at the end of a file with an odd size is not in this list: its last
    // byte counts.
    for (len, offset) in [
        (64, 0x10),
        (64, 0x11),
        (65, 0x11),
        (64, 0x3B),
        (65, 0x3C),
        (64, 0x3D),
    ] {
        let mut data = pattern(len);
        let value = calculate_checksum(&data, offset);
        let end = data.len().min(offset + 4);
        data[offset..end].copy_from_slice(&value.to_le_bytes()[..end - offset]);
        assert_eq!(calculate_checksum(&data, offset), value);
    }
}

#[test]
fn test_even_offset_matches_reference() {
    // The field ends at, crosses, or starts after the end of the data in the last cases.
    for (len, offset) in [
        (64, 0x10),
        (65, 0x3C),
        (8, 4),
        (64, 0x3C),
        (64, 0x3E),
        (65, 0x3E),
        (65, 0x40),
        (65, 0x42),
    ] {
        let data = pattern(len);
        assert_eq!(calculate_checksum(&data, offset), reference(&data, offset));
    }
}
