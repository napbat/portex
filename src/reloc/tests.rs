use super::*;
use crate::prelude::*;

#[test]
fn test_relocation_entry_roundtrip() {
    let entry = RelocationEntry {
        reloc_type: RelocationType::HighLow,
        offset: 0x123,
    };
    let value = entry.to_u16();
    let parsed = RelocationEntry::from_u16(value);
    assert_eq!(entry.reloc_type, parsed.reloc_type);
    assert_eq!(entry.offset, parsed.offset);
}

#[test]
fn test_relocation_entry_padding() {
    let entry = RelocationEntry::from_u16(0);
    assert!(entry.is_padding());

    let entry2 = RelocationEntry::from_u16(0x3123); // HIGHLOW
    assert!(!entry2.is_padding());
}

#[test]
fn test_relocation_block_parse() {
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // page_rva
    data[4..8].copy_from_slice(&16u32.to_le_bytes()); // block_size (header + 4 entries)
    data[8..10].copy_from_slice(&0x3010u16.to_le_bytes()); // HIGHLOW at 0x10
    data[10..12].copy_from_slice(&0x3020u16.to_le_bytes()); // HIGHLOW at 0x20
    data[12..14].copy_from_slice(&0x0000u16.to_le_bytes()); // padding
    data[14..16].copy_from_slice(&0xA030u16.to_le_bytes()); // DIR64 at 0x30

    let block = RelocationBlock::parse(&data).unwrap();
    assert_eq!(block.page_rva, 0x1000);
    assert_eq!(block.entries.len(), 4);
    assert_eq!(block.entries[0].reloc_type, RelocationType::HighLow);
    assert_eq!(block.entries[0].offset, 0x10);
    assert!(block.entries[2].is_padding());
    assert_eq!(block.entries[3].reloc_type, RelocationType::Dir64);
}

#[test]
fn test_relocation_table_builder() {
    let mut table = RelocationTable::default();

    // Add relocations on different pages.
    table.add_highlow(0x1010);
    table.add_highlow(0x1020);
    table.add_dir64(0x2008);
    table.add_highlow(0x1030); // Same page as first two

    let data = table.build();

    // Parse the data again.
    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let offset = rva as usize;
        if offset >= data.len() {
            return None;
        }
        let available = (data.len() - offset).min(len);
        Some(data[offset..offset + available].to_vec())
    };

    let parsed = RelocationTable::parse(0, u32::try_from(data.len()).unwrap(), read_fn).unwrap();
    assert_eq!(parsed.blocks.len(), 2); // Two pages: 0x1000 and 0x2000
    assert_eq!(parsed.relocation_count(), 4);
}

#[test]
fn test_relocation_builder() {
    let mut builder = RelocationBuilder::new();

    builder
        .add_dir64(0x1000)
        .add_dir64(0x1008)
        .add_highlow(0x2000);

    assert_eq!(builder.relocation_count(), 3);

    let (data, size) = builder.build();
    assert!(size > 0);
    assert_eq!(data.len(), size as usize);

    // Parse the data again.
    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let offset = rva as usize;
        if offset >= data.len() {
            return None;
        }
        let available = (data.len() - offset).min(len);
        Some(data[offset..offset + available].to_vec())
    };

    let parsed = RelocationTable::parse(0, size, read_fn).unwrap();
    assert_eq!(parsed.blocks.len(), 2);
    assert_eq!(parsed.relocation_count(), 3);
}

#[test]
fn test_apply_wraps_at_field_width() {
    let entry = |reloc_type, offset| RelocationEntry { reloc_type, offset };
    let table = RelocationTable {
        blocks: vec![RelocationBlock {
            page_rva: 0,
            block_size: 0,
            entries: vec![
                entry(RelocationType::HighLow, 0x00),
                entry(RelocationType::Dir64, 0x08),
                entry(RelocationType::Low, 0x10),
                entry(RelocationType::High, 0x12),
                entry(RelocationType::HighAdj, 0x14),
                // HIGHADJ adjustment word (low half of the target), 0x7FFF.
                RelocationEntry::from_u16(0x7FFF),
            ],
        }],
    };
    let mut buffer = vec![0u8; 0x18];
    buffer[0x00..0x04].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    buffer[0x08..0x10].copy_from_slice(&u64::MAX.to_le_bytes());
    buffer[0x10..0x12].copy_from_slice(&0xFFFFu16.to_le_bytes());
    buffer[0x12..0x14].copy_from_slice(&0xFFFFu16.to_le_bytes());
    buffer[0x14..0x16].copy_from_slice(&0xFFFFu16.to_le_bytes());

    let applied = table.try_apply(&mut buffer, 0x1_0020, true).unwrap();
    assert_eq!(applied, 5);
    // 0xFFFF_FFF0 + 0x1_0020 wraps to 0x0001_0010.
    assert_eq!(buffer[0x00..0x04], 0x0001_0010u32.to_le_bytes());
    // u64::MAX + 0x1_0020 wraps to 0x1_001F.
    assert_eq!(buffer[0x08..0x10], 0x0001_001Fu64.to_le_bytes());
    // Low 16 bits of 0xFFFF + 0x1_0020.
    assert_eq!(buffer[0x10..0x12], 0x001Fu16.to_le_bytes());
    // High 16 bits of 0xFFFF_0000 + 0x1_0020 = 0x1_0000_0020.
    assert_eq!(buffer[0x12..0x14], 0x0000u16.to_le_bytes());
    // (0xFFFF_7FFF + 0x1_0020 + 0x8000) >> 16 = 0x1_0001, truncated.
    assert_eq!(buffer[0x14..0x16], 0x0001u16.to_le_bytes());

    // A negative delta wraps below zero.
    let mut buffer = 0x10u32.to_le_bytes().to_vec();
    let table = RelocationTable {
        blocks: vec![RelocationBlock {
            page_rva: 0,
            block_size: 0,
            entries: vec![entry(RelocationType::HighLow, 0)],
        }],
    };
    table.try_apply(&mut buffer, -0x20, false).unwrap();
    assert_eq!(buffer, 0xFFFF_FFF0u32.to_le_bytes());
}

#[test]
fn test_block_parse_rejects_bad_sizes() {
    let mut data = vec![0u8; 12];
    data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
    // The block size is larger than the data.
    data[4..8].copy_from_slice(&16u32.to_le_bytes());
    let error = RelocationBlock::parse(&data).unwrap_err();
    assert!(matches!(
        error.kind(),
        crate::ErrorKind::BufferTooSmall { .. }
    ));
    // The block size is smaller than the header.
    data[4..8].copy_from_slice(&4u32.to_le_bytes());
    let error = RelocationBlock::parse(&data).unwrap_err();
    assert!(matches!(
        error.kind(),
        crate::ErrorKind::InvalidDataDirectory(_)
    ));
    let error = RelocationBlock::parse(&data[..7]).unwrap_err();
    assert!(matches!(
        error.kind(),
        crate::ErrorKind::BufferTooSmall { .. }
    ));
}

#[test]
fn test_apply_rejects_bad_targets() {
    let table = |entries| RelocationTable {
        blocks: vec![RelocationBlock {
            page_rva: 0,
            block_size: 0,
            entries,
        }],
    };
    let entry = |reloc_type, offset| RelocationEntry { reloc_type, offset };
    // The 4-byte field at offset 2 ends past the 4-byte buffer.
    let mut buffer = vec![0u8; 4];
    let error = table(vec![entry(RelocationType::HighLow, 2)])
        .try_apply(&mut buffer, 1, false)
        .unwrap_err();
    assert!(matches!(error.kind(), crate::ErrorKind::InvalidRva(2)));
    assert_eq!(buffer, [0; 4]);
    // A HIGHADJ entry without its adjustment word.
    let error = table(vec![entry(RelocationType::HighAdj, 0)])
        .try_apply(&mut buffer, 1, false)
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        crate::ErrorKind::InvalidDataDirectory(_)
    ));
}
