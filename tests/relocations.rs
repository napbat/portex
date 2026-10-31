//! Regression tests for the base relocation types and builders.

use portex::reloc::{
    RelocationBlock, RelocationBuilder, RelocationEntry, RelocationTable, RelocationType,
};

#[test]
fn relocation_type_codes_are_canonical() {
    // The type is the low four bits.
    assert_eq!(RelocationType::from_u8(0x13), RelocationType::HighLow);
    assert_eq!(RelocationType::from_u8(0xfa), RelocationType::Dir64);
    assert_eq!(RelocationType::from_u8(0x10), RelocationType::Absolute);
    // Only a code without a name is `Unknown`.
    for code in 11..=15 {
        let reloc_type = RelocationType::from_u8(code);
        assert_eq!(reloc_type, RelocationType::Unknown(code));
        assert_eq!(reloc_type.as_u8(), code);
        assert_eq!(RelocationType::from_u8(code | 0xf0), reloc_type);
    }
    for code in 0..=10 {
        assert!(!matches!(
            RelocationType::from_u8(code),
            RelocationType::Unknown(_)
        ));
        assert_eq!(RelocationType::from_u8(code).as_u8(), code);
    }
}

#[test]
fn serializer_rejects_non_canonical_unknown_types() {
    let block = |reloc_type| RelocationBlock {
        page_rva: 0x1000,
        block_size: 0,
        entries: vec![RelocationEntry {
            reloc_type,
            offset: 0x10,
        }],
    };
    // `Unknown(3)` is the code of `HighLow`.
    assert!(block(RelocationType::Unknown(3)).try_to_bytes().is_err());
    assert!(block(RelocationType::Unknown(0)).try_to_bytes().is_err());
    assert!(block(RelocationType::Unknown(0x13)).try_to_bytes().is_err());
    let bytes = block(RelocationType::Unknown(11)).try_to_bytes().unwrap();
    assert_eq!(bytes[8..10], 0xb010u16.to_le_bytes());
}

#[test]
fn builder_groups_many_pages_quickly() {
    // With a linear search for each page, this test runs for minutes.
    const PAGES: u32 = 1 << 17;
    let mut builder = RelocationBuilder::new();
    for page in (0..PAGES).rev() {
        builder.add_dir64(page << 12);
    }
    for page in 0..PAGES {
        builder.add_dir64((page << 12) | 0x8);
    }
    assert_eq!(builder.relocation_count(), 2 * PAGES as usize);
    let table = builder.into_table();
    assert_eq!(table.blocks.len(), PAGES as usize);
    for (page, block) in (0..PAGES).zip(&table.blocks) {
        assert_eq!(block.page_rva, page << 12);
        assert_eq!(
            block.entries,
            [
                RelocationEntry {
                    reloc_type: RelocationType::Dir64,
                    offset: 0,
                },
                RelocationEntry {
                    reloc_type: RelocationType::Dir64,
                    offset: 8,
                },
            ]
        );
    }
}

#[test]
fn builder_from_table_appends_to_existing_pages() {
    let mut table = RelocationTable::default();
    table.add_highlow(0x2004);
    table.add_highlow(0x1000);
    table.add_highlow(0x2008);
    let mut builder = RelocationBuilder::from_table(table);
    builder
        .add_highlow(0x200c)
        .add_highlow(0x1010)
        .add_highlow(0x3000);
    let table = builder.into_table();
    let pages: Vec<_> = table
        .blocks
        .iter()
        .map(|block| {
            (
                block.page_rva,
                block
                    .entries
                    .iter()
                    .filter(|entry| !entry.is_padding())
                    .map(|entry| entry.offset)
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    assert_eq!(
        pages,
        vec![
            (0x1000, vec![0, 0x10]),
            (0x2000, vec![4, 8, 0xc]),
            (0x3000, vec![0]),
        ]
    );
}
