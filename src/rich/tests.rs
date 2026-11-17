use super::*;

#[test]
fn test_rich_entry_roundtrip() {
    let entry = RichEntry {
        product_id: 0x0104, // Utc1900_C
        build_number: 30729,
        use_count: 5,
    };

    let comp_id = entry.to_comp_id();
    let parsed = RichEntry::from_comp_id(comp_id, entry.use_count);
    assert_eq!(entry.product_id, parsed.product_id);
    assert_eq!(entry.build_number, parsed.build_number);
}

#[test]
fn test_rich_header_build_parse() {
    let header = RichHeader {
        key: 0x1234_5678,
        entries: vec![
            RichEntry {
                product_id: 0x0104,
                build_number: 30729,
                use_count: 5,
            },
            RichEntry {
                product_id: 0x0105,
                build_number: 30729,
                use_count: 1,
            },
        ],
        offset: 0,
        size: 0,
    };

    let built = header.build();

    // Create a minimal PE structure to parse.
    let mut pe_data = vec![0u8; 0x200];
    pe_data[0] = b'M';
    pe_data[1] = b'Z';
    pe_data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes()); // PE at 0x100

    // Insert the Rich header at 0x80.
    pe_data[0x80..0x80 + built.len()].copy_from_slice(&built);

    let parsed = RichHeader::parse(&pe_data).expect("Failed to parse Rich header");
    assert_eq!(parsed.key, header.key);
    assert_eq!(parsed.entries.len(), header.entries.len());
}

#[test]
fn test_rich_builder() {
    let mut builder = RichBuilder::new();

    builder.add(0x0104, 30729, 5).add(0x0105, 30729, 1);

    assert_eq!(builder.entry_count(), 2);

    let (data, size) = builder.build_with_key(0xABCD_1234);
    assert!(size > 0);
    assert_eq!(data.len(), size as usize);
    assert_eq!(size as usize, builder.calculate_size());

    // Parse the result to verify it.
    let mut pe_data = vec![0u8; 0x200];
    pe_data[0] = b'M';
    pe_data[1] = b'Z';
    pe_data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());
    pe_data[0x80..0x80 + data.len()].copy_from_slice(&data);

    let parsed = RichHeader::parse(&pe_data).unwrap();
    assert_eq!(parsed.key, 0xABCD_1234);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].product_id, 0x0104);
    assert_eq!(parsed.entries[1].product_id, 0x0105);
}

#[test]
fn pe_image_parses_rich_header_from_its_dos_stub() {
    let mut image = crate::PeBuilder::new().try_build().unwrap();
    let (encoded, _) = RichBuilder::new()
        .add(0x0104, 30729, 5)
        .try_build_with_key(0x1234_5678)
        .unwrap();
    let start = image.dos_stub.len() - encoded.len();
    image.dos_stub[start..].copy_from_slice(&encoded);

    let parsed = image.rich_header().unwrap();
    assert_eq!(parsed.key, 0x1234_5678);
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].product_id, 0x0104);
}

#[test]
fn test_rich_builder_from_header() {
    let original = RichHeader {
        key: 0x1122_3344,
        entries: vec![RichEntry {
            product_id: 0x0104,
            build_number: 30729,
            use_count: 3,
        }],
        offset: 0,
        size: 0,
    };

    let builder = RichBuilder::from_header(&original);
    assert_eq!(builder.entry_count(), 1);

    let header = builder.into_header(0x5566_7788);
    assert_eq!(header.key, 0x5566_7788);
    assert_eq!(header.entries.len(), 1);
}

#[test]
fn parse_is_linear_in_a_stub_full_of_rich_markers() {
    // Each aligned word is "Rich", so every offset is a candidate with the key "Rich". The
    // old nested search did about 2^38 steps for this stub. One scan needs 2^18 steps.
    let pe_offset = 0x10_0000usize;
    let mut data = b"Rich".repeat((pe_offset + 0x100) / 4);
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&u32::try_from(pe_offset).unwrap().to_le_bytes());
    assert_eq!(RichHeader::parse(&data), None);

    // A real header near the PE header is found in the same stub.
    let (encoded, _) = RichBuilder::new()
        .add(0x0105, 30729, 5)
        .try_build_with_key(0x1234_5678)
        .unwrap();
    let start = pe_offset - 0x40;
    data[start..start + encoded.len()].copy_from_slice(&encoded);
    let parsed = RichHeader::parse(&data).unwrap();
    assert_eq!(parsed.offset, start);
    assert_eq!(parsed.key, 0x1234_5678);
    assert_eq!(parsed.entries.len(), 1);
}

#[test]
fn calculate_key_matches_the_linker_checksum() {
    let mut prefix = vec![0u8; 0x80];
    for (index, byte) in prefix.iter_mut().enumerate() {
        *byte = u8::try_from(index * 7 % 251).unwrap();
    }
    prefix[0..2].copy_from_slice(b"MZ");
    prefix[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());
    let entries = [
        RichEntry::from_comp_id(0x0105_7809, 37),
        RichEntry::from_comp_id(0x0102_7809, 1),
    ];

    // The spec formula, written out independently.
    let mut expected: u32 = 0x80;
    for index in 0..0x80u32 {
        if (0x3C..0x40).contains(&index) {
            continue;
        }
        let byte = u32::from(prefix[usize::try_from(index).unwrap()]);
        expected =
            expected.wrapping_add((byte << (index % 32)) | (byte >> ((32 - index % 32) % 32)));
    }
    expected = expected.wrapping_add(0x0105_7809u32.rotate_left(37 % 32));
    expected = expected.wrapping_add(0x0102_7809u32.rotate_left(1));
    assert_eq!(RichHeader::calculate_key(&entries, &prefix), expected);

    // The e_lfanew bytes have no effect on the key.
    let mut other = prefix.clone();
    other[0x3C..0x40].copy_from_slice(&0x200u32.to_le_bytes());
    assert_eq!(RichHeader::calculate_key(&entries, &other), expected);

    // The builder uses the same key, and the parser reads it back.
    let mut builder = RichBuilder::new();
    for entry in entries {
        builder.add_entry(entry);
    }
    let (encoded, _) = builder.try_build_with_dos_header(&prefix).unwrap();
    let mut data = prefix;
    data.extend_from_slice(&encoded);
    data.resize(0x100 + 4, 0);
    assert_eq!(RichHeader::parse(&data).unwrap().key, expected);
}

#[test]
fn product_name_uses_the_published_prodid_table() {
    let name = |product_id| {
        RichEntry {
            product_id,
            build_number: 0,
            use_count: 0,
        }
        .product_name()
    };
    assert_eq!(name(0x0102), "Linker1400");
    assert_eq!(name(0x0104), "Utc1900_C");
    assert_eq!(name(0x0105), "Utc1900_CPP");
    assert_eq!(name(0x00FF), "Cvtres1400");
    assert_eq!(name(0x0101), "Implib1400");
    assert_eq!(name(0x0100), "Export1400");
    assert_eq!(name(0x00E3), "Utc1800_CVTCIL_CPP");
    assert_eq!(name(0x010F), "Unknown");
}
