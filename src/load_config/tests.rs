use super::*;

#[test]
fn legacy_prefixes_preserve_present_fields_and_omit_only_whole_fields() {
    let mut early32 = vec![0; 60];
    early32[..4].copy_from_slice(&60_u32.to_le_bytes());
    early32[32..36].copy_from_slice(&0x0040_1000_u32.to_le_bytes());
    let parsed32 = LoadConfigDirectory32::parse(&early32).expect("a whole pre-cookie prefix");
    assert_eq!(parsed32.lock_prefix_table, 0x0040_1000);
    assert_eq!(parsed32.security_cookie, 0);
    assert_eq!(parsed32.se_handler_table, 0);
    let mut cookie64 = vec![0; 96];
    cookie64[..4].copy_from_slice(&96_u32.to_le_bytes());
    cookie64[88..96].copy_from_slice(&0x1_4000_1000_u64.to_le_bytes());
    let parsed64 =
        LoadConfigDirectory64::parse(&cookie64).expect("the cookie predates reserved SEH fields");
    assert_eq!(parsed64.security_cookie, 0x1_4000_1000);
    assert_eq!(parsed64.se_handler_table, 0);
    assert_eq!(parsed64.guard_flags, 0);
    cookie64[..4].fill(0);
    assert_eq!(
        LoadConfigDirectory64::parse(&cookie64)
            .expect("legacy Size zero uses available bytes")
            .security_cookie,
        parsed64.security_cookie
    );
    let mut bounded = vec![0xff; 148];
    bounded[..4].copy_from_slice(&4_u32.to_le_bytes());
    let absent =
        LoadConfigDirectory64::parse(&bounded).expect("bytes beyond declared Size are not fields");
    assert_eq!(absent.security_cookie, 0);
    assert_eq!(absent.trailing_data, Vec::<u8>::new());
}

#[test]
fn versioned_prefixes_reject_partial_fields_and_unreadable_declared_sizes() {
    for size in [5_usize, 9, 53, 61, 65, 73, 89] {
        let mut bytes = vec![0; size];
        bytes[..4].copy_from_slice(
            &u32::try_from(size)
                .expect("test size fits u32")
                .to_le_bytes(),
        );
        assert!(
            LoadConfigDirectory32::parse(&bytes).is_err(),
            "partial PE32 field at Size {size}"
        );
    }
    for size in [5_usize, 9, 25, 41, 77, 89, 97, 105, 113, 145] {
        let mut bytes = vec![0; size];
        bytes[..4].copy_from_slice(
            &u32::try_from(size)
                .expect("test size fits u32")
                .to_le_bytes(),
        );
        assert!(
            LoadConfigDirectory64::parse(&bytes).is_err(),
            "partial PE32+ field at Size {size}"
        );
    }
    for declared in [1_u32, 3, 97] {
        let mut bytes = vec![0; 96];
        bytes[..4].copy_from_slice(&declared.to_le_bytes());
        assert!(LoadConfigDirectory64::parse(&bytes).is_err());
    }
    assert!(LoadConfigDirectory32::parse(&[]).is_err());
    assert!(LoadConfigDirectory64::parse(&[0; 3]).is_err());
}

#[test]
fn serialization_keeps_trailing_data_and_declared_size() {
    let config32 = LoadConfigDirectory32 {
        size: 70,
        security_cookie: 0x0040_1000,
        trailing_data: vec![0xAA, 0xBB],
        ..Default::default()
    };
    let bytes32 = config32.try_to_bytes().expect("a small PE32 record");
    assert_eq!(bytes32.len(), LoadConfigDirectory32::KNOWN_SIZE + 2);
    assert_eq!(bytes32[0xc4..], [0xAA, 0xBB]);
    let parsed32 = LoadConfigDirectory32::parse(&bytes32).expect("serialized PE32 record");
    assert_eq!(parsed32.trailing_data, config32.trailing_data);
    assert_eq!(parsed32.security_cookie, config32.security_cookie);

    let config64 = LoadConfigDirectory64 {
        size: 0x150,
        guard_flags: guard_flags::CF_INSTRUMENTED,
        trailing_data: vec![0xCC],
        ..Default::default()
    };
    let bytes64 = config64.try_to_bytes().expect("a small PE32+ record");
    assert_eq!(bytes64.len(), 0x150);
    assert_eq!(bytes64[0x148], 0xCC);
    assert!(bytes64[0x149..].iter().all(|&byte| byte == 0));
    let parsed64 = LoadConfigDirectory64::parse(&bytes64).expect("serialized PE32+ record");
    assert_eq!(parsed64.guard_flags, config64.guard_flags);
    assert_eq!(parsed64.size, 0x150);
}

#[test]
fn va_field_offsets_cover_every_va_field() {
    let config32 = LoadConfigDirectory::Config32(LoadConfigDirectory32 {
        security_cookie: 0x0040_1000,
        guard_cf_function_table: 0x0040_2000,
        guard_cf_function_count: 3,
        guard_eh_continuation_table: 0x0040_5000,
        ..Default::default()
    });
    assert_eq!(config32.va_field_offsets(), [60, 80, 0xA4]);

    let config64 = LoadConfigDirectory::Config64(LoadConfigDirectory64 {
        lock_prefix_table: 0x1_4000_1000,
        security_cookie: 0x1_4000_2000,
        dynamic_value_reloc_table_offset: 0x40,
        uma_function_pointers: 0x1_4000_6000,
        ..Default::default()
    });
    assert_eq!(config64.va_field_offsets(), [40, 88, 0x140]);
}

/// Each field of the full layout keeps its offset through a round trip.
#[test]
fn every_field_round_trips_at_its_offset() {
    for is_64bit in [false, true] {
        let known = if is_64bit {
            LoadConfigDirectory64::KNOWN_SIZE
        } else {
            LoadConfigDirectory32::KNOWN_SIZE
        };
        let mut bytes = vec![0; known];
        for (index, field) in LoadConfigField::ALL.into_iter().enumerate() {
            let offset = field.offset(is_64bit);
            let value = u8::try_from(index + 1).expect("53 fields");
            bytes[offset..field.end(is_64bit)].fill(value);
        }
        let size = u32::try_from(known).expect("a small structure");
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        let parsed = LoadConfigDirectory::parse(&bytes, is_64bit).expect("a full structure");
        for (index, field) in LoadConfigField::ALL.into_iter().enumerate().skip(1) {
            let byte = u64::try_from(index + 1).expect("53 fields");
            let expected = (0..field.size(is_64bit)).fold(0, |value, _| (value << 8) | byte);
            assert_eq!(parsed.field(field), Some(expected), "{field:?}");
        }
        assert_eq!(parsed.try_to_bytes().expect("a full structure"), bytes);
        assert!(!parsed.has_unknown_fields());
    }
}

#[test]
fn size_states_present_fields_and_rejects_cut_fields() {
    let mut bytes = vec![0; 0x150];
    bytes[..4].copy_from_slice(&0x128_u32.to_le_bytes());
    bytes[0xe4..0xe6].copy_from_slice(&2_u16.to_le_bytes());
    bytes[0x130] = 1;
    let config = LoadConfigDirectory::parse(&bytes, true).expect("a whole prefix");
    assert_eq!(
        config.field(LoadConfigField::DynamicValueRelocTableSection),
        Some(2)
    );
    assert_eq!(
        config.field(LoadConfigField::GuardXfgDispatchFunctionPointer),
        Some(0)
    );
    assert_eq!(
        config.va(LoadConfigField::GuardXfgDispatchFunctionPointer),
        None
    );
    assert_eq!(
        config.field(LoadConfigField::CastGuardOsDeterminedFailureMode),
        None
    );
    assert!(!config.has_unknown_fields());

    bytes[..4].copy_from_slice(&0x124_u32.to_le_bytes());
    let error = LoadConfigDirectory::parse(&bytes, true).expect_err("a cut field");
    assert!(error.to_string().contains("0x120"), "{error}");
    for size in [0x5d_u32, 0xc2] {
        let mut bytes = vec![0; 0xc4];
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        assert!(
            LoadConfigDirectory::parse(&bytes, false).is_err(),
            "{size:#x}"
        );
    }

    bytes[..4].copy_from_slice(&0x150_u32.to_le_bytes());
    let config = LoadConfigDirectory::parse(&bytes, true).expect("a known prefix and more");
    assert!(!config.has_unknown_fields());
    bytes[0x14c] = 1;
    let config = LoadConfigDirectory::parse(&bytes, true).expect("a known prefix and more");
    assert!(config.has_unknown_fields());
}
