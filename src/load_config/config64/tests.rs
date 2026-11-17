use super::*;

#[test]
fn test_load_config_64_min_size() {
    assert_eq!(LoadConfigDirectory64::MIN_SIZE, 112);
}

#[test]
fn test_load_config_64_roundtrip() {
    let original = LoadConfigDirectory64 {
        size: 148,
        security_cookie: 0x0000_0001_4000_1000,
        guard_cf_function_table: 0x0000_0001_4000_2000,
        guard_cf_function_count: 20,
        guard_flags: guard_flags::CF_INSTRUMENTED | guard_flags::CF_FUNCTION_TABLE_PRESENT,
        ..Default::default()
    };

    let bytes = original.to_bytes();
    let parsed = LoadConfigDirectory64::parse(&bytes).unwrap();
    assert_eq!(original.size, parsed.size);
    assert_eq!(original.security_cookie, parsed.security_cookie);
    assert_eq!(original.guard_flags, parsed.guard_flags);
}

/// Before the fix, a parsed legacy `Size` of zero was written back as 112.
#[test]
fn legacy_zero_size_is_kept() {
    let mut bytes = vec![0; LoadConfigDirectory64::MIN_SIZE];
    bytes[88..96].copy_from_slice(&0x1_4000_1000_u64.to_le_bytes());
    let parsed = LoadConfigDirectory64::parse(&bytes).unwrap();
    assert_eq!(parsed.size, 0);
    assert_eq!(parsed.try_to_bytes().unwrap(), bytes);
}

/// Before the fix, a `Size` of 116 gave 116 bytes. The parser then rejected the
/// truncated field at 0x70.
#[test]
fn size_inside_a_field_is_extended_to_the_field_end() {
    let config = LoadConfigDirectory64 {
        size: 116,
        ..Default::default()
    };
    let bytes = config.try_to_bytes().unwrap();
    assert_eq!(bytes.len(), 120);
    assert_eq!(LoadConfigDirectory64::parse(&bytes).unwrap().size, 120);
}

#[test]
fn has_cfg_requires_cf_instrumented() {
    let config = LoadConfigDirectory64 {
        guard_flags: guard_flags::RF_INSTRUMENTED,
        guard_cf_function_table: 0x1_4000_2000,
        ..Default::default()
    };
    assert!(!config.has_cfg());
}
