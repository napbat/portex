use super::*;

#[test]
fn test_load_config_32_min_size() {
    assert_eq!(LoadConfigDirectory32::MIN_SIZE, 64);
}

#[test]
fn test_load_config_32_roundtrip() {
    let original = LoadConfigDirectory32 {
        size: 104,
        time_date_stamp: 0x1234_5678,
        major_version: 1,
        minor_version: 0,
        security_cookie: 0x0040_1000,
        se_handler_table: 0x0040_2000,
        se_handler_count: 5,
        guard_cf_function_table: 0x0040_3000,
        guard_cf_function_count: 10,
        guard_flags: guard_flags::CF_INSTRUMENTED,
        ..Default::default()
    };

    let bytes = original.to_bytes();
    let parsed = LoadConfigDirectory32::parse(&bytes).unwrap();
    assert_eq!(original.size, parsed.size);
    assert_eq!(original.security_cookie, parsed.security_cookie);
    assert_eq!(original.guard_flags, parsed.guard_flags);
}

/// Before the fix, a `Size` of 70 gave 70 bytes. The parser then rejected the
/// truncated field at 0x44.
#[test]
fn size_inside_a_field_is_extended_to_the_field_end() {
    let config = LoadConfigDirectory32 {
        size: 70,
        security_cookie: 0x0040_1000,
        ..Default::default()
    };
    let bytes = config.try_to_bytes().unwrap();
    assert_eq!(bytes.len(), 72);
    let parsed = LoadConfigDirectory32::parse(&bytes).unwrap();
    assert_eq!(parsed.size, 72);
    assert_eq!(parsed.security_cookie, config.security_cookie);
}

/// Before the fix, `has_cfg` was true for any `GuardFlags` value that is not zero.
#[test]
fn has_cfg_requires_cf_instrumented() {
    let mut config = LoadConfigDirectory32 {
        guard_flags: guard_flags::SECURITY_COOKIE_UNUSED,
        ..Default::default()
    };
    assert!(!config.has_cfg());
    config.guard_flags = 0;
    config.guard_cf_function_table = 0x0040_3000;
    assert!(!config.has_cfg());
    config.guard_flags = guard_flags::CF_INSTRUMENTED;
    assert!(config.has_cfg());
}
