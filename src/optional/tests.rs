use super::*;

#[test]
fn test_optional_header_sizes() {
    assert_eq!(OptionalHeader32::BASE_SIZE, 96);
    assert_eq!(OptionalHeader64::BASE_SIZE, 112);
}

#[test]
fn test_subsystem_from_u16() {
    assert_eq!(Subsystem::from_u16(2), Some(Subsystem::WindowsGui));
    assert_eq!(Subsystem::from_u16(3), Some(Subsystem::WindowsCui));
    assert_eq!(Subsystem::from_u16(255), None);
}
