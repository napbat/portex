use super::*;

#[test]
fn test_align_up() {
    assert_eq!(align_up(0, 0x200), 0);
    assert_eq!(align_up(1, 0x200), 0x200);
    assert_eq!(align_up(0x200, 0x200), 0x200);
    assert_eq!(align_up(0x201, 0x200), 0x400);
    assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    assert_eq!(align_up(0x1001, 0x1000), 0x2000);
}

#[test]
#[should_panic(expected = "aligned value exceeds u32")]
fn align_up_panics_on_overflow() {
    assert_eq!(checked_align_up(u32::MAX, 0x1000), None);
    let _ = align_up(u32::MAX, 0x1000);
}

#[test]
fn test_align_down() {
    assert_eq!(align_down(0, 0x200), 0);
    assert_eq!(align_down(0x1FF, 0x200), 0);
    assert_eq!(align_down(0x200, 0x200), 0x200);
    assert_eq!(align_down(0x3FF, 0x200), 0x200);
}

#[test]
fn headers_size_reports_overflow() {
    assert_eq!(
        headers_size(1, 0xE0),
        Some(DosHeader::SIZE + 4 + CoffHeader::SIZE + 0xE0 + SectionHeader::SIZE)
    );
    assert_eq!(headers_size(usize::MAX, 0), None);
    assert_eq!(headers_size(0, usize::MAX), None);
}
