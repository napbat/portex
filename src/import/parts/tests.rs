use nostdio::Write;

use super::*;

#[test]
fn split_parts_gives_each_part_its_own_cursor() {
    let mut data = [0u8; 6];
    let [mut first, mut second, third] = split_parts(&mut data, [0, 2, 5]).unwrap();
    first.write_all(&[1, 2]).unwrap();
    // A write past the end of a part fails and leaves the next part unchanged.
    assert!(first.write_all(&[3]).is_err());
    second.write_all(&[4, 5, 6]).unwrap();
    assert_eq!(third.get_ref().len(), 1);
    assert_eq!(data, [1, 2, 4, 5, 6, 0]);
}

#[test]
fn split_parts_rejects_bad_offsets() {
    let mut data = [0u8; 4];
    assert!(split_parts(&mut data, [1, 2]).is_err());
    assert!(split_parts(&mut data, [0, 3, 2]).is_err());
    assert!(split_parts(&mut data, [0, 5]).is_err());
}

#[test]
fn skip_to_even_moves_only_from_odd_positions() {
    let mut data = [0u8; 4];
    let mut cursor = Cursor::new(&mut data[..]);
    skip_to_even(&mut cursor).unwrap();
    assert_eq!(cursor.position(), 0);
    cursor.seek_relative(1).unwrap();
    skip_to_even(&mut cursor).unwrap();
    assert_eq!(cursor.position(), 2);
}
