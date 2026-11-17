use super::*;
use core::cell::Cell;

#[test]
fn read_terminated_reads_a_name_at_the_end_of_the_data() {
    let data = b"\x01\x00abc\0";
    let read = |rva: u32, len: usize| {
        let start = usize::try_from(rva).ok()?;
        let end = start.checked_add(len)?;
        data.get(start..end).map(<[u8]>::to_vec)
    };
    assert_eq!(
        read_terminated(&read, 0, 2, "test").unwrap(),
        b"\x01\x00abc"
    );
    assert_eq!(read_terminated(&read, 2, 0, "test").unwrap(), b"abc");
    assert_eq!(read_terminated(&read, 5, 0, "test").unwrap(), b"");
    assert!(read_terminated(&read, 6, 0, "test").is_err());
    // The prefix can contain a zero byte.
    assert_eq!(read_terminated(&read, 1, 2, "test").unwrap(), b"\x00abc");
}

#[test]
fn read_terminated_reads_a_long_name_in_few_reads() {
    let mut data = vec![b'a'; MAX_NAME_LEN];
    data.push(0);
    let reads = Cell::new(0usize);
    let read = |rva: u32, len: usize| {
        reads.set(reads.get() + 1);
        let start = usize::try_from(rva).ok()?;
        let end = start.checked_add(len)?.min(data.len());
        data.get(start..end).map(<[u8]>::to_vec)
    };
    let name = read_terminated(&read, 0, 0, "test").unwrap();
    assert_eq!(name.len(), MAX_NAME_LEN);
    // Before the fix, each byte was a separate read.
    assert!(reads.get() <= 8, "{} reads", reads.get());

    data.insert(0, b'a');
    let read = |rva: u32, len: usize| {
        let start = usize::try_from(rva).ok()?;
        let end = start.checked_add(len)?.min(data.len());
        data.get(start..end).map(<[u8]>::to_vec)
    };
    assert!(read_terminated(&read, 0, 0, "test").is_err());
}
