use super::*;
use crate::ErrorKind;

#[test]
fn test_slice_reader() {
    let data = [0x4D, 0x5A, 0x90, 0x00];
    let reader = SliceReader::new(&data);
    assert_eq!(reader.size(), Some(4));
    assert_eq!(reader.read_u16_at(0).unwrap(), 0x5A4D);
}

#[test]
fn test_vec_reader() {
    let data = vec![0x4D, 0x5A, 0x90, 0x00];
    let reader = VecReader::new(data);
    assert_eq!(reader.read_u16_at(0).unwrap(), 0x5A4D);
}

#[test]
fn test_read_past_end() {
    let data = [0x4D, 0x5A];
    let reader = SliceReader::new(&data);
    let mut buf = [0u8; 4];
    let n = reader.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(reader.read_at(2, &mut buf).unwrap(), 0);
    assert_eq!(reader.read_at(u64::MAX, &mut buf).unwrap(), 0);
}

#[test]
fn test_base_address_reader_rejects_range_past_address_space() {
    let data = [0x4D, 0x5A, 0x90, 0x00];
    #[expect(unsafe_code, reason = "constructs a reader over a local buffer")]
    // SAFETY: the test reads in-range offsets of `data`, and offsets that
    // `read_at` rejects before it reads memory.
    let reader = unsafe { BaseAddressReader::new(data.as_ptr(), None) };
    assert_eq!(reader.read_u16_at(0).unwrap(), 0x5A4D);

    let end = u64::try_from(usize::MAX).unwrap();
    let mut buf = [0u8; 4];
    assert!(matches!(
        reader.read_at(end, &mut buf).unwrap_err().kind(),
        ErrorKind::OffsetOutOfBounds { .. }
    ));
    assert!(reader.read_exact_at(end - 1, &mut buf).is_err());
    let past_isize = u64::try_from(isize::MAX.unsigned_abs()).unwrap();
    assert!(reader.read_at(past_isize, &mut buf).is_err());
}

#[test]
fn base_address_reader_reads_an_empty_range_at_any_offset_as_empty() {
    let data = [0x4D, 0x5A, 0x90, 0x00];
    #[expect(unsafe_code, reason = "constructs a reader over a local buffer")]
    // SAFETY: the test reads only empty ranges, which `read_at` does not read from memory.
    let reader = unsafe { BaseAddressReader::new(data.as_ptr(), None) };
    for offset in [0, 4, 1 << 40, u64::try_from(usize::MAX).unwrap(), u64::MAX] {
        assert_eq!(
            reader.read_at(offset, &mut []).unwrap(),
            0,
            "offset {offset:#x}"
        );
        reader.read_exact_at(offset, &mut []).unwrap();
    }

    #[expect(unsafe_code, reason = "constructs a reader over a local buffer")]
    // SAFETY: `data` is readable for its length and does not change.
    let bounded = unsafe { BaseAddressReader::new(data.as_ptr(), Some(data.len())) };
    assert_eq!(bounded.read_at(2, &mut []).unwrap(), 0);
    assert_eq!(bounded.read_at(u64::MAX, &mut []).unwrap(), 0);
}

/// Source that has a byte at each offset and reads one byte for each call.
struct OneByteReader;

impl ReadAt for OneByteReader {
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize> {
        match buf.first_mut() {
            Some(byte) => {
                *byte = 0xAA;
                Ok(1)
            }
            None => Ok(0),
        }
    }

    fn size(&self) -> Option<u64> {
        None
    }
}

#[test]
fn read_exact_at_reports_the_u64_offset_of_an_overflowing_request() {
    let mut buf = [0u8; 4];
    let error = OneByteReader
        .read_exact_at(u64::MAX - 1, &mut buf)
        .unwrap_err();
    assert!(
        matches!(
            error.kind(),
            ErrorKind::OffsetOutOfBounds {
                offset: 0xFFFF_FFFF_FFFF_FFFE,
                size: 4
            }
        ),
        "{error}"
    );
}

/// Stream that fails its first read with an interrupted error, as a signal can.
struct InterruptedOnce {
    inner: nostdio::Cursor<Vec<u8>>,
    interrupted: bool,
}

impl nostdio::Read for InterruptedOnce {
    fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, nostdio::IoError> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(nostdio::interrupted());
        }
        self.inner.read(buf)
    }
}

impl nostdio::Seek for InterruptedOnce {
    fn seek(&mut self, position: SeekFrom) -> core::result::Result<u64, nostdio::IoError> {
        self.inner.seek(position)
    }
}

#[test]
fn test_seek_reader_retries_interrupted_read() {
    let stream = InterruptedOnce {
        inner: nostdio::Cursor::new(vec![0x4D, 0x5A]),
        interrupted: false,
    };
    let reader = SeekReader::with_discovered_size(stream).unwrap();
    assert_eq!(reader.read_u16_at(0).unwrap(), 0x5A4D);
}
