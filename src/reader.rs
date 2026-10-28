//! The [`ReadAt`] trait and positional readers for PE data sources.

use crate::prelude::*;
use crate::{Error, Result};
use core::cell::RefCell;
use nostdio::SeekFrom;

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::path::Path;

/// Trait for reading bytes from a source, for example a file, memory or a remote process.
///
/// Implement this trait to read PE structures from a custom source. An example of such a source
/// is the memory of a remote process, read through `ReadProcessMemory`.
pub trait ReadAt {
    /// Read bytes at `offset` into `buf`.
    ///
    /// Returns the number of bytes that the source read. Returns 0 if `offset` is at or past the
    /// end of the source.
    ///
    /// # Errors
    ///
    /// Returns an error that the implementation defines if the source fails.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Get the total size of the source in bytes, if it is known.
    ///
    /// Returns `None` if the size is not known, for example for a remote process.
    fn size(&self) -> Option<u64>;

    /// Read exactly `buf.len()` bytes at `offset`.
    ///
    /// # Errors
    ///
    /// - Returns [`ErrorKind::BufferTooSmall`](crate::error::ErrorKind::BufferTooSmall) if the
    ///   source ends before `buf` is full.
    /// - Returns [`ErrorKind::OffsetOutOfBounds`](crate::error::ErrorKind::OffsetOutOfBounds) if
    ///   the offset arithmetic overflows.
    /// - Returns a generic error if [`Self::read_at`] reports more bytes than `buf` can hold.
    /// - Propagates any error from [`Self::read_at`].
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let expected = buf.len();
        let mut total = 0usize;

        while total < expected {
            let read_offset = offset
                .checked_add(total as u64)
                .ok_or_else(|| Error::offset_out_of_bounds(usize::MAX, expected))?;
            let count = self.read_at(read_offset, &mut buf[total..])?;
            if count == 0 {
                return Err(Error::buffer_too_small(expected, total));
            }
            if count > expected - total {
                return Err(Error::generic(
                    "ReadAt::read_at reported more bytes than the supplied buffer",
                ));
            }
            total = total
                .checked_add(count)
                .ok_or_else(|| Error::offset_out_of_bounds(usize::MAX, expected))?;
        }

        Ok(())
    }

    /// Read a little-endian `u16` at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Self::read_exact_at`].
    fn read_u16_at(&self, offset: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Read a little-endian `u32` at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Self::read_exact_at`].
    fn read_u32_at(&self, offset: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a little-endian `u64` at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Self::read_exact_at`].
    fn read_u64_at(&self, offset: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a little-endian `i32` at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Self::read_exact_at`].
    fn read_i32_at(&self, offset: u64) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    /// Read `len` bytes at `offset` into a new `Vec`.
    ///
    /// # Errors
    ///
    /// Returns a generic error if the allocation of `len` bytes fails. Propagates any error from
    /// [`Self::read_exact_at`].
    fn read_bytes_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len)
            .map_err(|_| Error::generic("reader request is too large to allocate"))?;
        buf.resize(len, 0);
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Adapter that reads the bytes after the end of a source as zeros.
///
/// A PE file can end inside its headers, for example a tiny file or a data-file DLL. The header
/// parser uses this adapter, so that it reads such headers as the Windows XP loader and the
/// data-file loader do. The adapter knows the end only of a source that reports its size. For
/// another source, it returns the result of the source as it is.
pub(crate) struct ZeroPadded<'a, R> {
    inner: &'a R,
}

impl<'a, R: ReadAt> ZeroPadded<'a, R> {
    /// Wrap `inner`.
    pub(crate) const fn new(inner: &'a R) -> Self {
        Self { inner }
    }
}

impl<R: ReadAt> ReadAt for ZeroPadded<'_, R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let count = self.inner.read_at(offset, buf)?;
        if count == 0 && self.inner.size().is_some_and(|size| offset >= size) {
            buf.fill(0);
            return Ok(buf.len());
        }
        Ok(count)
    }

    fn size(&self) -> Option<u64> {
        self.inner.size()
    }
}

/// Adapter that gives the [`ReadAt`] interface to a [`nostdio::Read`] + [`nostdio::Seek`] stream.
///
/// A stream has a current position, and a read changes that position. [`ReadAt`] reads at an
/// explicit offset through a shared reference. The adapter uses interior mutability to do this.
/// Thus, use the adapter from one thread only.
///
/// For a remote process or a source that reads at an offset natively, implement [`ReadAt`]
/// directly. Such an implementation can support concurrent reads.
pub struct SeekReader<R> {
    inner: RefCell<R>,
    size: Option<u64>,
}

impl<R> SeekReader<R> {
    /// Wrap a seekable stream. `size` is the length of the stream in bytes, if it is known.
    pub const fn new(inner: R, size: Option<u64>) -> Self {
        Self {
            inner: RefCell::new(inner),
            size,
        }
    }

    /// Consume the adapter and return the wrapped stream.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }

    /// Borrow the wrapped stream mutably without consuming the adapter.
    pub fn get_mut(&mut self) -> &mut R {
        self.inner.get_mut()
    }
}

impl<R: nostdio::Seek> SeekReader<R> {
    /// Wrap a seekable stream and find its length.
    ///
    /// The function seeks to the end of the stream to get the length. Then it seeks back to the
    /// original position.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the query of the stream position fails or if a seek fails.
    pub fn with_discovered_size(mut inner: R) -> Result<Self> {
        let original = inner.stream_position()?;
        let size = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(original))?;
        Ok(Self::new(inner, Some(size)))
    }
}

impl<R: nostdio::Read + nostdio::Seek> ReadAt for SeekReader<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut inner = self
            .inner
            .try_borrow_mut()
            .map_err(|_| Error::generic("seekable reader is already borrowed"))?;
        inner.seek(SeekFrom::Start(offset))?;
        // Retry an interrupted read, as the `std::io::Read` contract requires.
        loop {
            match inner.read(buf) {
                Err(error) if nostdio::is_interrupted(&error) => {}
                result => return Ok(result?),
            }
        }
    }

    fn size(&self) -> Option<u64> {
        self.size
    }
}

impl<R> core::fmt::Debug for SeekReader<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SeekReader")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// Positional reader for a byte slice in memory.
#[derive(Debug, Clone)]
pub struct SliceReader<'a> {
    data: &'a [u8],
}

impl<'a> SliceReader<'a> {
    /// Wrap a borrowed byte slice.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Get the underlying byte slice.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl ReadAt for SliceReader<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Some(src) = usize::try_from(offset)
            .ok()
            .and_then(|offset| self.data.get(offset..))
        else {
            return Ok(0); // Offset is at or past the end, or too large for this platform
        };
        let to_read = buf.len().min(src.len());
        // `to_read` is not larger than `buf.len()` or `src.len()`.
        buf[..to_read].copy_from_slice(&src[..to_read]);
        Ok(to_read)
    }

    fn size(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

/// Positional reader for an owned byte vector.
#[derive(Debug, Clone)]
pub struct VecReader {
    data: Vec<u8>,
}

impl VecReader {
    /// Wrap an owned byte vector.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the underlying bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the reader and return the owned bytes.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

impl ReadAt for VecReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        SliceReader::new(&self.data).read_at(offset, buf)
    }

    fn size(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

#[cfg(feature = "std")]
/// Positional reader for a file on disk.
pub type FileReader = SeekReader<File>;

#[cfg(feature = "std")]
impl SeekReader<File> {
    /// Open a file for reading.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file does not open or if the reader cannot find the file
    /// size.
    #[must_use = "opening a file may fail"]
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::with_discovered_size(File::open(path)?)
    }

    /// Get the size of the file in bytes.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.size.unwrap_or(0)
    }
}

/// Positional reader for memory at a base address in the current process.
///
/// Use this reader to parse a module that is already loaded.
#[derive(Debug, Clone, Copy)]
pub struct BaseAddressReader {
    base: *const u8,
    size: Option<usize>,
}

impl BaseAddressReader {
    /// Create a reader for memory that starts at `base`. `size` is an optional limit in bytes.
    ///
    /// # Safety
    ///
    /// For the lifetime of the reader, the caller must make sure that:
    ///
    /// - The memory at `base` is readable for `size` bytes. If `size` is `None`, each range that
    ///   a later [`ReadAt::read_at`] call requests must be readable.
    /// - No other code changes this memory concurrently.
    #[must_use]
    #[expect(
        unsafe_code,
        reason = "constructor encodes the caller's memory-validity invariant"
    )]
    pub unsafe fn new(base: *const u8, size: Option<usize>) -> Self {
        Self { base, size }
    }

    /// Create a reader for memory that starts at `base`, with no size limit.
    ///
    /// # Safety
    ///
    /// For the lifetime of the reader, the caller must make sure that each range that a later
    /// [`ReadAt::read_at`] call requests (as an offset from `base`):
    ///
    /// - Is readable.
    /// - Is not changed concurrently by other code.
    ///
    /// The only exception is a range that ends past the address space, or that ends more than
    /// `isize::MAX` bytes from `base`. [`ReadAt::read_at`] rejects such a range and does not read
    /// memory.
    #[must_use]
    #[expect(
        unsafe_code,
        reason = "constructor encodes the caller's memory-validity invariant"
    )]
    pub unsafe fn from_base(base: *const u8) -> Self {
        Self { base, size: None }
    }
}

impl ReadAt for BaseAddressReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(0); // Offset too large for this platform
        };
        if let Some(size) = self.size {
            if offset >= size {
                return Ok(0);
            }
            let available = size - offset;
            let to_read = buf.len().min(available);
            // SAFETY: the caller of the constructor guarantees `size` readable bytes at `base`.
            // `offset + to_read <= size`. `buf` is a distinct exclusive borrow of at least
            // `to_read` bytes.
            #[expect(unsafe_code, reason = "reads caller-guaranteed in-process memory")]
            unsafe {
                core::ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), to_read);
            }
            return Ok(to_read);
        }
        // An unbounded reader has no size to check against. Reject a range that
        // `pointer::add` cannot reach or that wraps the address space. Such a
        // range cannot be readable memory.
        let max_offset = isize::MAX.unsigned_abs();
        let fits = offset
            .checked_add(buf.len())
            .filter(|&end| end <= max_offset)
            .and_then(|end| self.base.addr().checked_add(end))
            .is_some();
        if !fits {
            return Err(Error::offset_out_of_bounds(offset, max_offset));
        }
        // SAFETY: for an unbounded reader, the caller of the constructor guarantees that each
        // requested range from `base` is readable. The only exception is a range that the check
        // above rejects. `offset + buf.len()` is at most `isize::MAX` and does not wrap the
        // address space. `buf` is a distinct exclusive borrow of exactly `buf.len()` bytes.
        #[expect(unsafe_code, reason = "reads caller-guaranteed in-process memory")]
        unsafe {
            core::ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), buf.len());
        }
        Ok(buf.len())
    }

    fn size(&self) -> Option<u64> {
        self.size.map(|s| s as u64)
    }
}

#[expect(
    unsafe_code,
    reason = "raw pointer field opts out of Send automatically"
)]
// SAFETY: the reader only reads through the raw pointer. It never writes through the pointer
// or frees it. The caller of the constructor guarantees that the memory stays valid and does
// not change. Thus it is sound to move the reader to another thread.
unsafe impl Send for BaseAddressReader {}
#[expect(
    unsafe_code,
    reason = "raw pointer field opts out of Sync automatically"
)]
// SAFETY: `read_at` takes `&self` and only reads through the raw pointer. Thus concurrent
// shared access does only concurrent reads of valid memory.
unsafe impl Sync for BaseAddressReader {}

#[cfg(test)]
mod tests {
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
        let reader = unsafe { BaseAddressReader::from_base(data.as_ptr()) };
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
}
