//! Read PE structures in place, with the buffer offset of each field.
//!
//! The parsers of the other modules copy the values of a table and check them. A patch tool
//! must do more: it rewrites the fields in the buffer, and it must read each field again after
//! a change, because tables can overlap. The raw views of this module support this work:
//!
//! - Each view keeps the offset of each field in a [`RawField`].
//! - Each view reads only the bytes that it needs. It does not check the values.
//! - A cursor (see [`RawCursor`]) reads one record for each call, from the buffer that you
//!   give. Thus you can change the buffer between two calls.
//! - The caller selects the end of each table: a byte or record count, and a rule for the
//!   last record.
//! - The views take buffer offsets, not RVAs. Use your own rule to convert an RVA to an
//!   offset, for example [`PeHeaders::rva_to_offset`](crate::PeHeaders::rva_to_offset).
//!
//! A view returns an [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds)
//! error if a field that it reads is not in the buffer.

mod exception;
mod export;
mod headers;
mod import;
mod loadconfig;
mod reloc;
mod resource;

pub use exception::{RawRuntimeFunction, RawRuntimeFunctions, RawUnwindInfo};
pub use export::RawExportDirectory;
pub use headers::HeaderOffsets;
pub use import::{
    ImportTableEnd, RawAddressTable, RawImportByName, RawImportDescriptor, RawImportDescriptors,
};
pub use loadconfig::RawLoadConfigDirectory;
pub use reloc::{RawRelocation, RawRelocationBlock, RawRelocationBlocks, RawRelocations};
pub use resource::{RawResourceDataEntry, RawResourceDirectory, RawResourceEntry};

use crate::{Error, Result};

/// A field of a PE structure and its offset in the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawField<T> {
    /// The offset of the first byte of the field in the buffer.
    pub offset: usize,
    /// The value of the field when the view read it.
    pub value: T,
}

/// A cursor that reads the records of a table one at a time.
///
/// The cursor keeps only its position. Each call to [`Self::read_next`] reads the next record
/// from the buffer that you give. Thus you can rewrite the buffer between two calls, and the
/// cursor reads the changed bytes, as a tool does that rewrites a table in place.
pub trait RawCursor {
    /// The record type.
    type Item;

    /// Read the next record from `data`.
    ///
    /// Return `Ok(None)` at the end of the table. After the end, each call returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the record is not in `data`.
    fn read_next(&mut self, data: &[u8]) -> Result<Option<Self::Item>>;

    /// Return an iterator over the records in `data`.
    ///
    /// Use this when you do not change the buffer. The iterator stops after the first error.
    fn iter(self, data: &[u8]) -> RawIter<'_, Self>
    where
        Self: Sized,
    {
        RawIter {
            cursor: self,
            data,
            done: false,
        }
    }
}

/// An iterator over the records of a [`RawCursor`] in one buffer.
#[derive(Debug, Clone)]
pub struct RawIter<'a, C> {
    cursor: C,
    data: &'a [u8],
    done: bool,
}

impl<C: RawCursor> Iterator for RawIter<'_, C> {
    type Item = Result<C::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let item = self.cursor.read_next(self.data).transpose();
        if !matches!(item, Some(Ok(_))) {
            self.done = true;
        }
        item
    }
}

/// Read `N` bytes at `offset`.
fn bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    offset
        .checked_add(N)
        .and_then(|end| data.get(offset..end))
        .and_then(|bytes| bytes.first_chunk::<N>())
        .copied()
        .ok_or_else(|| Error::offset_out_of_bounds(offset, data.len()))
}

/// Read the byte at `offset`.
pub(crate) fn read_u8(data: &[u8], offset: usize) -> Result<RawField<u8>> {
    let [value] = bytes::<1>(data, offset)?;
    Ok(RawField { offset, value })
}

/// Read the little-endian `u16` at `offset`.
pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<RawField<u16>> {
    let value = u16::from_le_bytes(bytes(data, offset)?);
    Ok(RawField { offset, value })
}

/// Read the little-endian `u32` at `offset`.
pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<RawField<u32>> {
    let value = u32::from_le_bytes(bytes(data, offset)?);
    Ok(RawField { offset, value })
}

/// Read the little-endian `u64` at `offset`.
pub(crate) fn read_u64(data: &[u8], offset: usize) -> Result<RawField<u64>> {
    let value = u64::from_le_bytes(bytes(data, offset)?);
    Ok(RawField { offset, value })
}

/// Return `base + delta`, or an error if the sum overflows.
pub(crate) fn at(base: usize, delta: usize) -> Result<usize> {
    base.checked_add(delta)
        .ok_or_else(|| Error::offset_out_of_bounds(base, usize::MAX))
}

/// Make sure that `size` bytes at `offset` are in `data`.
pub(crate) fn check_range(data: &[u8], offset: usize, size: usize) -> Result<()> {
    if offset
        .checked_add(size)
        .is_some_and(|end| end <= data.len())
    {
        Ok(())
    } else {
        Err(Error::offset_out_of_bounds(offset, data.len()))
    }
}
