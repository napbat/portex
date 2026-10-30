//! Raw views of the import directory: descriptors, address tables and hint/name entries.

use super::{RawCursor, RawField, at, read_u8, read_u16, read_u32, read_u64};
use crate::Result;
use crate::import::ImportDescriptor;

/// The rule that ends a list of import descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportTableEnd {
    /// End at a descriptor with all fields zero, as the loader does.
    #[default]
    NullDescriptor,
    /// End at the first descriptor with a zero `OriginalFirstThunk`, as `msdelta.dll` does.
    ZeroOriginalFirstThunk,
}

/// An import descriptor (`IMAGE_IMPORT_DESCRIPTOR`) and the offsets of its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawImportDescriptor {
    /// The offset of the descriptor.
    pub offset: usize,
    /// `OriginalFirstThunk`: the RVA of the import lookup table.
    pub original_first_thunk: RawField<u32>,
    /// `TimeDateStamp`. It is not zero for a bound import.
    pub time_date_stamp: RawField<u32>,
    /// `ForwarderChain`.
    pub forwarder_chain: RawField<u32>,
    /// `Name`: the RVA of the DLL name.
    pub name_rva: RawField<u32>,
    /// `FirstThunk`: the RVA of the import address table.
    pub first_thunk: RawField<u32>,
}

impl RawImportDescriptor {
    /// The size of `IMAGE_IMPORT_DESCRIPTOR` in bytes.
    pub const SIZE: usize = ImportDescriptor::SIZE;

    /// Read the import descriptor at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        super::check_range(data, offset, Self::SIZE)?;
        Ok(Self {
            offset,
            original_first_thunk: read_u32(data, offset)?,
            time_date_stamp: read_u32(data, at(offset, 4)?)?,
            forwarder_chain: read_u32(data, at(offset, 8)?)?,
            name_rva: read_u32(data, at(offset, 12)?)?,
            first_thunk: read_u32(data, at(offset, 16)?)?,
        })
    }

    /// Return `true` if all fields are zero.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.descriptor().is_null()
    }

    /// Return the values of the fields as an [`ImportDescriptor`].
    #[must_use]
    pub fn descriptor(&self) -> ImportDescriptor {
        ImportDescriptor {
            original_first_thunk: self.original_first_thunk.value,
            time_date_stamp: self.time_date_stamp.value,
            forwarder_chain: self.forwarder_chain.value,
            name_rva: self.name_rva.value,
            first_thunk: self.first_thunk.value,
        }
    }
}

/// A cursor over the import descriptors of an import directory.
///
/// The cursor reads at most `size` bytes of descriptors. It ends at a partial descriptor, or at
/// the descriptor that the [`ImportTableEnd`] rule selects. It does not return that last
/// descriptor.
#[derive(Debug, Clone)]
pub struct RawImportDescriptors {
    offset: usize,
    remaining: usize,
    end: ImportTableEnd,
}

impl RawImportDescriptors {
    /// Make a cursor for the descriptors at `offset`, with at most `size` bytes.
    #[must_use]
    pub const fn new(offset: usize, size: usize, end: ImportTableEnd) -> Self {
        Self {
            offset,
            remaining: size,
            end,
        }
    }
}

impl RawCursor for RawImportDescriptors {
    type Item = RawImportDescriptor;

    fn read_next(&mut self, data: &[u8]) -> Result<Option<RawImportDescriptor>> {
        if self.remaining < RawImportDescriptor::SIZE {
            return Ok(None);
        }
        let descriptor = RawImportDescriptor::parse(data, self.offset)?;
        let last = match self.end {
            ImportTableEnd::NullDescriptor => descriptor.is_null(),
            ImportTableEnd::ZeroOriginalFirstThunk => descriptor.original_first_thunk.value == 0,
        };
        if last {
            self.remaining = 0;
            return Ok(None);
        }
        self.offset = at(self.offset, RawImportDescriptor::SIZE)?;
        self.remaining -= RawImportDescriptor::SIZE;
        Ok(Some(descriptor))
    }
}

/// A cursor over a table of 32-bit or 64-bit address entries.
///
/// Use it for an import lookup table, an import address table, an export address table, an
/// export name pointer table or the lock prefix table of the load configuration. Each entry is
/// a [`RawField<u64>`]. A 32-bit entry has zero in its high bits.
#[derive(Debug, Clone)]
pub struct RawAddressTable {
    offset: usize,
    remaining: usize,
    is_64bit: bool,
    ends_at_zero: bool,
}

impl RawAddressTable {
    /// Make a cursor that ends at a zero entry or after `size` bytes.
    ///
    /// The cursor does not return the zero entry. It ignores a partial entry at the end of
    /// `size`. Use this for an import lookup table, an import address table or the lock prefix
    /// table.
    #[must_use]
    pub const fn zero_terminated(offset: usize, size: usize, is_64bit: bool) -> Self {
        let width = if is_64bit { 8 } else { 4 };
        Self {
            offset,
            remaining: size / width,
            is_64bit,
            ends_at_zero: true,
        }
    }

    /// Make a cursor that reads `count` entries, also the zero entries.
    ///
    /// Use this for an export address table or an export name pointer table.
    #[must_use]
    pub const fn counted(offset: usize, count: usize, is_64bit: bool) -> Self {
        Self {
            offset,
            remaining: count,
            is_64bit,
            ends_at_zero: false,
        }
    }

    /// Return the size of one entry in bytes: 4 or 8.
    #[must_use]
    pub const fn entry_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }
}

impl RawCursor for RawAddressTable {
    type Item = RawField<u64>;

    fn read_next(&mut self, data: &[u8]) -> Result<Option<RawField<u64>>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let entry = if self.is_64bit {
            read_u64(data, self.offset)?
        } else {
            let entry = read_u32(data, self.offset)?;
            RawField {
                offset: entry.offset,
                value: u64::from(entry.value),
            }
        };
        if self.ends_at_zero && entry.value == 0 {
            self.remaining = 0;
            return Ok(None);
        }
        self.offset = at(self.offset, self.entry_size())?;
        self.remaining -= 1;
        Ok(Some(entry))
    }
}

/// A hint/name entry (`IMAGE_IMPORT_BY_NAME`) and the offsets of its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawImportByName {
    /// The offset of the entry.
    pub offset: usize,
    /// `Hint`: the index into the export name pointer table of the DLL.
    pub hint: RawField<u16>,
    /// The offset of the first byte of the name.
    pub name_offset: usize,
    /// The length of the name in bytes, without the zero terminator.
    pub name_len: usize,
}

impl RawImportByName {
    /// Read the hint/name entry at `offset`, with at most `size` bytes.
    ///
    /// Return `None` if `size` is 2 or less, or if no zero byte ends the name in the first
    /// `size` bytes of the entry. The method reads the name bytes one at a time, and stops at
    /// the zero byte.
    ///
    /// # Errors
    ///
    /// Returns an error if a byte that the method reads is not in `data`.
    pub fn parse(data: &[u8], offset: usize, size: usize) -> Result<Option<Self>> {
        if size <= 2 {
            return Ok(None);
        }
        let hint = read_u16(data, offset)?;
        let name_offset = at(offset, 2)?;
        for index in 2..size {
            if read_u8(data, at(offset, index)?)?.value == 0 {
                return Ok(Some(Self {
                    offset,
                    hint,
                    name_offset,
                    name_len: index - 2,
                }));
            }
        }
        Ok(None)
    }

    /// Return the size of the entry in bytes: the hint, the name and the zero terminator.
    #[must_use]
    pub const fn size(&self) -> usize {
        // The terminator is in the buffer, so this sum does not overflow.
        self.name_len + 3
    }

    /// Return the name bytes in `data`, or `None` if they are not in `data`.
    #[must_use]
    pub fn name<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        data.get(self.name_offset..self.name_offset.checked_add(self.name_len)?)
    }
}
