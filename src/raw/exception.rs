//! Raw views of the x64 exception directory: `RUNTIME_FUNCTION` records and `UNWIND_INFO`.

use super::{RawCursor, RawField, at, check_range, read_u8, read_u32};
use crate::Result;
use crate::exception::{RuntimeFunction, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER};

/// An x64 `RUNTIME_FUNCTION` record and the offsets of its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRuntimeFunction {
    /// The offset of the record.
    pub offset: usize,
    /// `BeginAddress`: the RVA of the start of the function.
    pub begin_address: RawField<u32>,
    /// `EndAddress`: the RVA of the end of the function.
    pub end_address: RawField<u32>,
    /// `UnwindInfoAddress`: the RVA of the `UNWIND_INFO`.
    pub unwind_info_address: RawField<u32>,
}

impl RawRuntimeFunction {
    /// The size of `RUNTIME_FUNCTION` in bytes.
    pub const SIZE: usize = RuntimeFunction::SIZE;

    /// Read the record at `offset`. The method does not check the values.
    ///
    /// # Errors
    ///
    /// Returns an error if the record is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        check_range(data, offset, Self::SIZE)?;
        Ok(Self {
            offset,
            begin_address: read_u32(data, offset)?,
            end_address: read_u32(data, at(offset, 4)?)?,
            unwind_info_address: read_u32(data, at(offset, 8)?)?,
        })
    }

    /// Return the values of the fields as a [`RuntimeFunction`].
    #[must_use]
    pub fn function(&self) -> RuntimeFunction {
        RuntimeFunction {
            begin_address: self.begin_address.value,
            end_address: self.end_address.value,
            unwind_info_address: self.unwind_info_address.value,
        }
    }
}

/// A cursor over the `RUNTIME_FUNCTION` records of an x64 exception directory.
///
/// The cursor reads `size / 12` records. It ignores a partial record at the end. It returns
/// all records, also records with all fields zero, and it does not check the order.
#[derive(Debug, Clone)]
pub struct RawRuntimeFunctions {
    offset: usize,
    remaining: usize,
}

impl RawRuntimeFunctions {
    /// Make a cursor for the records at `offset`, in `size` bytes.
    #[must_use]
    pub const fn new(offset: usize, size: usize) -> Self {
        Self {
            offset,
            remaining: size / RawRuntimeFunction::SIZE,
        }
    }

    /// Return the count of records that remain.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.remaining
    }

    /// Return `true` if no records remain.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining == 0
    }
}

impl RawCursor for RawRuntimeFunctions {
    type Item = RawRuntimeFunction;

    fn read_next(&mut self, data: &[u8]) -> Result<Option<RawRuntimeFunction>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let function = RawRuntimeFunction::parse(data, self.offset)?;
        self.offset = at(self.offset, RawRuntimeFunction::SIZE)?;
        self.remaining -= 1;
        Ok(Some(function))
    }
}

/// The 4-byte header of an x64 `UNWIND_INFO` and the offsets of its fields.
///
/// The view does not read the unwind codes or the data after them. It only calculates their
/// offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawUnwindInfo {
    /// The offset of the `UNWIND_INFO`.
    pub offset: usize,
    /// The version (bits 0 to 2) and the flags (bits 3 to 7).
    pub version_and_flags: RawField<u8>,
    /// `SizeOfProlog`.
    pub size_of_prolog: RawField<u8>,
    /// `CountOfCodes`: the count of 2-byte unwind code slots.
    pub count_of_codes: RawField<u8>,
    /// The frame register (bits 0 to 3) and the scaled frame offset (bits 4 to 7).
    pub frame_register_and_offset: RawField<u8>,
}

impl RawUnwindInfo {
    /// The size of the `UNWIND_INFO` header in bytes.
    pub const HEADER_SIZE: usize = 4;

    /// Read the `UNWIND_INFO` header at `offset`. The method does not check the values.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        check_range(data, offset, Self::HEADER_SIZE)?;
        Ok(Self {
            offset,
            version_and_flags: read_u8(data, offset)?,
            size_of_prolog: read_u8(data, at(offset, 1)?)?,
            count_of_codes: read_u8(data, at(offset, 2)?)?,
            frame_register_and_offset: read_u8(data, at(offset, 3)?)?,
        })
    }

    /// Return the version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version_and_flags.value & 0x07
    }

    /// Return the `UNW_FLAG_*` flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.version_and_flags.value >> 3
    }

    /// Return `true` if a field follows the unwind codes: the RVA of an exception handler
    /// (`UNW_FLAG_EHANDLER` or `UNW_FLAG_UHANDLER`) or a chained `RUNTIME_FUNCTION`
    /// (`UNW_FLAG_CHAININFO`).
    #[must_use]
    pub const fn has_trailer(&self) -> bool {
        self.flags() & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO) != 0
    }

    /// Return the size of the header and the unwind codes, in bytes.
    ///
    /// The unwind codes have 2 bytes each, and the size is a multiple of 4. This is also the
    /// distance from the start of the `UNWIND_INFO` to the trailer.
    #[must_use]
    pub const fn size_without_trailer(&self) -> usize {
        let slots = self.count_of_codes.value as usize;
        Self::HEADER_SIZE + 4 * slots.div_ceil(2)
    }

    /// Return the offset of the trailer after the unwind codes, or `None` on overflow.
    ///
    /// See [`Self::has_trailer`] for the contents of the trailer.
    #[must_use]
    pub const fn trailer_offset(&self) -> Option<usize> {
        self.offset.checked_add(self.size_without_trailer())
    }
}
