//! ARM and ARM64 `.pdata` records and their exception directory.

use core::mem::{offset_of, size_of};

use nostdio::ReadLe;

use crate::prelude::*;
use crate::{Error, Result};

/// The layout of `IMAGE_ARM_RUNTIME_FUNCTION_ENTRY`.
///
/// The `UnwindData` union is one `u32`. Portex does not read the structure through this type.
/// The type gives the offset and the width of each field.
#[repr(C)]
struct ImageArmRuntimeFunctionEntry {
    begin_address: u32,
    unwind_data: u32,
}

/// The layout of `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY`.
///
/// The `UnwindData` union is one `u32`. Portex does not read the structure through this type.
/// The type gives the offset and the width of each field.
#[repr(C)]
struct ImageArm64RuntimeFunctionEntry {
    begin_address: u32,
    unwind_data: u32,
}

const _: () = {
    assert!(size_of::<ImageArmRuntimeFunctionEntry>() == 8);
    assert!(offset_of!(ImageArmRuntimeFunctionEntry, unwind_data) == 4);
    assert!(size_of::<ImageArm64RuntimeFunctionEntry>() == 8);
    assert!(offset_of!(ImageArm64RuntimeFunctionEntry, unwind_data) == 4);
    // One record type serves both architectures.
    assert!(
        offset_of!(ImageArmRuntimeFunctionEntry, begin_address)
            == offset_of!(ImageArm64RuntimeFunctionEntry, begin_address)
    );
    assert!(
        offset_of!(ImageArmRuntimeFunctionEntry, unwind_data)
            == offset_of!(ImageArm64RuntimeFunctionEntry, unwind_data)
    );
};

/// An ARM or ARM64 `.pdata` record of 8 bytes.
///
/// This type mirrors `IMAGE_ARM_RUNTIME_FUNCTION_ENTRY` and
/// `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY`. The low two bits of `unwind_data` select packed or
/// unpacked unwind information. The type keeps the complete word. Thus it supports both ARM
/// encodings and does not lose the architecture-specific packed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PackedRuntimeFunction {
    /// RVA of the first instruction in the function or fragment.
    ///
    /// For ARM NT, bit 0 is the Thumb bit. Linkers set it for Thumb code, so the value is
    /// odd. The function starts at `begin_address & !1`.
    pub begin_address: u32,
    /// The architecture-specific packed unwind word, or the exception data RVA plus flags.
    pub unwind_data: u32,
}

impl PackedRuntimeFunction {
    /// Size of one ARM/ARM64 `.pdata` record in bytes.
    pub const SIZE: usize = size_of::<ImageArm64RuntimeFunctionEntry>();

    /// Parse a record from little-endian bytes.
    ///
    /// # Errors
    /// Returns an error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }
        // Read the fields in the order of `ImageArm64RuntimeFunctionEntry`.
        let mut reader = data;
        Ok(Self {
            begin_address: reader.read_u32_le()?,
            unwind_data: reader.read_u32_le()?,
        })
    }

    /// Serialize to little-endian bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        for (offset, value) in [
            (
                offset_of!(ImageArm64RuntimeFunctionEntry, begin_address),
                self.begin_address,
            ),
            (
                offset_of!(ImageArm64RuntimeFunctionEntry, unwind_data),
                self.unwind_data,
            ),
        ] {
            bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    /// Return the low-bit discriminator (`Flag`) that the ARM exception ABI defines.
    ///
    /// - 0: `unwind_data` is the RVA of an `.xdata` record.
    /// - 1: packed unwind data.
    /// - 2: packed unwind data for a fragment without a prolog.
    /// - 3: ARM64 `.pdata` record link (reserved for ARM NT).
    #[must_use]
    pub const fn flag(self) -> u8 {
        // The low byte holds the two flag bits. A `const fn` cannot use `u8::try_from`.
        self.unwind_data.to_le_bytes()[0] & 0b11
    }

    /// Return the RVA of the external exception data record if [`Self::flag`] is zero.
    #[must_use]
    pub const fn exception_data_rva(self) -> Option<u32> {
        if self.flag() == 0 {
            Some(self.unwind_data & !0b11)
        } else {
            None
        }
    }

    /// Return the RVA of the parent `.pdata` record if [`Self::flag`] is 3.
    ///
    /// On ARM64, `Flag` 3 marks a record link: the record describes a jump island, and the
    /// upper 30 bits of `unwind_data` are the RVA of the `.pdata` record of its parent
    /// function. On ARM NT, `Flag` 3 is reserved.
    #[must_use]
    pub const fn parent_record_rva(self) -> Option<u32> {
        if self.flag() == 3 {
            Some(self.unwind_data & !0b11)
        } else {
            None
        }
    }

    /// Return `true` if this record encodes the unwind description directly.
    ///
    /// This is the case for [`Self::flag`] 1 and 2.
    #[must_use]
    pub const fn is_packed(self) -> bool {
        matches!(self.flag(), 1 | 2)
    }
}

/// An ARM-family exception directory with fixed-width packed records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackedExceptionDirectory {
    /// Runtime-function records in table order.
    pub functions: Vec<PackedRuntimeFunction>,
}

impl PackedExceptionDirectory {
    /// Parse an ARM-family `.pdata` table.
    ///
    /// The function calls `read_at_rva` one time for the complete table. For this call, `len`
    /// can be as large as `pdata_size`. The callback must return at least `len` bytes. Extra
    /// bytes are ignored.
    ///
    /// # Errors
    /// Returns an error if `pdata_size` is not a multiple of the record size
    /// or the table cannot be read.
    pub fn parse<F>(pdata_rva: u32, pdata_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if !(pdata_size as usize).is_multiple_of(PackedRuntimeFunction::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "ARM exception directory size {} is not a multiple of {}",
                pdata_size,
                PackedRuntimeFunction::SIZE
            )));
        }
        let table = crate::parse_utils::read_record_table(
            &read_at_rva,
            pdata_rva,
            pdata_size,
            PackedRuntimeFunction::SIZE,
            "exception table",
        )?;
        let mut functions = Vec::new();
        for bytes in table.as_chunks::<{ PackedRuntimeFunction::SIZE }>().0 {
            let function = PackedRuntimeFunction::parse(bytes)?;
            if function.begin_address != 0 || function.unwind_data != 0 {
                functions.push(function);
            }
        }
        Ok(Self { functions })
    }

    /// Serialize to bytes.
    ///
    /// # Panics
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("packed exception-directory build failed: use try_to_bytes()")
    }

    /// Serialize to bytes after validation.
    ///
    /// # Errors
    /// Returns an error if [`Self::validate`] fails.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let byte_size = self.byte_size()?;
        let mut bytes = Vec::with_capacity(byte_size);
        for function in &self.functions {
            bytes.extend_from_slice(&function.to_bytes());
        }
        Ok(bytes)
    }

    /// Return the table size in bytes. The size must fit in `u32`.
    fn byte_size(&self) -> Result<usize> {
        let byte_size = self
            .functions
            .len()
            .checked_mul(PackedRuntimeFunction::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("exception table size overflow"))?;
        u32::try_from(byte_size)
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok(byte_size)
    }

    /// Check the record order and the table size.
    ///
    /// The unwinder does a binary search on `begin_address`. Thus the records must be in
    /// strictly ascending `begin_address` order. The table size must fit in `u32`.
    ///
    /// # Errors
    /// Returns an error that describes the first violation.
    pub fn validate(&self) -> Result<()> {
        self.byte_size()?;
        for (index, pair) in self.functions.windows(2).enumerate() {
            if pair[1].begin_address <= pair[0].begin_address {
                return Err(Error::invalid_data_directory(format!(
                    "ARM runtime-function record {} is unsorted or a duplicate",
                    index + 1
                )));
            }
        }
        Ok(())
    }

    /// Sort the records by `begin_address`.
    pub fn sort(&mut self) {
        self.functions
            .sort_by_key(|function| function.begin_address);
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Whether the table has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

#[cfg(test)]
mod tests;
