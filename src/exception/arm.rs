//! ARM and ARM64 `.pdata` records and their exception directory.

use crate::prelude::*;
use crate::{Error, Result};

/// An ARM or ARM64 `.pdata` record of 8 bytes.
///
/// This type mirrors `IMAGE_ARM_RUNTIME_FUNCTION_ENTRY` and
/// `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY`. The low two bits of `unwind_data` select packed or
/// unpacked unwind information. The type keeps the complete word. Thus it supports both ARM
/// encodings and does not lose the architecture-specific packed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PackedRuntimeFunction {
    /// RVA of the first instruction in the function or fragment.
    pub begin_address: u32,
    /// The architecture-specific packed unwind word, or the exception data RVA plus flags.
    pub unwind_data: u32,
}

impl PackedRuntimeFunction {
    /// Size of one ARM/ARM64 `.pdata` record in bytes.
    pub const SIZE: usize = 8;

    /// Parse a record from little-endian bytes.
    ///
    /// # Errors
    /// Returns an error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };
        Ok(Self {
            begin_address: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            unwind_data: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    /// Serialize to little-endian bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[..4].copy_from_slice(&self.begin_address.to_le_bytes());
        bytes[4..].copy_from_slice(&self.unwind_data.to_le_bytes());
        bytes
    }

    /// Return the low-bit discriminator that the ARM exception ABI defines.
    #[must_use]
    pub const fn flag(self) -> u8 {
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

    /// Return `true` if this record encodes the unwind description directly.
    #[must_use]
    pub const fn is_packed(self) -> bool {
        self.flag() != 0
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

    /// Serialize to bytes.
    ///
    /// # Errors
    /// Returns an error if the table size exceeds `u32`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let byte_size = self
            .functions
            .len()
            .checked_mul(PackedRuntimeFunction::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("exception table size overflow"))?;
        u32::try_from(byte_size)
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        let mut bytes = Vec::with_capacity(byte_size);
        for function in &self.functions {
            bytes.extend_from_slice(&function.to_bytes());
        }
        Ok(bytes)
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
mod tests {
    use super::*;

    #[test]
    fn huge_declared_size_does_not_reserve_memory() {
        // The largest multiple of 8 in a `u32`. Before the fix, `parse` reserved 4 GiB for
        // this size, and the reservation panicked on 32-bit targets.
        let size = u32::MAX - u32::MAX % 8;
        let result = PackedExceptionDirectory::parse(0x1000, size, |_, _| None);
        assert!(result.is_err());
    }
}
