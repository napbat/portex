//! x64 `RUNTIME_FUNCTION` records and the x64 exception directory.

use core::mem::{offset_of, size_of};

use nostdio::ReadLe;

use crate::prelude::*;
use crate::{Error, Result};

/// The layout of `IMAGE_RUNTIME_FUNCTION_ENTRY` (x64 `RUNTIME_FUNCTION`).
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror the BeginAddress/EndAddress/UnwindInfoAddress fields of winnt.h"
)]
pub(crate) struct ImageRuntimeFunctionEntry {
    pub(crate) begin_address: u32,
    pub(crate) end_address: u32,
    pub(crate) unwind_info_address: u32,
}

const _: () = {
    assert!(size_of::<ImageRuntimeFunctionEntry>() == 12);
    assert!(offset_of!(ImageRuntimeFunctionEntry, end_address) == 4);
    assert!(offset_of!(ImageRuntimeFunctionEntry, unwind_info_address) == 8);
};

/// An x64 `RUNTIME_FUNCTION` entry of 12 bytes.
///
/// The `.pdata` section uses these entries for exception handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror the BeginAddress/EndAddress/UnwindInfoAddress spec fields"
)]
pub struct RuntimeFunction {
    /// RVA of the start of the function.
    pub begin_address: u32,
    /// RVA of the end of the function.
    pub end_address: u32,
    /// RVA of the unwind information.
    pub unwind_info_address: u32,
}

impl RuntimeFunction {
    /// Size of one x64 `RUNTIME_FUNCTION` record in bytes.
    pub const SIZE: usize = size_of::<ImageRuntimeFunctionEntry>();

    /// Parse an entry from little-endian bytes.
    ///
    /// # Errors
    /// Returns an error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }
        // Read the fields in the order of `ImageRuntimeFunctionEntry`.
        let mut reader = data;
        Ok(Self {
            begin_address: reader.read_u32_le()?,
            end_address: reader.read_u32_le()?,
            unwind_info_address: reader.read_u32_le()?,
        })
    }

    /// Serialize the entry to little-endian bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        for (offset, value) in [
            (
                offset_of!(ImageRuntimeFunctionEntry, begin_address),
                self.begin_address,
            ),
            (
                offset_of!(ImageRuntimeFunctionEntry, end_address),
                self.end_address,
            ),
            (
                offset_of!(ImageRuntimeFunctionEntry, unwind_info_address),
                self.unwind_info_address,
            ),
        ] {
            buf[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
        }
        buf
    }

    /// Return the function size in bytes.
    #[must_use]
    pub fn size(self) -> u32 {
        self.end_address.saturating_sub(self.begin_address)
    }

    /// Return `true` if the function contains `rva`.
    #[must_use]
    pub fn contains_rva(self, rva: u32) -> bool {
        rva >= self.begin_address && rva < self.end_address
    }
}

/// The complete x64 exception directory (`.pdata`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExceptionDirectory {
    /// List of runtime function entries.
    pub functions: Vec<RuntimeFunction>,
}

impl ExceptionDirectory {
    /// Parse the x64 exception directory of a PE image.
    ///
    /// `pdata_rva` is the RVA of the table. `read_at_rva` reads bytes at an RVA.
    ///
    /// The function calls `read_at_rva` one time for the complete table. For this call, `len`
    /// can be as large as `pdata_size`. The callback must return at least `len` bytes. Extra
    /// bytes are ignored.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - `pdata_size` is not a multiple of the record size.
    /// - The table cannot be read.
    /// - The entries fail [`Self::validate`].
    pub fn parse<F>(pdata_rva: u32, pdata_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if !(pdata_size as usize).is_multiple_of(RuntimeFunction::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "x64 exception directory size {} is not a multiple of {}",
                pdata_size,
                RuntimeFunction::SIZE
            )));
        }
        let table = crate::parse_utils::read_record_table(
            &read_at_rva,
            pdata_rva,
            pdata_size,
            RuntimeFunction::SIZE,
            "exception table",
        )?;
        let mut functions = Vec::new();
        for data in table.as_chunks::<{ RuntimeFunction::SIZE }>().0 {
            let func = RuntimeFunction::parse(data)?;
            // Skip null entries.
            if func.begin_address != 0 || func.end_address != 0 {
                functions.push(func);
            }
        }

        let directory = Self { functions };
        directory.validate()?;
        Ok(directory)
    }

    /// Serialize to bytes.
    ///
    /// # Panics
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("exception-directory build failed: use try_to_bytes()")
    }

    /// Serialize to bytes after validation.
    ///
    /// # Errors
    /// Returns an error if [`Self::validate`] fails.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let byte_size = self.byte_size()?;
        let mut buf = Vec::with_capacity(byte_size);
        for func in &self.functions {
            buf.extend_from_slice(&func.to_bytes());
        }
        Ok(buf)
    }

    /// Return the table size in bytes.
    ///
    /// The size must fit in `u32`, because the data directory stores it as a `u32`.
    fn byte_size(&self) -> Result<usize> {
        let byte_size = self
            .functions
            .len()
            .checked_mul(RuntimeFunction::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("exception table size overflow"))?;
        u32::try_from(byte_size)
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok(byte_size)
    }

    /// Check the entries and the table size.
    ///
    /// Each entry must be nonempty. The entries must be sorted and must not overlap. The table
    /// size must fit in `u32`.
    ///
    /// # Errors
    /// Returns an error describing the first violation found.
    pub fn validate(&self) -> Result<()> {
        self.byte_size()?;

        let mut previous_end = 0u32;
        for (index, function) in self.functions.iter().enumerate() {
            if function.begin_address >= function.end_address {
                return Err(Error::invalid_data_directory(format!(
                    "exception function {index} has an empty or reversed range"
                )));
            }
            if index != 0 && function.begin_address < previous_end {
                return Err(Error::invalid_data_directory(format!(
                    "exception function {index} is unsorted or overlaps its predecessor"
                )));
            }
            previous_end = function.end_address;
        }
        Ok(())
    }

    /// Find the runtime function that contains `rva`.
    #[must_use]
    pub fn find_function(&self, rva: u32) -> Option<&RuntimeFunction> {
        self.functions.iter().find(|f| f.contains_rva(rva))
    }

    /// Return the number of functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Return `true` if the directory has no functions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Add a runtime function entry.
    ///
    /// `begin`, `end` and `unwind_info` are RVAs.
    pub fn add_function(&mut self, begin: u32, end: u32, unwind_info: u32) {
        self.functions.push(RuntimeFunction {
            begin_address: begin,
            end_address: end,
            unwind_info_address: unwind_info,
        });
    }

    /// Sort functions by begin address.
    pub fn sort(&mut self) {
        self.functions.sort_by_key(|f| f.begin_address);
    }
}

#[cfg(test)]
mod tests;
