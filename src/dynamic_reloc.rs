//! Read the dynamic value relocation table (DVRT).
//!
//! The load configuration locates the table by section number and offset
//! (`DynamicValueRelocTableSection` and `DynamicValueRelocTableOffset`). The table starts with
//! `IMAGE_DYNAMIC_RELOCATION_TABLE`. Version 1 then holds one record for each symbol
//! (`IMAGE_DYNAMIC_RELOCATION32` or `IMAGE_DYNAMIC_RELOCATION64`). The symbol selects the format
//! of the record body:
//!
//! - [`symbols::IMPORT_CONTROL_TRANSFER`]: base relocation blocks of 32-bit entries.
//! - [`symbols::FUNCTION_OVERRIDE`]: `IMAGE_FUNCTION_OVERRIDE_HEADER`, the override records and
//!   the BDD bytes.
//! - [`symbols::RF_PROLOGUE`], [`symbols::RF_EPILOGUE`], [`symbols::ARM64X`] and
//!   [`symbols::ARM64_KERNEL_IMPORT_CALL_TRANSFER`]: a body that this module does not decode.
//! - Each other symbol: base relocation blocks of 16-bit entries.
//!
//! The structures follow `winnt.h` of the Windows SDK 10.0.26100. This module reads only the
//! structure. It does not give a meaning to the bits of an entry.
//!
//! Each reader returns an [`ErrorKind::InvalidRva`](crate::ErrorKind::InvalidRva) error with the
//! RVA of a structure that is not completely in its parent, or whose size is not valid.

mod blocks;
mod function_override;
#[cfg(test)]
mod tests;

pub use blocks::{DynamicRelocationBlock, DynamicRelocationBlocks, DynamicRelocationEntries};
pub use function_override::{FunctionOverride, FunctionOverrideHeader, FunctionOverrides};

use core::mem::{offset_of, size_of};

use crate::parse_utils::{u32_at, u64_at};
use crate::prelude::*;
use crate::{Error, Result};

/// The layout of `IMAGE_DYNAMIC_RELOCATION_TABLE`.
#[repr(C)]
struct ImageDynamicRelocationTable {
    version: u32,
    size: u32,
}

/// The layout of `IMAGE_DYNAMIC_RELOCATION32`.
#[repr(C)]
struct ImageDynamicRelocation32 {
    symbol: u32,
    base_reloc_size: u32,
}

/// The layout of `IMAGE_DYNAMIC_RELOCATION64`. `winnt.h` packs it to 4 bytes.
#[repr(C, packed(4))]
struct ImageDynamicRelocation64 {
    symbol: u64,
    base_reloc_size: u32,
}

const _: () = {
    assert!(size_of::<ImageDynamicRelocationTable>() == 8);
    assert!(size_of::<ImageDynamicRelocation32>() == 8);
    assert!(size_of::<ImageDynamicRelocation64>() == 12);
    assert!(offset_of!(ImageDynamicRelocation64, base_reloc_size) == 8);
};

/// The reserved symbols (`IMAGE_DYNAMIC_RELOCATION_*`) of a version-1 record.
pub mod symbols {
    /// `IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE`.
    pub const RF_PROLOGUE: u64 = 1;
    /// `IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE`.
    pub const RF_EPILOGUE: u64 = 2;
    /// `IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER`.
    pub const IMPORT_CONTROL_TRANSFER: u64 = 3;
    /// `IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER`.
    pub const INDIR_CONTROL_TRANSFER: u64 = 4;
    /// `IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH`.
    pub const SWITCHTABLE_BRANCH: u64 = 5;
    /// `IMAGE_DYNAMIC_RELOCATION_ARM64X`.
    pub const ARM64X: u64 = 6;
    /// `IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE`.
    pub const FUNCTION_OVERRIDE: u64 = 7;
    /// `IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER`.
    pub const ARM64_KERNEL_IMPORT_CALL_TRANSFER: u64 = 8;
}

/// Return the RVA of the byte at `offset` after `rva`.
///
/// Each table that this module reads ends at an RVA that fits `u32`, so the sum does not
/// overflow. The function saturates to keep this rule without a panic.
fn rva_at(rva: u32, offset: usize) -> u32 {
    u32::try_from(offset)
        .ok()
        .and_then(|offset| rva.checked_add(offset))
        .unwrap_or(u32::MAX)
}

/// Return the error for the structure `name` at `rva`.
fn invalid(rva: u32, name: &str) -> Error {
    Error::invalid_rva(rva).in_structure(name)
}

/// The dynamic value relocation table (`IMAGE_DYNAMIC_RELOCATION_TABLE`) and its records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicRelocationTable {
    /// The RVA of the table header.
    rva: u32,
    /// `Version`.
    version: u32,
    /// `true` if the records have 64-bit symbols.
    is_64bit: bool,
    /// The `Size` bytes after the header of a version-1 table. Empty for another version.
    records: Vec<u8>,
}

impl DynamicRelocationTable {
    /// The size of `IMAGE_DYNAMIC_RELOCATION_TABLE` in bytes.
    pub const HEADER_SIZE: usize = size_of::<ImageDynamicRelocationTable>();

    /// Parse the table at the start of `data`. The table header is at `rva`.
    ///
    /// `is_64bit` selects 64-bit symbols (`IMAGE_DYNAMIC_RELOCATION64`). The function reads the
    /// records only for version 1, the only version with a known layout. For another version,
    /// [`Self::records`] returns an error.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidRva` error if `data` cannot hold the header or the records of a
    /// version-1 table, or if the records end after the last RVA.
    pub fn parse(data: &[u8], rva: u32, is_64bit: bool) -> Result<Self> {
        Self::read(rva, is_64bit, |at, len| {
            let start = usize::try_from(at.checked_sub(rva)?).ok()?;
            data.get(start..start.checked_add(len)?).map(<[u8]>::to_vec)
        })
    }

    /// Read the table at `rva` with `read`, which returns `len` bytes at an RVA.
    pub(crate) fn read(
        rva: u32,
        is_64bit: bool,
        read: impl Fn(u32, usize) -> Option<Vec<u8>>,
    ) -> Result<Self> {
        let name = "IMAGE_DYNAMIC_RELOCATION_TABLE";
        let header = read(rva, Self::HEADER_SIZE).ok_or_else(|| invalid(rva, name))?;
        let (Some(version), Some(size)) = (
            u32_at(&header, offset_of!(ImageDynamicRelocationTable, version)),
            u32_at(&header, offset_of!(ImageDynamicRelocationTable, size)),
        ) else {
            return Err(invalid(rva, name));
        };
        let mut table = Self {
            rva,
            version,
            is_64bit,
            records: Vec::new(),
        };
        if version != 1 {
            return Ok(table);
        }
        let records_rva = rva_at(rva, Self::HEADER_SIZE);
        let length = usize::try_from(size).map_err(|_| invalid(records_rva, name))?;
        if records_rva.checked_add(size).is_none() {
            return Err(invalid(records_rva, name));
        }
        table.records = read(records_rva, length).ok_or_else(|| invalid(records_rva, name))?;
        Ok(table)
    }

    /// Return the RVA of the table header.
    #[must_use]
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Return `Version`.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Return `true` if the records have 64-bit symbols.
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Return an iterator over the records of a version-1 table.
    ///
    /// The iterator reads one record at a time. It stops after the first error.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the table version is not 1.
    pub fn records(&self) -> Result<DynamicRelocations<'_>> {
        if self.version != 1 {
            return Err(Error::invalid_data_directory(format!(
                "dynamic value relocation table version {} is not supported",
                self.version
            )));
        }
        Ok(DynamicRelocations {
            data: &self.records,
            rva: rva_at(self.rva, Self::HEADER_SIZE),
            is_64bit: self.is_64bit,
            position: 0,
            done: false,
        })
    }
}

/// An iterator over the records of a version-1 dynamic value relocation table.
#[derive(Debug, Clone)]
pub struct DynamicRelocations<'a> {
    /// The records.
    data: &'a [u8],
    /// The RVA of the first record.
    rva: u32,
    /// `true` if the records have 64-bit symbols.
    is_64bit: bool,
    /// The offset of the next record in `data`.
    position: usize,
    /// `true` after the last record or an error.
    done: bool,
}

impl<'a> DynamicRelocations<'a> {
    /// Read the record at the current position.
    fn read_record(&mut self) -> Result<DynamicRelocation<'a>> {
        let (name, header_size) = if self.is_64bit {
            (
                "IMAGE_DYNAMIC_RELOCATION64",
                size_of::<ImageDynamicRelocation64>(),
            )
        } else {
            (
                "IMAGE_DYNAMIC_RELOCATION32",
                size_of::<ImageDynamicRelocation32>(),
            )
        };
        let rva = rva_at(self.rva, self.position);
        let fail = || invalid(rva, name);
        let header_end = self.position.checked_add(header_size).ok_or_else(fail)?;
        let header = self.data.get(self.position..header_end).ok_or_else(fail)?;
        let (symbol, size) = if self.is_64bit {
            (
                u64_at(header, offset_of!(ImageDynamicRelocation64, symbol)),
                u32_at(
                    header,
                    offset_of!(ImageDynamicRelocation64, base_reloc_size),
                ),
            )
        } else {
            (
                u32_at(header, offset_of!(ImageDynamicRelocation32, symbol)).map(u64::from),
                u32_at(
                    header,
                    offset_of!(ImageDynamicRelocation32, base_reloc_size),
                ),
            )
        };
        let (Some(symbol), Some(size)) = (symbol, size) else {
            return Err(fail());
        };
        let body_end = usize::try_from(size)
            .ok()
            .and_then(|size| header_end.checked_add(size))
            .ok_or_else(fail)?;
        let body = self.data.get(header_end..body_end).ok_or_else(fail)?;
        self.position = body_end;
        Ok(DynamicRelocation {
            rva,
            symbol,
            body,
            body_rva: rva_at(self.rva, header_end),
        })
    }
}

impl<'a> Iterator for DynamicRelocations<'a> {
    type Item = Result<DynamicRelocation<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.position >= self.data.len() {
            return None;
        }
        let record = self.read_record();
        self.done = record.is_err();
        Some(record)
    }
}

/// One record of a version-1 table (`IMAGE_DYNAMIC_RELOCATION32` or
/// `IMAGE_DYNAMIC_RELOCATION64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicRelocation<'a> {
    /// The RVA of the record header.
    rva: u32,
    /// `Symbol`.
    symbol: u64,
    /// The `BaseRelocSize` bytes after the record header.
    body: &'a [u8],
    /// The RVA of the body.
    body_rva: u32,
}

impl<'a> DynamicRelocation<'a> {
    /// Return the RVA of the record header.
    #[must_use]
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Return `Symbol`. See [`symbols`] for the reserved values.
    #[must_use]
    pub fn symbol(&self) -> u64 {
        self.symbol
    }

    /// Return the bytes of the body (`BaseRelocSize` bytes).
    #[must_use]
    pub fn raw_body(&self) -> &'a [u8] {
        self.body
    }

    /// Return the RVA of the body.
    #[must_use]
    pub fn body_rva(&self) -> u32 {
        self.body_rva
    }

    /// Decode the body in the format that the symbol selects.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidRva` error if the body of a function override cannot hold
    /// `IMAGE_FUNCTION_OVERRIDE_HEADER` or the override records that it states.
    pub fn body(&self) -> Result<DynamicRelocationBody<'a>> {
        Ok(match self.symbol {
            symbols::RF_PROLOGUE
            | symbols::RF_EPILOGUE
            | symbols::ARM64X
            | symbols::ARM64_KERNEL_IMPORT_CALL_TRANSFER => DynamicRelocationBody::Raw(self.body),
            symbols::IMPORT_CONTROL_TRANSFER => DynamicRelocationBody::Blocks(
                DynamicRelocationBlocks::new(self.body, self.body_rva, 4),
            ),
            symbols::FUNCTION_OVERRIDE => DynamicRelocationBody::FunctionOverride(
                FunctionOverrideHeader::parse(self.body, self.body_rva)?,
            ),
            _ => DynamicRelocationBody::Blocks(DynamicRelocationBlocks::new(
                self.body,
                self.body_rva,
                2,
            )),
        })
    }
}

/// The decoded body of one record.
#[derive(Debug, Clone)]
pub enum DynamicRelocationBody<'a> {
    /// Base relocation blocks. The entries have 32 bits for
    /// [`symbols::IMPORT_CONTROL_TRANSFER`] and 16 bits for each other symbol.
    Blocks(DynamicRelocationBlocks<'a>),
    /// The body of [`symbols::FUNCTION_OVERRIDE`].
    FunctionOverride(FunctionOverrideHeader<'a>),
    /// A body that this module does not decode.
    Raw(&'a [u8]),
}
