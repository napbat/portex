//! Export table parsing and building.
//!
//! This module reads and writes PE export tables. An export table holds the export directory
//! (`IMAGE_EXPORT_DIRECTORY`) and the exported functions.
//!
//! # Examples
//!
//! ## Listing exports from a DLL
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let exports = pe.exports()?;
//! println!("DLL name: {}", exports.dll_name);
//! println!("Ordinal base: {}", exports.directory.base);
//!
//! for func in &exports.exports {
//!     let name = func.name.as_deref().unwrap_or("<unnamed>");
//!     let addr = match &func.address {
//!         portex::ExportAddress::Rva(rva) => format!("{:#x}", rva),
//!         portex::ExportAddress::Forwarder(s) => s.clone(),
//!     };
//!     println!("  {} (ordinal {}): {}", name, func.ordinal, addr);
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Creating a DLL with exports
//!
//! ```no_run
//! use portex::{ExportTable, PeImage};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Build the export table.
//! let mut exports = ExportTable::default();
//! exports.dll_name = "mylib.dll".to_string();
//! exports.directory.base = 1;
//! exports.add_export(Some("MyFunction1"), 0x1000);
//! exports.add_export(Some("MyFunction2"), 0x2000);
//! exports.add_export(None, 0x3000); // No name, only an ordinal.
//!
//! // Put the new exports into the PE image.
//! pe.update_exports(&exports, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// The maximum length of a DLL name or a function name in an export table.
///
/// This limit covers all valid Windows symbol names. It also stops unbounded reads on malformed
/// PE files.
const MAX_NAME_LEN: usize = 4096;
const MAX_EXPORT_FUNCTIONS: u32 = 1_048_576;

/// `IMAGE_EXPORT_DIRECTORY`: the 40-byte header of the export data directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportDirectory {
    /// Export flags. Reserved, must be 0.
    pub characteristics: u32,
    /// The time and date stamp.
    pub time_date_stamp: u32,
    /// The major version.
    pub major_version: u16,
    /// The minor version.
    pub minor_version: u16,
    /// The RVA of the DLL name.
    pub name_rva: u32,
    /// The first ordinal number.
    pub base: u32,
    /// The number of entries in the export address table (EAT).
    pub number_of_functions: u32,
    /// The number of entries in the name pointer table.
    pub number_of_names: u32,
    /// The RVA of the export address table (EAT).
    pub address_of_functions: u32,
    /// The RVA of the export name pointer table.
    pub address_of_names: u32,
    /// The RVA of the export ordinal table.
    pub address_of_name_ordinals: u32,
}

impl ExportDirectory {
    /// Size of a serialized `IMAGE_EXPORT_DIRECTORY` in bytes.
    pub const SIZE: usize = 40;

    /// Parse an export directory from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::buffer_too_small`] if `data` is shorter than
    /// [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(d) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        Ok(Self {
            characteristics: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
            time_date_stamp: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
            major_version: u16::from_le_bytes([d[8], d[9]]),
            minor_version: u16::from_le_bytes([d[10], d[11]]),
            name_rva: u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
            base: u32::from_le_bytes([d[16], d[17], d[18], d[19]]),
            number_of_functions: u32::from_le_bytes([d[20], d[21], d[22], d[23]]),
            number_of_names: u32::from_le_bytes([d[24], d[25], d[26], d[27]]),
            address_of_functions: u32::from_le_bytes([d[28], d[29], d[30], d[31]]),
            address_of_names: u32::from_le_bytes([d[32], d[33], d[34], d[35]]),
            address_of_name_ordinals: u32::from_le_bytes([d[36], d[37], d[38], d[39]]),
        })
    }

    /// Write the export directory to a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::buffer_too_small`] if `buf` is shorter than
    /// [`Self::SIZE`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let buf_len = buf.len();
        let Some(out) = buf.first_chunk_mut::<{ ExportDirectory::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, buf_len));
        };
        self.encode(out);
        Ok(())
    }

    /// Serialize the export directory to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; ExportDirectory::SIZE];
        self.encode(&mut buf);
        buf.to_vec()
    }

    fn encode(&self, buf: &mut [u8; ExportDirectory::SIZE]) {
        buf[0..4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.name_rva.to_le_bytes());
        buf[16..20].copy_from_slice(&self.base.to_le_bytes());
        buf[20..24].copy_from_slice(&self.number_of_functions.to_le_bytes());
        buf[24..28].copy_from_slice(&self.number_of_names.to_le_bytes());
        buf[28..32].copy_from_slice(&self.address_of_functions.to_le_bytes());
        buf[32..36].copy_from_slice(&self.address_of_names.to_le_bytes());
        buf[36..40].copy_from_slice(&self.address_of_name_ordinals.to_le_bytes());
    }
}

/// One exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedFunction {
    /// The ordinal number.
    pub ordinal: u32,
    /// The function name, if the function is exported by name.
    pub name: Option<String>,
    /// More names that resolve to the same ordinal and EAT slot.
    pub aliases: Vec<String>,
    /// The RVA of the function, or the forwarder name.
    pub address: ExportAddress,
}

/// The address of an exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportAddress {
    /// The RVA of the function.
    Rva(u32),
    /// A forwarder to a function in another DLL (for example "NTDLL.RtlAllocateHeap").
    Forwarder(String),
}

/// The complete export table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportTable {
    /// The export directory header.
    pub directory: ExportDirectory,
    /// The DLL name.
    pub dll_name: String,
    /// The exported functions.
    pub exports: Vec<ExportedFunction>,
}

impl ExportTable {
    /// Return `true` if the export table has no exports.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }

    /// Find an export by name or by alias.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&ExportedFunction> {
        self.exports.iter().find(|export| {
            export.name.as_deref() == Some(name) || export.aliases.iter().any(|alias| alias == name)
        })
    }

    /// Find an export by ordinal.
    #[must_use]
    pub fn find_by_ordinal(&self, ordinal: u32) -> Option<&ExportedFunction> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }

    /// Add an exported function at an RVA.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_add_export`] returns an error.
    pub fn add_export(&mut self, name: Option<&str>, rva: u32) {
        self.try_add_export(name, rva)
            .expect("export ordinal overflow: use try_add_export()");
    }

    /// Add an exported function at an RVA.
    ///
    /// The new export gets the ordinal after the highest existing ordinal.
    /// If the table has no exports, the new export gets the ordinal base.
    ///
    /// # Errors
    ///
    /// Returns [`Error::invalid_data_directory`] if the highest existing
    /// ordinal is `u32::MAX`.
    pub fn try_add_export(&mut self, name: Option<&str>, rva: u32) -> Result<()> {
        self.push_export(name, ExportAddress::Rva(rva))
    }

    /// Add a forwarded export.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_add_forwarder`] returns an error.
    pub fn add_forwarder(&mut self, name: Option<&str>, forward_to: &str) {
        self.try_add_forwarder(name, forward_to)
            .expect("export ordinal overflow: use try_add_forwarder()");
    }

    /// Add a forwarded export.
    ///
    /// The new export gets the ordinal after the highest existing ordinal.
    /// If the table has no exports, the new export gets the ordinal base.
    ///
    /// # Errors
    ///
    /// Returns [`Error::invalid_data_directory`] if the highest existing
    /// ordinal is `u32::MAX`.
    pub fn try_add_forwarder(&mut self, name: Option<&str>, forward_to: &str) -> Result<()> {
        self.push_export(name, ExportAddress::Forwarder(forward_to.to_string()))
    }

    /// Push an export with the next free ordinal.
    fn push_export(&mut self, name: Option<&str>, address: ExportAddress) -> Result<()> {
        let ordinal = match self.exports.iter().map(|e| e.ordinal).max() {
            None => self.directory.base,
            Some(highest) => highest
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?,
        };
        self.exports.push(ExportedFunction {
            ordinal,
            name: name.map(str::to_string),
            aliases: Vec::new(),
            address,
        });
        Ok(())
    }

    /// Set the DLL name.
    pub fn set_dll_name(&mut self, name: &str) {
        self.dll_name = name.to_string();
    }

    /// Set the ordinal base.
    pub fn set_base(&mut self, base: u32) {
        self.directory.base = base;
    }
}

mod builder;
mod parse;

pub use builder::ExportTableBuilder;

#[cfg(test)]
mod tests;
