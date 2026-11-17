//! CLR (Common Language Runtime) header parsing.
//!
//! This module gives minimal CLR header parsing for .NET assemblies. Data directory index 14
//! (`ClrRuntime`) gives the location of the CLI header (`IMAGE_COR20_HEADER`).
//!
//! For full metadata parsing (BSJB, streams, tables), see the `clrmeta` crate.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! if let Some(cli) = pe.clr_header()? {
//!     println!("CLR runtime: {}.{}", cli.major_runtime_version, cli.minor_runtime_version);
//!     println!("Metadata RVA: {:#x}, size: {}", cli.metadata_rva, cli.metadata_size);
//!     println!("Entry point token: {:#x}", cli.entry_point_token_or_rva);
//!     if cli.is_il_only() {
//!         println!("IL-only assembly");
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// CLI header (`IMAGE_COR20_HEADER`).
///
/// This 72-byte structure is the entry point for .NET metadata. The data directory
/// `DataDirectoryType::ClrRuntime` (index 14) gives its location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CliHeader {
    /// The size of the header in bytes (always 72).
    pub cb: u32,
    /// The major runtime version that the assembly requires.
    pub major_runtime_version: u16,
    /// The minor runtime version that the assembly requires.
    pub minor_runtime_version: u16,
    /// The RVA of the metadata (BSJB).
    pub metadata_rva: u32,
    /// The size of the metadata in bytes.
    pub metadata_size: u32,
    /// The flags (`COMIMAGE_FLAGS_*`).
    pub flags: u32,
    /// The entry point token (`MethodDef` or `File`), or the RVA of the native entry point.
    pub entry_point_token_or_rva: u32,
    /// The RVA of the resources.
    pub resources_rva: u32,
    /// The size of the resources in bytes.
    pub resources_size: u32,
    /// The RVA of the strong name signature.
    pub strong_name_signature_rva: u32,
    /// The size of the strong name signature in bytes.
    pub strong_name_signature_size: u32,
    /// The RVA of the code manager table (reserved).
    pub code_manager_table_rva: u32,
    /// The size of the code manager table in bytes.
    pub code_manager_table_size: u32,
    /// The RVA of the `VTable` fixups.
    pub vtable_fixups_rva: u32,
    /// The size of the `VTable` fixups in bytes.
    pub vtable_fixups_size: u32,
    /// The RVA of the export address table jumps.
    pub export_address_table_jumps_rva: u32,
    /// The size of the export address table jumps in bytes.
    pub export_address_table_jumps_size: u32,
    /// The RVA of the managed native header (reserved).
    pub managed_native_header_rva: u32,
    /// The size of the managed native header in bytes.
    pub managed_native_header_size: u32,
}

impl CliHeader {
    /// Size of the CLI header in bytes.
    pub const SIZE: usize = 72;
    /// Size of the CLI header in bytes, as the `u32` stored in `cb`.
    pub const SIZE_U32: u32 = 72;

    /// `COMIMAGE_FLAGS_ILONLY`: the image contains only IL code.
    pub const FLAG_ILONLY: u32 = 0x0000_0001;
    /// `COMIMAGE_FLAGS_32BITREQUIRED`: the image requires a 32-bit platform.
    pub const FLAG_32BITREQUIRED: u32 = 0x0000_0002;
    /// `COMIMAGE_FLAGS_IL_LIBRARY`: the image is an IL library, not an executable.
    pub const FLAG_IL_LIBRARY: u32 = 0x0000_0004;
    /// `COMIMAGE_FLAGS_STRONGNAMESIGNED`: the image has a strong name signature.
    pub const FLAG_STRONGNAMESIGNED: u32 = 0x0000_0008;
    /// `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT`: the entry point is a native RVA, not a token.
    pub const FLAG_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
    /// `COMIMAGE_FLAGS_TRACKDEBUGDATA`: track debug data.
    pub const FLAG_TRACKDEBUGDATA: u32 = 0x0001_0000;
    /// `COMIMAGE_FLAGS_32BITPREFERRED`: the image prefers a 32-bit platform.
    pub const FLAG_32BITPREFERRED: u32 = 0x0002_0000;

    /// Parse a CLI header from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BufferTooSmall`](crate::error::ErrorKind::BufferTooSmall)
    /// if `data` is shorter than 72 bytes, and
    /// [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if the declared `cb` is smaller than 72.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };
        let read_u16 =
            |offset: usize| -> u16 { u16::from_le_bytes([data[offset], data[offset + 1]]) };

        let cb = read_u32(0);
        if cb < Self::SIZE_U32 {
            return Err(Error::invalid_data_directory(format!(
                "CLR header declares size {}, expected at least {}",
                cb,
                Self::SIZE
            )));
        }

        Ok(Self {
            cb,
            major_runtime_version: read_u16(4),
            minor_runtime_version: read_u16(6),
            metadata_rva: read_u32(8),
            metadata_size: read_u32(12),
            flags: read_u32(16),
            entry_point_token_or_rva: read_u32(20),
            resources_rva: read_u32(24),
            resources_size: read_u32(28),
            strong_name_signature_rva: read_u32(32),
            strong_name_signature_size: read_u32(36),
            code_manager_table_rva: read_u32(40),
            code_manager_table_size: read_u32(44),
            vtable_fixups_rva: read_u32(48),
            vtable_fixups_size: read_u32(52),
            export_address_table_jumps_rva: read_u32(56),
            export_address_table_jumps_size: read_u32(60),
            managed_native_header_rva: read_u32(64),
            managed_native_header_size: read_u32(68),
        })
    }

    /// Return `true` if the assembly contains only IL code.
    #[must_use]
    pub fn is_il_only(&self) -> bool {
        self.flags & Self::FLAG_ILONLY != 0
    }

    /// Return `true` if the assembly requires a 32-bit platform.
    #[must_use]
    pub fn is_32bit_required(&self) -> bool {
        self.flags & Self::FLAG_32BITREQUIRED != 0
    }

    /// Return `true` if the assembly prefers a 32-bit platform.
    #[must_use]
    pub fn is_32bit_preferred(&self) -> bool {
        self.flags & Self::FLAG_32BITPREFERRED != 0
    }

    /// Return `true` if the assembly has a strong name signature.
    #[must_use]
    pub fn is_strong_name_signed(&self) -> bool {
        self.flags & Self::FLAG_STRONGNAMESIGNED != 0
    }

    /// Return `true` if the entry point is a native RVA, not a metadata token.
    #[must_use]
    pub fn has_native_entry_point(&self) -> bool {
        self.flags & Self::FLAG_NATIVE_ENTRYPOINT != 0
    }

    /// Serialize the CLI header to a 72-byte array.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];

        data[0..4].copy_from_slice(&self.cb.to_le_bytes());
        data[4..6].copy_from_slice(&self.major_runtime_version.to_le_bytes());
        data[6..8].copy_from_slice(&self.minor_runtime_version.to_le_bytes());
        data[8..12].copy_from_slice(&self.metadata_rva.to_le_bytes());
        data[12..16].copy_from_slice(&self.metadata_size.to_le_bytes());
        data[16..20].copy_from_slice(&self.flags.to_le_bytes());
        data[20..24].copy_from_slice(&self.entry_point_token_or_rva.to_le_bytes());
        data[24..28].copy_from_slice(&self.resources_rva.to_le_bytes());
        data[28..32].copy_from_slice(&self.resources_size.to_le_bytes());
        data[32..36].copy_from_slice(&self.strong_name_signature_rva.to_le_bytes());
        data[36..40].copy_from_slice(&self.strong_name_signature_size.to_le_bytes());
        data[40..44].copy_from_slice(&self.code_manager_table_rva.to_le_bytes());
        data[44..48].copy_from_slice(&self.code_manager_table_size.to_le_bytes());
        data[48..52].copy_from_slice(&self.vtable_fixups_rva.to_le_bytes());
        data[52..56].copy_from_slice(&self.vtable_fixups_size.to_le_bytes());
        data[56..60].copy_from_slice(&self.export_address_table_jumps_rva.to_le_bytes());
        data[60..64].copy_from_slice(&self.export_address_table_jumps_size.to_le_bytes());
        data[64..68].copy_from_slice(&self.managed_native_header_rva.to_le_bytes());
        data[68..72].copy_from_slice(&self.managed_native_header_size.to_le_bytes());

        data
    }
}

impl Default for CliHeader {
    fn default() -> Self {
        Self {
            cb: Self::SIZE_U32,
            major_runtime_version: 2,
            minor_runtime_version: 5,
            metadata_rva: 0,
            metadata_size: 0,
            flags: 0,
            entry_point_token_or_rva: 0,
            resources_rva: 0,
            resources_size: 0,
            strong_name_signature_rva: 0,
            strong_name_signature_size: 0,
            code_manager_table_rva: 0,
            code_manager_table_size: 0,
            vtable_fixups_rva: 0,
            vtable_fixups_size: 0,
            export_address_table_jumps_rva: 0,
            export_address_table_jumps_size: 0,
            managed_native_header_rva: 0,
            managed_native_header_size: 0,
        }
    }
}

/// A builder for CLI headers.
///
/// This builder gives a fluent interface to build CLI (COR20) headers for .NET assemblies.
///
/// # Example
///
/// ```
/// use portex::clr::{CliBuilder, CliHeader};
///
/// let mut builder = CliBuilder::new();
///
/// builder
///     .metadata(0x2000, 0x1234)
///     .entry_point_token(0x0600_0001)
///     .il_only(true);
///
/// let (data, size) = builder.build();
/// assert_eq!(size, CliHeader::SIZE as u32);
/// ```
#[derive(Debug, Clone, Default)]
pub struct CliBuilder {
    header: CliHeader,
}

impl CliBuilder {
    /// Create a CLI builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: CliHeader::default(),
        }
    }

    /// Create a builder from an existing CLI header.
    #[must_use]
    pub fn from_header(header: CliHeader) -> Self {
        Self { header }
    }

    /// Set the metadata RVA and size.
    pub fn metadata(&mut self, rva: u32, size: u32) -> &mut Self {
        self.header.metadata_rva = rva;
        self.header.metadata_size = size;
        self
    }

    /// Set the entry point token (`MethodDef` or `File` token).
    pub fn entry_point_token(&mut self, token: u32) -> &mut Self {
        self.header.entry_point_token_or_rva = token;
        self.header.flags &= !CliHeader::FLAG_NATIVE_ENTRYPOINT;
        self
    }

    /// Set the RVA of the native entry point. Mixed-mode assemblies use this, but it is rare.
    pub fn native_entry_point(&mut self, rva: u32) -> &mut Self {
        self.header.entry_point_token_or_rva = rva;
        self.header.flags |= CliHeader::FLAG_NATIVE_ENTRYPOINT;
        self
    }

    /// Set whether the assembly is IL-only.
    pub fn il_only(&mut self, value: bool) -> &mut Self {
        if value {
            self.header.flags |= CliHeader::FLAG_ILONLY;
        } else {
            self.header.flags &= !CliHeader::FLAG_ILONLY;
        }
        self
    }

    /// Set whether the assembly requires a 32-bit platform.
    pub fn requires_32bit(&mut self, value: bool) -> &mut Self {
        if value {
            self.header.flags |= CliHeader::FLAG_32BITREQUIRED;
        } else {
            self.header.flags &= !CliHeader::FLAG_32BITREQUIRED;
        }
        self
    }

    /// Set whether the assembly prefers a 32-bit platform.
    pub fn prefers_32bit(&mut self, value: bool) -> &mut Self {
        if value {
            self.header.flags |= CliHeader::FLAG_32BITPREFERRED;
        } else {
            self.header.flags &= !CliHeader::FLAG_32BITPREFERRED;
        }
        self
    }

    /// Set the resources RVA and size.
    pub fn resources(&mut self, rva: u32, size: u32) -> &mut Self {
        self.header.resources_rva = rva;
        self.header.resources_size = size;
        self
    }

    /// Set the RVA and size of the strong name signature.
    pub fn strong_name_signature(&mut self, rva: u32, size: u32) -> &mut Self {
        self.header.strong_name_signature_rva = rva;
        self.header.strong_name_signature_size = size;
        self
    }

    /// Set the RVA and size of the `VTable` fixups.
    pub fn vtable_fixups(&mut self, rva: u32, size: u32) -> &mut Self {
        self.header.vtable_fixups_rva = rva;
        self.header.vtable_fixups_size = size;
        self
    }

    /// Set the raw flags value.
    pub fn flags(&mut self, flags: u32) -> &mut Self {
        self.header.flags = flags;
        self
    }

    /// Build the CLI header. Returns `(data, size)`.
    #[must_use]
    pub fn build(&self) -> (Vec<u8>, u32) {
        let data = self.header.to_bytes().to_vec();
        (data, CliHeader::SIZE_U32)
    }

    /// Return the built header.
    #[must_use]
    pub fn into_header(self) -> CliHeader {
        self.header
    }
}

#[cfg(test)]
mod tests;
