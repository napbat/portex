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

use core::mem::{offset_of, size_of};

use crate::parse_utils::{le_u16, le_u32, put_u16, put_u32};
use crate::prelude::*;
use crate::{Error, Result};

/// The layout of `IMAGE_DATA_DIRECTORY`.
///
/// Portex does not read the structure through this type. The type gives the offset and the width
/// of each field.
#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

/// The layout of `IMAGE_COR20_HEADER`.
///
/// Portex does not read the structure through this type. The type gives the offset and the width
/// of each field.
#[repr(C)]
struct ImageCor20Header {
    cb: u32,
    major_runtime_version: u16,
    minor_runtime_version: u16,
    meta_data: ImageDataDirectory,
    flags: u32,
    entry_point_token: u32,
    resources: ImageDataDirectory,
    strong_name_signature: ImageDataDirectory,
    code_manager_table: ImageDataDirectory,
    vtable_fixups: ImageDataDirectory,
    export_address_table_jumps: ImageDataDirectory,
    managed_native_header: ImageDataDirectory,
}

const _: () = {
    assert!(size_of::<ImageDataDirectory>() == 8);
    assert!(size_of::<ImageCor20Header>() == 0x48);
    assert!(offset_of!(ImageCor20Header, meta_data) == 0x08);
    assert!(offset_of!(ImageCor20Header, entry_point_token) == 0x14);
    assert!(offset_of!(ImageCor20Header, managed_native_header.size) == 0x44);
    assert!(CliHeader::SIZE_U32 as usize == CliHeader::SIZE);
};

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
    pub const SIZE: usize = size_of::<ImageCor20Header>();
    /// Size of the CLI header in bytes, as the `u32` stored in `cb`. A compile-time assertion
    /// keeps it equal to [`Self::SIZE`].
    pub const SIZE_U32: u32 = 0x48;

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
        type H = ImageCor20Header;
        const N: usize = CliHeader::SIZE;
        let Some(raw) = data.first_chunk::<N>() else {
            return Err(Error::buffer_too_small(N, data.len()));
        };

        let cb = le_u32::<N, { offset_of!(H, cb) }>(raw);
        if cb < Self::SIZE_U32 {
            return Err(Error::invalid_data_directory(format!(
                "CLR header declares size {}, expected at least {}",
                cb,
                Self::SIZE
            )));
        }

        Ok(Self {
            cb,
            major_runtime_version: le_u16::<N, { offset_of!(H, major_runtime_version) }>(raw),
            minor_runtime_version: le_u16::<N, { offset_of!(H, minor_runtime_version) }>(raw),
            metadata_rva: le_u32::<N, { offset_of!(H, meta_data.virtual_address) }>(raw),
            metadata_size: le_u32::<N, { offset_of!(H, meta_data.size) }>(raw),
            flags: le_u32::<N, { offset_of!(H, flags) }>(raw),
            entry_point_token_or_rva: le_u32::<N, { offset_of!(H, entry_point_token) }>(raw),
            resources_rva: le_u32::<N, { offset_of!(H, resources.virtual_address) }>(raw),
            resources_size: le_u32::<N, { offset_of!(H, resources.size) }>(raw),
            strong_name_signature_rva: le_u32::<
                N,
                { offset_of!(H, strong_name_signature.virtual_address) },
            >(raw),
            strong_name_signature_size: le_u32::<N, { offset_of!(H, strong_name_signature.size) }>(
                raw,
            ),
            code_manager_table_rva: le_u32::<
                N,
                { offset_of!(H, code_manager_table.virtual_address) },
            >(raw),
            code_manager_table_size: le_u32::<N, { offset_of!(H, code_manager_table.size) }>(raw),
            vtable_fixups_rva: le_u32::<N, { offset_of!(H, vtable_fixups.virtual_address) }>(raw),
            vtable_fixups_size: le_u32::<N, { offset_of!(H, vtable_fixups.size) }>(raw),
            export_address_table_jumps_rva: le_u32::<
                N,
                { offset_of!(H, export_address_table_jumps.virtual_address) },
            >(raw),
            export_address_table_jumps_size: le_u32::<
                N,
                { offset_of!(H, export_address_table_jumps.size) },
            >(raw),
            managed_native_header_rva: le_u32::<
                N,
                { offset_of!(H, managed_native_header.virtual_address) },
            >(raw),
            managed_native_header_size: le_u32::<N, { offset_of!(H, managed_native_header.size) }>(
                raw,
            ),
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
        type H = ImageCor20Header;
        const N: usize = CliHeader::SIZE;
        let mut data = [0u8; N];

        put_u32::<N, { offset_of!(H, cb) }>(&mut data, self.cb);
        let major = self.major_runtime_version;
        put_u16::<N, { offset_of!(H, major_runtime_version) }>(&mut data, major);
        let minor = self.minor_runtime_version;
        put_u16::<N, { offset_of!(H, minor_runtime_version) }>(&mut data, minor);
        let pairs: [(u32, u32); 7] = [
            (self.metadata_rva, self.metadata_size),
            (self.resources_rva, self.resources_size),
            (
                self.strong_name_signature_rva,
                self.strong_name_signature_size,
            ),
            (self.code_manager_table_rva, self.code_manager_table_size),
            (self.vtable_fixups_rva, self.vtable_fixups_size),
            (
                self.export_address_table_jumps_rva,
                self.export_address_table_jumps_size,
            ),
            (
                self.managed_native_header_rva,
                self.managed_native_header_size,
            ),
        ];
        let [meta, res, sn, cm, vt, eat, mnh] = pairs;
        put_u32::<N, { offset_of!(H, meta_data.virtual_address) }>(&mut data, meta.0);
        put_u32::<N, { offset_of!(H, meta_data.size) }>(&mut data, meta.1);
        put_u32::<N, { offset_of!(H, flags) }>(&mut data, self.flags);
        let entry = self.entry_point_token_or_rva;
        put_u32::<N, { offset_of!(H, entry_point_token) }>(&mut data, entry);
        put_u32::<N, { offset_of!(H, resources.virtual_address) }>(&mut data, res.0);
        put_u32::<N, { offset_of!(H, resources.size) }>(&mut data, res.1);
        put_u32::<N, { offset_of!(H, strong_name_signature.virtual_address) }>(&mut data, sn.0);
        put_u32::<N, { offset_of!(H, strong_name_signature.size) }>(&mut data, sn.1);
        put_u32::<N, { offset_of!(H, code_manager_table.virtual_address) }>(&mut data, cm.0);
        put_u32::<N, { offset_of!(H, code_manager_table.size) }>(&mut data, cm.1);
        put_u32::<N, { offset_of!(H, vtable_fixups.virtual_address) }>(&mut data, vt.0);
        put_u32::<N, { offset_of!(H, vtable_fixups.size) }>(&mut data, vt.1);
        put_u32::<N, { offset_of!(H, export_address_table_jumps.virtual_address) }>(
            &mut data, eat.0,
        );
        put_u32::<N, { offset_of!(H, export_address_table_jumps.size) }>(&mut data, eat.1);
        put_u32::<N, { offset_of!(H, managed_native_header.virtual_address) }>(&mut data, mnh.0);
        put_u32::<N, { offset_of!(H, managed_native_header.size) }>(&mut data, mnh.1);

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
