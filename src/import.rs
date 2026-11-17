//! Import table parsing and building.
//!
//! This module has types to read and write PE import tables. These types are the import
//! descriptors, the thunks and the full import table.
//!
//! # Examples
//!
//! ## Listing imports from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let imports = pe.imports()?;
//! for dll in &imports.dlls {
//!     println!("DLL: {}", dll.name);
//!     for thunk in &dll.imports {
//!         match thunk {
//!             portex::ImportThunk::Name { hint, name } => {
//!                 println!("  {} (hint: {})", name, hint);
//!             }
//!             portex::ImportThunk::Ordinal(ordinal) => {
//!                 println!("  Ordinal #{}", ordinal);
//!             }
//!         }
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Adding new imports to a PE file
//!
//! Start from the imports of the image. Then each DLL that you do not change keeps its import
//! address table (IAT), and the existing code that calls through it continues to work.
//!
//! ```no_run
//! use portex::{ImportThunk, PeImage};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Add a new DLL to the existing imports.
//! let mut imports = pe.imports()?;
//! imports.add_dll("user32.dll", vec![
//!     ImportThunk::Name { hint: 0, name: "MessageBoxA".to_string() },
//! ]);
//!
//! // Update the PE image with the new imports.
//! pe.update_imports(&imports, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

mod budget;
mod build;
mod parts;
mod walk;

pub(crate) use budget::{MAX_NAME_LEN, NameBudget};
pub use build::ImportTableBuilder;
pub(crate) use parts::{skip_to_even, split_parts};
pub(crate) use walk::{NameAddress, ThunkWalker};

use core::mem::{offset_of, size_of};

use nostdio::ReadLe;

use crate::parse_utils::{le_u32, put_u32};
use crate::prelude::*;
use crate::{Error, Result};

/// The maximum number of descriptors in an import table.
const MAX_IMPORT_DESCRIPTORS: usize = 65_536;
/// `IMAGE_ORDINAL_FLAG32`: high bit of a PE32 thunk marks an import by ordinal.
pub(crate) const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;
/// `IMAGE_ORDINAL_FLAG64`: high bit of a PE32+ thunk marks an import by ordinal.
pub(crate) const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// The layout of `IMAGE_IMPORT_DESCRIPTOR`.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
pub(crate) struct ImageImportDescriptor {
    /// `OriginalFirstThunk`, in a union with `Characteristics`.
    pub(crate) original_first_thunk: u32,
    pub(crate) time_date_stamp: u32,
    pub(crate) forwarder_chain: u32,
    pub(crate) name: u32,
    pub(crate) first_thunk: u32,
}

/// The layout of `IMAGE_THUNK_DATA32`: one union of 32-bit values.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct ImageThunkData32 {
    /// `u1`: `ForwarderString`, `Function`, `Ordinal` or `AddressOfData`.
    u1: u32,
}

/// The layout of `IMAGE_THUNK_DATA64`: one union of 64-bit values.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct ImageThunkData64 {
    /// `u1`: `ForwarderString`, `Function`, `Ordinal` or `AddressOfData`.
    u1: u64,
}

/// The layout of `IMAGE_IMPORT_BY_NAME`.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
pub(crate) struct ImageImportByName {
    pub(crate) hint: u16,
    /// The first byte of the null-terminated name.
    pub(crate) name: [u8; 1],
}

const _: () = {
    assert!(size_of::<ImageImportDescriptor>() == 20);
    assert!(offset_of!(ImageImportDescriptor, name) == 12);
    assert!(offset_of!(ImageImportDescriptor, first_thunk) == 16);
    assert!(size_of::<ImageThunkData32>() == 4);
    assert!(size_of::<ImageThunkData64>() == 8);
    assert!(offset_of!(ImageImportByName, name) == 2);
    assert!(size_of::<ImageImportDescriptor>() == size_of::<[u32; 5]>());
};

/// The size of the fixed header of `IMAGE_IMPORT_BY_NAME`: the hint before the name.
pub(crate) const HINT_SIZE: usize = offset_of!(ImageImportByName, name);

/// Return the size in bytes of one thunk (`IMAGE_THUNK_DATA64` for PE32+,
/// `IMAGE_THUNK_DATA32` for PE32).
pub(crate) const fn thunk_size(is_64bit: bool) -> usize {
    if is_64bit {
        size_of::<ImageThunkData64>()
    } else {
        size_of::<ImageThunkData32>()
    }
}

/// Read the thunk value at `offset` of `data`: a `u64` for PE32+, a `u32` for PE32.
///
/// Return `None` if `data` does not hold the complete thunk.
pub(crate) fn thunk_at(data: &[u8], offset: usize, is_64bit: bool) -> Option<u64> {
    // A thunk list is a run of thunks up to a zero thunk; the walker reads it with a cursor.
    let mut rest = data.get(offset..)?;
    if is_64bit {
        rest.read_u64_le().ok()
    } else {
        rest.read_u32_le().ok().map(u64::from)
    }
}

/// Import descriptor (`IMAGE_IMPORT_DESCRIPTOR`).
///
/// One descriptor describes one imported DLL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportDescriptor {
    /// RVA of the Import Lookup Table (ILT), also known as the Import Name Table (INT).
    pub original_first_thunk: u32,
    /// Time stamp. The value is 0 if the imports are not bound.
    pub time_date_stamp: u32,
    /// Forwarder chain index. The value is -1 if there are no forwarders.
    pub forwarder_chain: u32,
    /// RVA of the DLL name (a null-terminated string).
    pub name_rva: u32,
    /// RVA of the Import Address Table (IAT).
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// Size of the on-disk structure in bytes.
    pub const SIZE: usize = size_of::<ImageImportDescriptor>();
    /// [`Self::SIZE`] as a `u32`, for RVA arithmetic.
    ///
    /// The structure is five `u32` fields; a const assert below checks this against
    /// [`Self::SIZE`].
    const SIZE_U32: u32 = 5 * (u32::BITS / u8::BITS);

    /// Return `true` if all fields are zero.
    ///
    /// A linker writes such a descriptor at the end of the table. The loader ends the table
    /// earlier, at the first descriptor for which [`Self::is_terminator`] returns `true`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.first_thunk == 0
    }

    /// Return `true` if the loader ends the descriptor table at this descriptor: `Name` or
    /// `FirstThunk` is zero.
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        self.name_rva == 0 || self.first_thunk == 0
    }

    /// Parse a descriptor from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        type Mirror = ImageImportDescriptor;
        const N: usize = ImportDescriptor::SIZE;
        let Some(raw) = data.first_chunk::<N>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };
        Ok(Self {
            original_first_thunk: le_u32::<N, { offset_of!(Mirror, original_first_thunk) }>(raw),
            time_date_stamp: le_u32::<N, { offset_of!(Mirror, time_date_stamp) }>(raw),
            forwarder_chain: le_u32::<N, { offset_of!(Mirror, forwarder_chain) }>(raw),
            name_rva: le_u32::<N, { offset_of!(Mirror, name) }>(raw),
            first_thunk: le_u32::<N, { offset_of!(Mirror, first_thunk) }>(raw),
        })
    }

    /// Write the descriptor to a buffer.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `buf` is shorter than [`Self::SIZE`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let Some(buf) = buf.first_chunk_mut::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, len));
        };
        *buf = self.to_array();
        Ok(())
    }

    /// Serialize the descriptor to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_array().to_vec()
    }

    /// Return the fields as the on-disk structure.
    fn to_array(&self) -> [u8; Self::SIZE] {
        type Mirror = ImageImportDescriptor;
        const N: usize = ImportDescriptor::SIZE;
        let mut raw = [0u8; N];
        put_u32::<N, { offset_of!(Mirror, original_first_thunk) }>(
            &mut raw,
            self.original_first_thunk,
        );
        put_u32::<N, { offset_of!(Mirror, time_date_stamp) }>(&mut raw, self.time_date_stamp);
        put_u32::<N, { offset_of!(Mirror, forwarder_chain) }>(&mut raw, self.forwarder_chain);
        put_u32::<N, { offset_of!(Mirror, name) }>(&mut raw, self.name_rva);
        put_u32::<N, { offset_of!(Mirror, first_thunk) }>(&mut raw, self.first_thunk);
        raw
    }
}

/// Import thunk entry. The entry is an import by ordinal or an import by name.
///
/// The import table and the delay-import table use this type for their entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportThunk {
    /// Import by ordinal number.
    Ordinal(u16),
    /// Import by name, with a hint.
    Name {
        /// Index into the export name pointer table of the exporting DLL. The loader tries
        /// this index first when it resolves the name.
        hint: u16,
        /// Imported function name.
        name: String,
    },
}

impl ImportThunk {
    /// Return `true` if a PE32 thunk value is an import by ordinal (high bit set).
    #[must_use]
    pub fn is_ordinal_entry_32(value: u32) -> bool {
        value & IMAGE_ORDINAL_FLAG32 != 0
    }

    /// Return `true` if a PE32+ thunk value is an import by ordinal (high bit set).
    #[must_use]
    pub fn is_ordinal_entry_64(value: u64) -> bool {
        value & IMAGE_ORDINAL_FLAG64 != 0
    }

    /// Get the ordinal from a PE32 thunk value.
    ///
    /// Use only the low 16 bits, as the loader does (`IMAGE_ORDINAL32`).
    #[must_use]
    pub fn ordinal_from_32(value: u32) -> u16 {
        // The mask keeps the value in `u16`, so the conversion cannot fail.
        u16::try_from(value & u32::from(u16::MAX)).unwrap_or_default()
    }

    /// Get the ordinal from a PE32+ thunk value.
    ///
    /// Use only the low 16 bits, as the loader does (`IMAGE_ORDINAL64`).
    #[must_use]
    pub fn ordinal_from_64(value: u64) -> u16 {
        // The mask keeps the value in `u16`, so the conversion cannot fail.
        u16::try_from(value & u64::from(u16::MAX)).unwrap_or_default()
    }

    /// Get the RVA of the hint/name entry from a PE32 thunk value.
    #[must_use]
    pub fn hint_name_rva_from_32(value: u32) -> u32 {
        value & 0x7FFF_FFFF
    }

    /// Get the RVA of the hint/name entry from a PE32+ thunk value.
    #[must_use]
    pub fn hint_name_rva_from_64(value: u64) -> u32 {
        // The mask keeps the value in `u32`, so the conversion cannot fail.
        u32::try_from(value & 0x7FFF_FFFF).unwrap_or_default()
    }
}

/// One imported DLL with its imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedDll {
    /// The DLL name.
    pub name: String,
    /// Import descriptor, as read from the image.
    ///
    /// [`ImportTableBuilder::keep_unchanged_iats`] uses `first_thunk` to keep the IAT of this
    /// DLL. For a new DLL, use the default value.
    pub descriptor: ImportDescriptor,
    /// Imported functions.
    pub imports: Vec<ImportThunk>,
}

/// A full import table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportTable {
    /// Imported DLLs.
    pub dlls: Vec<ImportedDll>,
}

impl ImportTable {
    /// Parse an import table from a PE file.
    ///
    /// `import_rva` is the RVA from the import data directory. `read_at_rva` is a closure
    /// that reads bytes at an RVA.
    ///
    /// The table ends at the first descriptor with a zero `Name` or a zero `FirstThunk`, as
    /// in the Windows loader. See [`ImportDescriptor::is_terminator`].
    ///
    /// The parse limits its output, so that a small malformed table cannot make a very large
    /// result. The thunks of all descriptors together are at most 1,048,576 entries. The name
    /// bytes are at most 16 times the distinct source bytes of the names, or 1 MiB if that is
    /// larger. A thunk table or a name that many descriptors share is read only one time.
    ///
    /// # Errors
    ///
    /// Returns an error if one of these conditions occurs:
    ///
    /// - A descriptor, a thunk or a name cannot be read.
    /// - A name has more than 4096 bytes before its null terminator, or is not UTF-8.
    /// - A named thunk has a null hint/name RVA, or a PE32+ hint/name RVA that is not in the
    ///   image.
    /// - An RVA computation overflows.
    /// - The descriptor table has no terminator.
    /// - The thunks or the names are more than the output limits.
    pub fn parse<F>(import_rva: u32, is_64bit: bool, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_bounded(import_rva, None, is_64bit, read_at_rva)
    }

    /// Parse an import descriptor table, and do not read descriptors past its
    /// data directory size.
    ///
    /// Names and thunk arrays can be in other parts of the image. The PE format
    /// permits this.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse`]. Also returns an error if
    /// `import_size` is smaller than one descriptor, or if the descriptor table
    /// has no terminator in the first `import_size` bytes.
    pub fn parse_sized<F>(
        import_rva: u32,
        import_size: u32,
        is_64bit: bool,
        read_at_rva: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if import_size < ImportDescriptor::SIZE_U32 {
            return Err(Error::invalid_data_directory(format!(
                "import directory is {import_size} bytes, expected at least {}",
                ImportDescriptor::SIZE
            )));
        }
        Self::parse_bounded(import_rva, Some(import_size), is_64bit, read_at_rva)
    }

    fn parse_bounded<F>(
        import_rva: u32,
        import_size: Option<u32>,
        is_64bit: bool,
        read_at_rva: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut walker = ThunkWalker::new(&read_at_rva, is_64bit, "import");
        let mut dlls = Vec::new();
        let mut offset = 0u32;

        for _ in 0..MAX_IMPORT_DESCRIPTORS {
            if let Some(size) = import_size {
                let end = offset
                    .checked_add(ImportDescriptor::SIZE_U32)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("import descriptor range overflow")
                    })?;
                if end > size {
                    return Err(Error::invalid_data_directory(
                        "import descriptor table is missing a terminator within its directory",
                    ));
                }
            }
            // Read the import descriptor.
            let descriptor_rva = import_rva
                .checked_add(offset)
                .ok_or_else(|| Error::invalid_data_directory("import descriptor RVA overflow"))?;
            let desc_data = read_at_rva(descriptor_rva, ImportDescriptor::SIZE)
                .ok_or(Error::invalid_rva(descriptor_rva))?;
            let descriptor = ImportDescriptor::parse(&desc_data)?;
            if descriptor.is_terminator() {
                return Ok(Self { dlls });
            }

            let name = walker.dll_name(descriptor.name_rva)?;
            // Without an ILT, the IAT holds the thunks on disk.
            let thunk_rva = if descriptor.original_first_thunk != 0 {
                descriptor.original_first_thunk
            } else {
                descriptor.first_thunk
            };
            let imports = walker.thunks(thunk_rva, NameAddress::Rva)?;

            dlls.push(ImportedDll {
                name,
                descriptor,
                imports,
            });

            offset = offset
                .checked_add(ImportDescriptor::SIZE_U32)
                .ok_or_else(|| {
                    Error::invalid_data_directory("import descriptor table size overflow")
                })?;
        }

        Err(Error::invalid_data_directory(
            "import descriptor table is missing a terminator",
        ))
    }

    /// Return `true` if the import table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dlls.is_empty()
    }

    /// Find a DLL by name (case-insensitive).
    #[must_use]
    pub fn find_dll(&self, name: &str) -> Option<&ImportedDll> {
        self.dlls
            .iter()
            .find(|dll| dll.name.eq_ignore_ascii_case(name))
    }

    /// Get the total number of imported functions.
    #[must_use]
    pub fn import_count(&self) -> usize {
        self.dlls.iter().map(|dll| dll.imports.len()).sum()
    }

    /// Add a new DLL with its imports.
    pub fn add_dll(&mut self, name: &str, imports: Vec<ImportThunk>) {
        self.dlls.push(ImportedDll {
            name: name.to_string(),
            descriptor: ImportDescriptor::default(),
            imports,
        });
    }

    /// Add an import to an existing DLL. If the DLL does not exist, add the DLL.
    ///
    /// An import for an existing DLL changes its function list. A rebuilt table then gives
    /// that DLL a new IAT. See [`ImportTableBuilder`].
    pub fn add_import(&mut self, dll_name: &str, import: ImportThunk) {
        if let Some(dll) = self
            .dlls
            .iter_mut()
            .find(|d| d.name.eq_ignore_ascii_case(dll_name))
        {
            dll.imports.push(import);
        } else {
            self.add_dll(dll_name, vec![import]);
        }
    }

    /// Add an import by name.
    pub fn add_named_import(&mut self, dll_name: &str, func_name: &str, hint: u16) {
        self.add_import(
            dll_name,
            ImportThunk::Name {
                hint,
                name: func_name.to_string(),
            },
        );
    }

    /// Add an import by ordinal.
    pub fn add_ordinal_import(&mut self, dll_name: &str, ordinal: u16) {
        self.add_import(dll_name, ImportThunk::Ordinal(ordinal));
    }
}

#[cfg(test)]
mod tests;
