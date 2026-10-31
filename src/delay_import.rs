//! Delay-load import directory parsing.
//!
//! The loader loads a delay-load import when the program first uses it, not at
//! program startup. Use delay-load imports for optional dependencies or to make
//! startup faster.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let delay_imports = pe.delay_imports()?;
//! for dll in &delay_imports.dlls {
//!     println!("Delay-load DLL: {}", dll.name);
//!     println!("  IAT RVA: {:#x}", dll.descriptor.import_address_table_rva);
//!     println!("  INT RVA: {:#x}", dll.descriptor.import_name_table_rva);
//! }
//! # Ok::<(), portex::Error>(())
//! ```

mod build;

pub use build::DelayImportBuilder;

use crate::import::{ImportThunk, NameAddress, ThunkWalker};
use crate::prelude::*;
use crate::{Error, Result};

/// The maximum number of descriptors in a delay-import table.
const MAX_DELAY_DESCRIPTORS: usize = 65_536;

/// Delay-load descriptor (`IMAGE_DELAYLOAD_DESCRIPTOR`).
///
/// The address fields are RVAs in the modern format. In the legacy format
/// ([`Self::uses_rvas`] returns `false`), they are VAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DelayLoadDescriptor {
    /// Attributes. Bit 0 set means that the address fields are RVAs.
    pub attributes: u32,
    /// Address of the DLL name.
    pub dll_name_rva: u32,
    /// Address of the module handle.
    pub module_handle_rva: u32,
    /// Address of the delay-load import address table (IAT).
    pub import_address_table_rva: u32,
    /// Address of the delay-load import name table (INT).
    pub import_name_table_rva: u32,
    /// Address of the bound delay-load import address table.
    pub bound_import_address_table_rva: u32,
    /// Address of the unload delay-load import address table.
    pub unload_information_table_rva: u32,
    /// Time stamp of the bound DLL. The value is 0 if the DLL is not bound.
    pub time_date_stamp: u32,
}

impl DelayLoadDescriptor {
    /// Size of the structure in bytes.
    pub const SIZE: usize = Self::SIZE_U32 as usize;
    /// [`Self::SIZE`] as a `u32`, for RVA arithmetic.
    const SIZE_U32: u32 = 32;

    /// Parse a descriptor from raw bytes.
    ///
    /// Use [`Self::is_null`] to find the null terminator.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        let mut fields = [0u32; 8];
        for (field, bytes) in fields.iter_mut().zip(data.as_chunks::<4>().0) {
            *field = u32::from_le_bytes(*bytes);
        }
        let [
            attributes,
            dll_name_rva,
            module_handle_rva,
            import_address_table_rva,
            import_name_table_rva,
            bound_import_address_table_rva,
            unload_information_table_rva,
            time_date_stamp,
        ] = fields;

        Ok(Self {
            attributes,
            dll_name_rva,
            module_handle_rva,
            import_address_table_rva,
            import_name_table_rva,
            bound_import_address_table_rva,
            unload_information_table_rva,
            time_date_stamp,
        })
    }

    /// Return `true` if all fields are zero: the descriptor is the null terminator.
    ///
    /// A descriptor with only some zero fields is malformed data. It is not an early end
    /// marker.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.to_array() == [0; Self::SIZE]
    }

    /// Return `true` if the descriptor address fields are RVAs (the modern format).
    #[must_use]
    pub fn uses_rvas(&self) -> bool {
        self.attributes & 1 != 0
    }

    /// Return the fields as the on-disk structure.
    fn to_array(self) -> [u8; Self::SIZE] {
        let fields = [
            self.attributes,
            self.dll_name_rva,
            self.module_handle_rva,
            self.import_address_table_rva,
            self.import_name_table_rva,
            self.bound_import_address_table_rva,
            self.unload_information_table_rva,
            self.time_date_stamp,
        ];
        let mut buf = [0u8; Self::SIZE];
        for (bytes, field) in buf.as_chunks_mut::<4>().0.iter_mut().zip(fields) {
            *bytes = field.to_le_bytes();
        }
        buf
    }

    /// Convert the VAs of a legacy descriptor to RVAs with `image_base`.
    fn convert_vas(&mut self, image_base: u64) -> Result<()> {
        for field in [
            &mut self.dll_name_rva,
            &mut self.module_handle_rva,
            &mut self.import_address_table_rva,
            &mut self.import_name_table_rva,
            &mut self.bound_import_address_table_rva,
            &mut self.unload_information_table_rva,
        ] {
            *field = va_field_to_rva(*field, image_base)?;
        }
        Ok(())
    }
}

/// A delay-loaded DLL with its descriptor, name, and imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayLoadedDll {
    /// The descriptor, as read from the image. The parser converts the VAs of a legacy
    /// descriptor to RVAs.
    ///
    /// [`DelayImportBuilder::keep_unchanged`] uses `import_address_table_rva` to keep the
    /// tables of this DLL. For a new DLL, the builder uses no field of the descriptor.
    pub descriptor: DelayLoadDescriptor,
    /// Resolved DLL name.
    pub name: String,
    /// Imported functions.
    pub imports: Vec<ImportThunk>,
}

/// Delay-load import directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelayImportDirectory {
    /// Delay-loaded DLLs.
    pub dlls: Vec<DelayLoadedDll>,
}

impl DelayImportDirectory {
    /// Parse the delay import directory.
    ///
    /// # Arguments
    /// * `rva` - RVA of the delay import directory.
    /// * `is_64bit` - `true` for a PE32+ image.
    /// * `read_fn` - Function that reads data at an RVA.
    ///
    /// The parse limits its output in the same way as [`crate::ImportTable::parse`]. An
    /// ordinal entry uses only the low 16 bits, as the loader does.
    ///
    /// # Errors
    ///
    /// Returns an error if one of these conditions occurs:
    ///
    /// - A descriptor, a thunk or a name cannot be read.
    /// - A descriptor has reserved attribute bits set or has no DLL name.
    /// - A name has more than 4096 bytes before its null terminator, or is not UTF-8.
    /// - A named thunk has a null hint/name address, or an address that is not in the image.
    /// - An RVA computation overflows.
    /// - The descriptor table has no null terminator.
    /// - The thunks or the names are more than the output limits.
    pub fn parse<F>(rva: u32, is_64bit: bool, read_fn: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_bounded(rva, None, 0, is_64bit, read_fn)
    }

    /// Parse delay imports. Convert legacy descriptors, which use VAs, to RVAs with
    /// `image_base`. `image_base` is the preferred or the runtime image base.
    ///
    /// In a legacy descriptor, the named entries of the import name table also hold VAs. The
    /// parser converts them in the same way.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse`]. Also returns an error if a nonzero legacy
    /// VA is less than `image_base`.
    pub fn parse_with_image_base<F>(
        rva: u32,
        image_base: u64,
        is_64bit: bool,
        read_fn: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_bounded(rva, None, image_base, is_64bit, read_fn)
    }

    /// Parse delay imports, and do not read descriptors past the data directory
    /// size `size`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse_with_image_base`]. Also returns an
    /// error if `size` is smaller than one descriptor, or if the descriptor table
    /// has no terminator in the first `size` bytes.
    pub fn parse_sized_with_image_base<F>(
        rva: u32,
        size: u32,
        image_base: u64,
        is_64bit: bool,
        read_fn: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if size < DelayLoadDescriptor::SIZE_U32 {
            return Err(Error::invalid_data_directory(format!(
                "delay-import directory is {size} bytes, expected at least {}",
                DelayLoadDescriptor::SIZE
            )));
        }
        Self::parse_bounded(rva, Some(size), image_base, is_64bit, read_fn)
    }

    fn parse_bounded<F>(
        rva: u32,
        directory_size: Option<u32>,
        image_base: u64,
        is_64bit: bool,
        read_fn: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut walker = ThunkWalker::new(&read_fn, is_64bit, "delay-import");
        let mut dlls = Vec::new();
        let mut offset = 0u32;

        for _ in 0..MAX_DELAY_DESCRIPTORS {
            if let Some(size) = directory_size {
                let end = offset
                    .checked_add(DelayLoadDescriptor::SIZE_U32)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("delay-import descriptor range overflow")
                    })?;
                if end > size {
                    return Err(Error::invalid_data_directory(
                        "delay-import descriptor table is missing a terminator within its directory",
                    ));
                }
            }
            let descriptor_rva = rva.checked_add(offset).ok_or_else(|| {
                Error::invalid_data_directory("delay-import descriptor RVA overflow")
            })?;
            let desc_data = read_fn(descriptor_rva, DelayLoadDescriptor::SIZE)
                .ok_or_else(|| Error::invalid_rva(descriptor_rva))?;
            let mut desc = DelayLoadDescriptor::parse(&desc_data)?;
            if desc.is_null() {
                return Ok(Self { dlls });
            }
            if desc.attributes & !1 != 0 {
                return Err(Error::invalid_data_directory(format!(
                    "delay-import descriptor has reserved attributes {:#x}",
                    desc.attributes
                )));
            }
            // In a legacy descriptor, the fields and the named INT entries are VAs.
            let names = if desc.uses_rvas() {
                NameAddress::Rva
            } else {
                desc.convert_vas(image_base)?;
                NameAddress::Va(image_base)
            };
            if desc.dll_name_rva == 0 {
                return Err(Error::invalid_data_directory(
                    "non-null delay-import descriptor has no DLL name",
                ));
            }

            let name = walker.dll_name(desc.dll_name_rva)?;
            // Parse the thunks from the INT (Import Name Table).
            let imports = if desc.import_name_table_rva == 0 {
                Vec::new()
            } else {
                walker.thunks(desc.import_name_table_rva, names)?
            };

            dlls.push(DelayLoadedDll {
                descriptor: desc,
                name,
                imports,
            });
            offset = offset
                .checked_add(DelayLoadDescriptor::SIZE_U32)
                .ok_or_else(|| {
                    Error::invalid_data_directory("delay-import descriptor table size overflow")
                })?;
        }

        Err(Error::invalid_data_directory(
            "delay-import descriptor table is missing a terminator",
        ))
    }
}

fn va_field_to_rva(value: u32, image_base: u64) -> Result<u32> {
    if value == 0 {
        return Ok(0);
    }
    u64::from(value)
        .checked_sub(image_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "legacy delay-import VA {value:#x} is outside image base {image_base:#x}"
            ))
        })
}

#[cfg(test)]
mod tests;
