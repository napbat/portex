//! Bound import directory parsing.
//!
//! Bound imports are a legacy optimization: the linker resolves import addresses before load
//! time. If the bound DLL did not change, the loader can skip address resolution.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! if let Some(bound) = pe.bound_imports()? {
//!     for desc in &bound.descriptors {
//!         println!("Bound import: {} (timestamp: {:#x})",
//!             desc.module_name, desc.time_date_stamp);
//!         for fwd in &desc.forwarder_refs {
//!             println!("  Forwarder: {} (timestamp: {:#x})",
//!                 fwd.module_name, fwd.time_date_stamp);
//!         }
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use core::mem::{offset_of, size_of};

use nostdio::{ReadLe, WriteLe};

use crate::import::{MAX_NAME_LEN, NameBudget};
use crate::prelude::*;
use crate::{Error, Result};

/// The layout of `IMAGE_BOUND_IMPORT_DESCRIPTOR`.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct ImageBoundImportDescriptor {
    time_date_stamp: u32,
    offset_module_name: u16,
    number_of_module_forwarder_refs: u16,
}

/// The layout of `IMAGE_BOUND_FORWARDER_REF`.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct ImageBoundForwarderRef {
    time_date_stamp: u32,
    offset_module_name: u16,
    reserved: u16,
}

const _: () = {
    assert!(size_of::<ImageBoundImportDescriptor>() == 8);
    assert!(offset_of!(ImageBoundImportDescriptor, offset_module_name) == 4);
    assert!(offset_of!(ImageBoundImportDescriptor, number_of_module_forwarder_refs) == 6);
    assert!(size_of::<ImageBoundForwarderRef>() == 8);
    assert!(offset_of!(ImageBoundForwarderRef, reserved) == 6);
};

/// A forwarder reference of a bound import (`IMAGE_BOUND_FORWARDER_REF`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundForwarderRef {
    /// Timestamp of the forwarder DLL.
    pub time_date_stamp: u32,
    /// Offset of the module name from the start of the bound import data. This is not an RVA.
    pub offset_module_name: u16,
    /// Reserved.
    pub reserved: u16,
    /// Module name, read from `offset_module_name`.
    pub module_name: String,
}

impl BoundForwarderRef {
    /// Size of the structure in bytes.
    pub const SIZE: usize = size_of::<ImageBoundForwarderRef>();

    /// Parse the structure from raw bytes. `module_name` stays empty.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        // Read the fields in the order of `ImageBoundForwarderRef`.
        let mut fields: &[u8] = data;
        Ok(Self {
            time_date_stamp: fields.read_u32_le()?,
            offset_module_name: fields.read_u16_le()?,
            reserved: fields.read_u16_le()?,
            module_name: String::new(), // Resolved later
        })
    }
}

/// A bound import descriptor (`IMAGE_BOUND_IMPORT_DESCRIPTOR`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundImportDescriptor {
    /// Timestamp of the bound DLL.
    pub time_date_stamp: u32,
    /// Offset of the module name from the start of the bound import data. This is not an RVA.
    pub offset_module_name: u16,
    /// Number of forwarder references.
    pub number_of_module_forwarder_refs: u16,
    /// Module name, read from `offset_module_name`.
    pub module_name: String,
    /// Forwarder references.
    pub forwarder_refs: Vec<BoundForwarderRef>,
}

impl BoundImportDescriptor {
    /// Size of the structure in bytes.
    pub const SIZE: usize = size_of::<ImageBoundImportDescriptor>();

    /// Parse the structure from raw bytes.
    ///
    /// `module_name` and `forwarder_refs` stay empty. Use [`Self::is_null`] to find the null
    /// terminator.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        // Read the fields in the order of `ImageBoundImportDescriptor`.
        let mut fields: &[u8] = data;
        Ok(Self {
            time_date_stamp: fields.read_u32_le()?,
            offset_module_name: fields.read_u16_le()?,
            number_of_module_forwarder_refs: fields.read_u16_le()?,
            module_name: String::new(), // Resolved later
            forwarder_refs: Vec::new(), // Parsed later
        })
    }

    /// Return `true` if the fields of the structure are zero: the descriptor is the null
    /// terminator.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.time_date_stamp == 0
            && self.offset_module_name == 0
            && self.number_of_module_forwarder_refs == 0
    }
}

/// Bound import directory: the data of the `BoundImport` data directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundImportDirectory {
    /// List of bound import descriptors.
    pub descriptors: Vec<BoundImportDescriptor>,
}

impl BoundImportDirectory {
    /// Parse the bound import directory from raw bytes.
    ///
    /// The parse limits its output. Each name has at most 4096 bytes. The name bytes of all
    /// records are at most 16 times the distinct source bytes of the names, or 1 MiB if that is
    /// larger. A name that many records share is read only one time.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - A descriptor or forwarder record is truncated.
    /// - A module-name offset is zero or out of range.
    /// - A name is not null-terminated within 4096 bytes.
    /// - The reserved field of a forwarder is not zero.
    /// - The directory has no null terminator.
    /// - The names are more than the output limit.
    ///
    /// Returns an invalid-UTF-8 error if a module name is not valid UTF-8.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut names = BoundNames {
            data,
            budget: NameBudget::default(),
            cache: BTreeMap::new(),
        };
        let mut descriptors = Vec::new();
        let mut offset = 0;

        // Parse each descriptor and the forwarder records that immediately follow it.
        while offset < data.len() {
            let descriptor_end = offset
                .checked_add(BoundImportDescriptor::SIZE)
                .ok_or_else(|| Error::invalid_data_directory("bound-import offset overflow"))?;
            let descriptor_bytes = data.get(offset..descriptor_end).ok_or_else(|| {
                Error::invalid_data_directory("truncated bound-import descriptor")
            })?;
            let mut desc = BoundImportDescriptor::parse(descriptor_bytes)?;
            if desc.is_null() {
                return Ok(Self { descriptors });
            }
            if desc.offset_module_name == 0 {
                return Err(Error::invalid_data_directory(
                    "bound-import descriptor has a zero module-name offset",
                ));
            }
            desc.module_name = names.read(desc.offset_module_name, "bound-import module")?;

            // Parse the forwarder references.
            let mut fwd_offset = descriptor_end;
            for _ in 0..desc.number_of_module_forwarder_refs {
                let fwd_end = fwd_offset
                    .checked_add(BoundForwarderRef::SIZE)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("bound-forwarder range overflow")
                    })?;
                let mut fwd =
                    BoundForwarderRef::parse(data.get(fwd_offset..fwd_end).ok_or_else(|| {
                        Error::invalid_data_directory("truncated bound-forwarder record")
                    })?)?;
                if fwd.reserved != 0 {
                    return Err(Error::invalid_data_directory(
                        "bound-forwarder reserved field must be zero",
                    ));
                }
                if fwd.offset_module_name == 0 {
                    return Err(Error::invalid_data_directory(
                        "bound-forwarder has a zero module-name offset",
                    ));
                }
                fwd.module_name = names.read(fwd.offset_module_name, "bound-forwarder module")?;
                desc.forwarder_refs.push(fwd);
                fwd_offset = fwd_end;
            }

            // Skip past the descriptor and its forwarder references.
            offset = fwd_offset;
            descriptors.push(desc);
        }

        Err(Error::invalid_data_directory(
            "bound-import directory is missing a terminator",
        ))
    }
}

/// A reader of the module names of a bound import directory, with a cache and a budget.
struct BoundNames<'a> {
    data: &'a [u8],
    budget: NameBudget,
    cache: BTreeMap<u16, String>,
}

impl BoundNames<'_> {
    /// Read the null-terminated name at `offset` in the directory data.
    fn read(&mut self, offset: u16, context: &str) -> Result<String> {
        let name = if let Some(name) = self.cache.get(&offset) {
            name.clone()
        } else {
            let start = usize::from(offset);
            let tail = self.data.get(start..).ok_or_else(|| {
                Error::invalid_data_directory(format!("{context} name is out of range"))
            })?;
            let window = tail.get(..=MAX_NAME_LEN).unwrap_or(tail);
            let name = core::ffi::CStr::from_bytes_until_nul(window).map_err(|_| {
                Error::invalid_data_directory(format!(
                    "{context} name is not null-terminated within {MAX_NAME_LEN} bytes"
                ))
            })?;
            let name = name.to_str().map_err(|_| Error::invalid_utf8())?;
            self.budget
                .add_source(u64::from(offset), name.len().saturating_add(1));
            self.cache.insert(offset, name.to_string());
            name.to_string()
        };
        self.budget.charge(name.len(), "bound-import")?;
        Ok(name)
    }
}

/// Builder that serializes bound import directories.
///
/// The builder has no state. Call its associated functions, for example
/// [`BoundImportBuilder::try_build`].
#[derive(Debug)]
pub struct BoundImportBuilder;

impl BoundImportBuilder {
    /// Calculate the total size needed for the bound import data.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(directory: &BoundImportDirectory) -> usize {
        Self::try_calculate_size(directory)
            .expect("bound-import size overflow: use try_calculate_size()")
    }

    /// Calculate the size, and validate the 16-bit name offsets and forwarder counts.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - A descriptor has more than `u16::MAX` forwarders.
    /// - The reserved field of a forwarder is not zero.
    /// - A module name is empty or contains NUL.
    /// - The size overflows.
    /// - The total is more than `u16::MAX` (the limit of the 16-bit name offsets).
    pub fn try_calculate_size(directory: &BoundImportDirectory) -> Result<usize> {
        if directory.descriptors.is_empty() {
            return Ok(0);
        }

        // Descriptors, forwarder references and the null terminator.
        let mut desc_size = BoundImportDescriptor::SIZE; // null terminator
        for desc in &directory.descriptors {
            u16::try_from(desc.forwarder_refs.len())
                .map_err(|_| Error::invalid_data_directory("bound-forwarder count exceeds u16"))?;
            if desc
                .forwarder_refs
                .iter()
                .any(|forwarder| forwarder.reserved != 0)
            {
                return Err(Error::invalid_data_directory(
                    "bound-forwarder reserved field must be zero",
                ));
            }
            desc_size = desc_size
                .checked_add(BoundImportDescriptor::SIZE)
                .and_then(|size| {
                    desc.forwarder_refs
                        .len()
                        .checked_mul(BoundForwarderRef::SIZE)
                        .and_then(|forwarders| size.checked_add(forwarders))
                })
                .ok_or_else(|| {
                    Error::invalid_data_directory("bound-import descriptor size overflow")
                })?;
        }

        // Module names (null-terminated strings).
        let mut names_size = 0usize;
        for desc in &directory.descriptors {
            names_size = checked_bound_name_size(names_size, &desc.module_name)?;
            for fwd in &desc.forwarder_refs {
                names_size = checked_bound_name_size(names_size, &fwd.module_name)?;
            }
        }

        let total = desc_size
            .checked_add(names_size)
            .ok_or_else(|| Error::invalid_data_directory("bound-import size overflow"))?;
        if total > usize::from(u16::MAX) {
            return Err(Error::invalid_data_directory(
                "bound-import directory exceeds its u16 name-offset format",
            ));
        }
        Ok(total)
    }

    /// Build the bound import data. Returns `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(directory: &BoundImportDirectory) -> (Vec<u8>, u32) {
        Self::try_build(directory)
            .expect("bound-import build failed: use try_build() for fallible serialization")
    }

    /// Build the bound import data, with checked relative offsets. Returns `(data, size)`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`]. Returns an invalid-data-directory
    /// error if the data size is more than `u32::MAX` or a name offset is more than `u16::MAX`.
    pub fn try_build(directory: &BoundImportDirectory) -> Result<(Vec<u8>, u32)> {
        if directory.descriptors.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let total_size = Self::try_calculate_size(directory)?;
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| Error::invalid_data_directory("bound-import data exceeds u32"))?;

        // The descriptors, the forwarder records and the null terminator come before the names.
        let strings_offset = directory
            .descriptors
            .iter()
            .try_fold(BoundImportDescriptor::SIZE, |size, desc| {
                desc.forwarder_refs
                    .len()
                    .checked_mul(BoundForwarderRef::SIZE)?
                    .checked_add(BoundImportDescriptor::SIZE)
                    .and_then(|records| size.checked_add(records))
            })
            .ok_or_else(|| {
                Error::invalid_data_directory("bound-import descriptor size overflow")
            })?;
        // Each name offset is relative to the start of the bound import data.
        let next_name_offset = |names: &[u8]| {
            strings_offset
                .checked_add(names.len())
                .and_then(|offset| u16::try_from(offset).ok())
        };

        let mut data = Vec::with_capacity(total_size);
        let mut names = Vec::new();
        for desc in &directory.descriptors {
            let name_offset = next_name_offset(&names).ok_or_else(|| {
                Error::invalid_data_directory("bound-import name offset exceeds u16")
            })?;
            let forwarder_count = u16::try_from(desc.forwarder_refs.len())
                .map_err(|_| Error::invalid_data_directory("bound-forwarder count exceeds u16"))?;
            // Write the fields in the order of `ImageBoundImportDescriptor`.
            data.write_u32_le(desc.time_date_stamp)?;
            data.write_u16_le(name_offset)?;
            data.write_u16_le(forwarder_count)?;
            names.extend_from_slice(desc.module_name.as_bytes());
            names.push(0);

            for fwd in &desc.forwarder_refs {
                let fwd_name_offset = next_name_offset(&names).ok_or_else(|| {
                    Error::invalid_data_directory("bound-forwarder name offset exceeds u16")
                })?;
                // Write the fields in the order of `ImageBoundForwarderRef`.
                data.write_u32_le(fwd.time_date_stamp)?;
                data.write_u16_le(fwd_name_offset)?;
                data.write_u16_le(fwd.reserved)?;
                names.extend_from_slice(fwd.module_name.as_bytes());
                names.push(0);
            }
        }

        // Add the null terminator descriptor, then the names.
        data.extend_from_slice(&[0; BoundImportDescriptor::SIZE]);
        data.extend_from_slice(&names);

        Ok((data, total_size_u32))
    }
}

fn checked_bound_name_size(current: usize, name: &str) -> Result<usize> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(Error::invalid_data_directory(
            "bound-import module names must be nonempty and contain no NUL bytes",
        ));
    }
    current
        .checked_add(
            name.len()
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("bound-import name size overflow"))?,
        )
        .ok_or_else(|| Error::invalid_data_directory("bound-import names size overflow"))
}

#[cfg(test)]
mod tests;
