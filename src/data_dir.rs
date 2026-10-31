//! Data directory structures and parsing.

use crate::prelude::*;
use crate::reader::ReadAt;
use crate::{Error, Result};

/// The type of a data directory, as a type-safe index into the data directory table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum DataDirectoryType {
    /// Export table (.edata)
    Export = 0,
    /// Import table (.idata)
    Import = 1,
    /// Resource table (.rsrc)
    Resource = 2,
    /// Exception table (.pdata)
    Exception = 3,
    /// Certificate (security) table. Its `virtual_address` is a file offset, not an RVA.
    Security = 4,
    /// Base relocation table (.reloc)
    BaseReloc = 5,
    /// Debug directory
    Debug = 6,
    /// Architecture-specific data.
    Architecture = 7,
    /// The RVA of the value for the global pointer register.
    GlobalPtr = 8,
    /// Thread local storage (.tls)
    Tls = 9,
    /// Load configuration
    LoadConfig = 10,
    /// Bound import table
    BoundImport = 11,
    /// Import address table
    Iat = 12,
    /// Delay import descriptor
    DelayImport = 13,
    /// CLR runtime header
    ClrRuntime = 14,
    /// Reserved
    Reserved = 15,
}

impl DataDirectoryType {
    /// Get the index of this directory type.
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }

    /// Make a directory type from an index. Returns `None` if the index is not in 0..16.
    #[must_use]
    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Export),
            1 => Some(Self::Import),
            2 => Some(Self::Resource),
            3 => Some(Self::Exception),
            4 => Some(Self::Security),
            5 => Some(Self::BaseReloc),
            6 => Some(Self::Debug),
            7 => Some(Self::Architecture),
            8 => Some(Self::GlobalPtr),
            9 => Some(Self::Tls),
            10 => Some(Self::LoadConfig),
            11 => Some(Self::BoundImport),
            12 => Some(Self::Iat),
            13 => Some(Self::DelayImport),
            14 => Some(Self::ClrRuntime),
            15 => Some(Self::Reserved),
            _ => None,
        }
    }

    /// Get the name of this directory type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Export => "Export",
            Self::Import => "Import",
            Self::Resource => "Resource",
            Self::Exception => "Exception",
            Self::Security => "Security",
            Self::BaseReloc => "BaseReloc",
            Self::Debug => "Debug",
            Self::Architecture => "Architecture",
            Self::GlobalPtr => "GlobalPtr",
            Self::Tls => "TLS",
            Self::LoadConfig => "LoadConfig",
            Self::BoundImport => "BoundImport",
            Self::Iat => "IAT",
            Self::DelayImport => "DelayImport",
            Self::ClrRuntime => "CLR",
            Self::Reserved => "Reserved",
        }
    }

    /// Iterate over all directory types.
    pub fn all() -> impl Iterator<Item = Self> {
        (0..16).filter_map(Self::from_index)
    }
}

/// Number of data directory entries that the PE format defines.
///
/// This is `IMAGE_NUMBEROF_DIRECTORY_ENTRIES`. The value is the same for PE32 and PE32+. An
/// optional header can declare fewer entries in `NumberOfRvaAndSizes`.
pub const NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;

/// Data Directory entry (`IMAGE_DATA_DIRECTORY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct DataDirectory {
    /// The start address of the table. This is an RVA for all entries but
    /// [`DataDirectoryType::Security`]: for that entry, it is a file offset.
    pub virtual_address: u32,
    /// Size of the table in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Size of a data directory entry in bytes.
    pub const SIZE: usize = 8;

    /// Parse a data directory from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let bytes = data
            .first_chunk::<{ Self::SIZE }>()
            .ok_or_else(|| Error::buffer_too_small(Self::SIZE, data.len()))?;
        Ok(Self::from_bytes(*bytes))
    }

    /// Decode a data directory from its 8-byte on-disk layout.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let [a0, a1, a2, a3, s0, s1, s2, s3] = bytes;
        Self {
            virtual_address: u32::from_le_bytes([a0, a1, a2, a3]),
            size: u32::from_le_bytes([s0, s1, s2, s3]),
        }
    }

    /// Write the data directory to a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `buf` is shorter than [`Self::SIZE`].
    pub fn write(self, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let out = buf
            .first_chunk_mut::<{ Self::SIZE }>()
            .ok_or_else(|| Error::buffer_too_small(Self::SIZE, len))?;
        *out = self.to_bytes();
        Ok(())
    }

    /// Serialize to a byte array.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.virtual_address.to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());
        buf
    }

    /// Check if this directory entry is present (the address or the size is not zero).
    #[must_use]
    pub fn is_present(self) -> bool {
        self.virtual_address != 0 || self.size != 0
    }

    /// Parse a data directory from a positional reader at the reader offset `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::SIZE`] bytes cannot be read at `offset`.
    pub fn read_from<R: ReadAt>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Read `count` consecutive data directories from a positional reader, starting at the
    /// reader offset `offset`.
    ///
    /// The method reserves memory only for the entries that the reader can hold, so a large
    /// `count` from a file does not allocate more memory than the source justifies.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error if the table size or an entry offset overflows.
    /// Returns a read error if `reader` cannot read an entry.
    pub fn read_directories<R: ReadAt>(reader: &R, offset: u64, count: usize) -> Result<Vec<Self>> {
        count
            .checked_mul(Self::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("data-directory table size overflow"))?;
        let mut dirs = Vec::with_capacity(crate::section::entries_to_reserve(
            reader,
            offset,
            count,
            Self::SIZE,
        ));
        for i in 0..count {
            let relative = i
                .checked_mul(Self::SIZE)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| {
                    Error::invalid_data_directory("data-directory table offset overflow")
                })?;
            let dir_offset = offset.checked_add(relative).ok_or_else(|| {
                Error::invalid_data_directory("data-directory table offset overflow")
            })?;
            dirs.push(Self::read_from(reader, dir_offset)?);
        }
        Ok(dirs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_directory_size() {
        assert_eq!(DataDirectory::SIZE, 8);
    }

    #[test]
    fn test_data_directory_roundtrip() {
        let dir = DataDirectory {
            virtual_address: 0x1000,
            size: 0x200,
        };

        let mut buf = [0u8; 8];
        dir.write(&mut buf).unwrap();

        let parsed = DataDirectory::parse(&buf).unwrap();
        assert_eq!(dir, parsed);
        assert!(parsed.is_present());
    }

    #[test]
    fn test_data_directory_to_bytes_roundtrip() {
        let dir = DataDirectory {
            virtual_address: 0xABCD_1234,
            size: 0x5678,
        };

        let bytes = dir.to_bytes();
        let parsed = DataDirectory::parse(&bytes).unwrap();
        assert_eq!(dir, parsed);
    }

    #[test]
    fn test_data_directory_not_present() {
        let dir = DataDirectory::default();
        assert!(!dir.is_present());
    }

    #[test]
    fn test_data_directory_type_roundtrip() {
        for dir_type in DataDirectoryType::all() {
            let index = dir_type.as_index();
            let recovered = DataDirectoryType::from_index(index).unwrap();
            assert_eq!(dir_type, recovered);
            assert_ne!(dir_type.name(), "");
        }
    }

    #[test]
    fn test_data_directory_type_values() {
        assert_eq!(DataDirectoryType::Export.as_index(), 0);
        assert_eq!(DataDirectoryType::Import.as_index(), 1);
        assert_eq!(DataDirectoryType::Resource.as_index(), 2);
        assert_eq!(DataDirectoryType::BaseReloc.as_index(), 5);
        assert_eq!(DataDirectoryType::Tls.as_index(), 9);
        assert_eq!(DataDirectoryType::LoadConfig.as_index(), 10);
    }
}
