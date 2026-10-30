//! Raw views of the resource directory: directories, entries and data entries.

use super::{RawField, at, check_range, read_u16, read_u32};
use crate::Result;
use crate::resource::{ResourceDataEntry, ResourceDirectoryEntry, ResourceDirectoryHeader};

/// The high bit of a resource directory entry field.
const HIGH_BIT: u32 = 0x8000_0000;

/// A resource directory (`IMAGE_RESOURCE_DIRECTORY`) and the offsets of its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawResourceDirectory {
    /// The offset of the directory.
    pub offset: usize,
    /// `Characteristics`.
    pub characteristics: RawField<u32>,
    /// `TimeDateStamp`.
    pub time_date_stamp: RawField<u32>,
    /// `MajorVersion`.
    pub major_version: RawField<u16>,
    /// `MinorVersion`.
    pub minor_version: RawField<u16>,
    /// `NumberOfNamedEntries`.
    pub number_of_named_entries: RawField<u16>,
    /// `NumberOfIdEntries`.
    pub number_of_id_entries: RawField<u16>,
}

impl RawResourceDirectory {
    /// The size of `IMAGE_RESOURCE_DIRECTORY` in bytes.
    pub const SIZE: usize = ResourceDirectoryHeader::SIZE;

    /// Read the directory at `offset`. The method does not check the values.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        check_range(data, offset, Self::SIZE)?;
        let half = |delta| read_u16(data, at(offset, delta)?);
        Ok(Self {
            offset,
            characteristics: read_u32(data, offset)?,
            time_date_stamp: read_u32(data, at(offset, 4)?)?,
            major_version: half(8)?,
            minor_version: half(10)?,
            number_of_named_entries: half(12)?,
            number_of_id_entries: half(14)?,
        })
    }

    /// Return the count of entries: the named entries and the ID entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        usize::from(self.number_of_named_entries.value)
            + usize::from(self.number_of_id_entries.value)
    }

    /// Return the offset of the first entry, after the directory, or `None` on overflow.
    #[must_use]
    pub const fn entries_offset(&self) -> Option<usize> {
        self.offset.checked_add(Self::SIZE)
    }
}

/// A resource directory entry (`IMAGE_RESOURCE_DIRECTORY_ENTRY`) and the offsets of its
/// fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawResourceEntry {
    /// The offset of the entry.
    pub offset: usize,
    /// The name offset or the ID. If the high bit is set, the low 31 bits are the offset of a
    /// name string from the start of the resource directory.
    pub name_or_id: RawField<u32>,
    /// The offset of the data entry or the subdirectory, from the start of the resource
    /// directory. If the high bit is set, the low 31 bits point to a subdirectory.
    pub offset_to_data: RawField<u32>,
}

impl RawResourceEntry {
    /// The size of `IMAGE_RESOURCE_DIRECTORY_ENTRY` in bytes.
    pub const SIZE: usize = ResourceDirectoryEntry::SIZE;

    /// Read the entry at `offset`. The method does not check the values.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        check_range(data, offset, Self::SIZE)?;
        Ok(Self {
            offset,
            name_or_id: read_u32(data, offset)?,
            offset_to_data: read_u32(data, at(offset, 4)?)?,
        })
    }

    /// Return `true` if the entry has a name string, not an ID.
    #[must_use]
    pub const fn is_named(&self) -> bool {
        self.name_or_id.value & HIGH_BIT != 0
    }

    /// Return `true` if the entry points to a subdirectory, not a data entry.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.offset_to_data.value & HIGH_BIT != 0
    }

    /// Return the offset of the name string from the start of the resource directory: the low
    /// 31 bits of the name field.
    #[must_use]
    pub const fn name_offset(&self) -> u32 {
        self.name_or_id.value & !HIGH_BIT
    }

    /// Return the offset of the child from the start of the resource directory: the low 31
    /// bits of the data field.
    #[must_use]
    pub const fn child_offset(&self) -> u32 {
        self.offset_to_data.value & !HIGH_BIT
    }
}

/// A resource data entry (`IMAGE_RESOURCE_DATA_ENTRY`) and the offsets of its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawResourceDataEntry {
    /// The offset of the data entry.
    pub offset: usize,
    /// `OffsetToData`: the RVA of the resource data.
    pub offset_to_data: RawField<u32>,
    /// `Size`: the size of the resource data in bytes.
    pub size: RawField<u32>,
    /// `CodePage`.
    pub code_page: RawField<u32>,
    /// `Reserved`.
    pub reserved: RawField<u32>,
}

impl RawResourceDataEntry {
    /// The size of `IMAGE_RESOURCE_DATA_ENTRY` in bytes.
    pub const SIZE: usize = ResourceDataEntry::SIZE;

    /// Read the data entry at `offset`. The method does not check the values.
    ///
    /// # Errors
    ///
    /// Returns an error if the data entry is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        check_range(data, offset, Self::SIZE)?;
        let word = |delta| read_u32(data, at(offset, delta)?);
        Ok(Self {
            offset,
            offset_to_data: word(0)?,
            size: word(4)?,
            code_page: word(8)?,
            reserved: word(12)?,
        })
    }
}
