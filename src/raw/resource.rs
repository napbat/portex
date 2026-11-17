//! Raw views of the resource directory: directories, entries and data entries.

use core::mem::offset_of;

use super::RawField;
use crate::parse_utils::{le_u16, le_u32};
use crate::resource::{
    ImageResourceDataEntry, ImageResourceDirectory as M, ImageResourceDirectoryEntry,
    ResourceDataEntry, ResourceDirectoryEntry, ResourceDirectoryHeader,
};
use crate::{Error, Result};

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
        const N: usize = RawResourceDirectory::SIZE;
        let Some(raw) = data.get(offset..).and_then(<[u8]>::first_chunk::<N>) else {
            return Err(Error::offset_out_of_bounds(offset, data.len()));
        };
        Ok(Self {
            offset,
            characteristics: RawField {
                offset: offset + offset_of!(M, characteristics),
                value: le_u32::<N, { offset_of!(M, characteristics) }>(raw),
            },
            time_date_stamp: RawField {
                offset: offset + offset_of!(M, time_date_stamp),
                value: le_u32::<N, { offset_of!(M, time_date_stamp) }>(raw),
            },
            major_version: RawField {
                offset: offset + offset_of!(M, major_version),
                value: le_u16::<N, { offset_of!(M, major_version) }>(raw),
            },
            minor_version: RawField {
                offset: offset + offset_of!(M, minor_version),
                value: le_u16::<N, { offset_of!(M, minor_version) }>(raw),
            },
            number_of_named_entries: RawField {
                offset: offset + offset_of!(M, number_of_named_entries),
                value: le_u16::<N, { offset_of!(M, number_of_named_entries) }>(raw),
            },
            number_of_id_entries: RawField {
                offset: offset + offset_of!(M, number_of_id_entries),
                value: le_u16::<N, { offset_of!(M, number_of_id_entries) }>(raw),
            },
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
        type E = ImageResourceDirectoryEntry;
        const N: usize = RawResourceEntry::SIZE;
        let Some(raw) = data.get(offset..).and_then(<[u8]>::first_chunk::<N>) else {
            return Err(Error::offset_out_of_bounds(offset, data.len()));
        };
        Ok(Self {
            offset,
            name_or_id: RawField {
                offset: offset + offset_of!(E, name),
                value: le_u32::<N, { offset_of!(E, name) }>(raw),
            },
            offset_to_data: RawField {
                offset: offset + offset_of!(E, offset_to_data),
                value: le_u32::<N, { offset_of!(E, offset_to_data) }>(raw),
            },
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
        type D = ImageResourceDataEntry;
        const N: usize = RawResourceDataEntry::SIZE;
        let Some(raw) = data.get(offset..).and_then(<[u8]>::first_chunk::<N>) else {
            return Err(Error::offset_out_of_bounds(offset, data.len()));
        };
        Ok(Self {
            offset,
            offset_to_data: RawField {
                offset: offset + offset_of!(D, offset_to_data),
                value: le_u32::<N, { offset_of!(D, offset_to_data) }>(raw),
            },
            size: RawField {
                offset: offset + offset_of!(D, size),
                value: le_u32::<N, { offset_of!(D, size) }>(raw),
            },
            code_page: RawField {
                offset: offset + offset_of!(D, code_page),
                value: le_u32::<N, { offset_of!(D, code_page) }>(raw),
            },
            reserved: RawField {
                offset: offset + offset_of!(D, reserved),
                value: le_u32::<N, { offset_of!(D, reserved) }>(raw),
            },
        })
    }
}
