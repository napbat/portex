//! A raw view of the export directory.

use core::mem::offset_of;

use super::{RawField, fixed};
use crate::Result;
use crate::export::{
    ADDRESS_ENTRY_SIZE_U32, ExportDirectory, ImageExportDirectory as M, NAME_POINTER_SIZE_U32,
    ORDINAL_SIZE_U32,
};
use crate::parse_utils::{le_u16, le_u32};

/// The export directory (`IMAGE_EXPORT_DIRECTORY`) and the offsets of its fields.
///
/// Use [`RawAddressTable::counted`](super::RawAddressTable::counted) to read the export
/// address table and the export name pointer table. Set its `is_64bit` argument to `false`,
/// also in a PE32+ image: the entries of these tables are always 32-bit RVAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawExportDirectory {
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
    /// `Name`: the RVA of the DLL name.
    pub name_rva: RawField<u32>,
    /// `Base`: the first ordinal.
    pub base: RawField<u32>,
    /// `NumberOfFunctions`: the entry count of the export address table.
    pub number_of_functions: RawField<u32>,
    /// `NumberOfNames`: the entry count of the name pointer table and the ordinal table.
    pub number_of_names: RawField<u32>,
    /// `AddressOfFunctions`: the RVA of the export address table.
    pub address_of_functions: RawField<u32>,
    /// `AddressOfNames`: the RVA of the export name pointer table.
    pub address_of_names: RawField<u32>,
    /// `AddressOfNameOrdinals`: the RVA of the export ordinal table.
    pub address_of_name_ordinals: RawField<u32>,
}

impl RawExportDirectory {
    /// The size of `IMAGE_EXPORT_DIRECTORY` in bytes.
    pub const SIZE: usize = ExportDirectory::SIZE;

    /// Read the export directory at `offset`. The method does not check the values.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        const N: usize = RawExportDirectory::SIZE;
        let raw = fixed::<N>(data, offset)?;
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
            name_rva: RawField {
                offset: offset + offset_of!(M, name),
                value: le_u32::<N, { offset_of!(M, name) }>(raw),
            },
            base: RawField {
                offset: offset + offset_of!(M, base),
                value: le_u32::<N, { offset_of!(M, base) }>(raw),
            },
            number_of_functions: RawField {
                offset: offset + offset_of!(M, number_of_functions),
                value: le_u32::<N, { offset_of!(M, number_of_functions) }>(raw),
            },
            number_of_names: RawField {
                offset: offset + offset_of!(M, number_of_names),
                value: le_u32::<N, { offset_of!(M, number_of_names) }>(raw),
            },
            address_of_functions: RawField {
                offset: offset + offset_of!(M, address_of_functions),
                value: le_u32::<N, { offset_of!(M, address_of_functions) }>(raw),
            },
            address_of_names: RawField {
                offset: offset + offset_of!(M, address_of_names),
                value: le_u32::<N, { offset_of!(M, address_of_names) }>(raw),
            },
            address_of_name_ordinals: RawField {
                offset: offset + offset_of!(M, address_of_name_ordinals),
                value: le_u32::<N, { offset_of!(M, address_of_name_ordinals) }>(raw),
            },
        })
    }

    /// Return the size of the export address table in bytes, or `None` if the size does not
    /// fit in `u32`.
    #[must_use]
    pub fn address_table_size(&self) -> Option<u32> {
        self.number_of_functions
            .value
            .checked_mul(ADDRESS_ENTRY_SIZE_U32)
    }

    /// Return the size of the export name pointer table in bytes, or `None` if the size does
    /// not fit in `u32`.
    #[must_use]
    pub fn name_table_size(&self) -> Option<u32> {
        self.number_of_names
            .value
            .checked_mul(NAME_POINTER_SIZE_U32)
    }

    /// Return the size of the export ordinal table in bytes, or `None` if the size does not
    /// fit in `u32`.
    #[must_use]
    pub fn ordinal_table_size(&self) -> Option<u32> {
        self.number_of_names.value.checked_mul(ORDINAL_SIZE_U32)
    }

    /// Return the values of the fields as an [`ExportDirectory`].
    #[must_use]
    pub fn directory(&self) -> ExportDirectory {
        ExportDirectory {
            characteristics: self.characteristics.value,
            time_date_stamp: self.time_date_stamp.value,
            major_version: self.major_version.value,
            minor_version: self.minor_version.value,
            name_rva: self.name_rva.value,
            base: self.base.value,
            number_of_functions: self.number_of_functions.value,
            number_of_names: self.number_of_names.value,
            address_of_functions: self.address_of_functions.value,
            address_of_names: self.address_of_names.value,
            address_of_name_ordinals: self.address_of_name_ordinals.value,
        }
    }
}
