//! A raw view of the export directory.

use super::{RawField, at, check_range, read_u16, read_u32};
use crate::Result;
use crate::export::ExportDirectory;

/// The export directory (`IMAGE_EXPORT_DIRECTORY`) and the offsets of its fields.
///
/// Use [`RawAddressTable::counted`](super::RawAddressTable::counted) to read the export
/// address table and the export name pointer table.
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
        check_range(data, offset, Self::SIZE)?;
        let word = |delta| read_u32(data, at(offset, delta)?);
        Ok(Self {
            offset,
            characteristics: word(0)?,
            time_date_stamp: word(4)?,
            major_version: read_u16(data, at(offset, 8)?)?,
            minor_version: read_u16(data, at(offset, 10)?)?,
            name_rva: word(12)?,
            base: word(16)?,
            number_of_functions: word(20)?,
            number_of_names: word(24)?,
            address_of_functions: word(28)?,
            address_of_names: word(32)?,
            address_of_name_ordinals: word(36)?,
        })
    }

    /// Return the size of the export address table in bytes, or `None` if the size does not
    /// fit in `u32`.
    #[must_use]
    pub fn address_table_size(&self) -> Option<u32> {
        self.number_of_functions.value.checked_mul(4)
    }

    /// Return the size of the export name pointer table in bytes, or `None` if the size does
    /// not fit in `u32`.
    #[must_use]
    pub fn name_table_size(&self) -> Option<u32> {
        self.number_of_names.value.checked_mul(4)
    }

    /// Return the size of the export ordinal table in bytes, or `None` if the size does not
    /// fit in `u32`.
    #[must_use]
    pub fn ordinal_table_size(&self) -> Option<u32> {
        self.number_of_names.value.checked_mul(2)
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
