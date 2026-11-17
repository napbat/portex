//! A raw view of the load configuration directory.

use super::{RawField, at};
use crate::load_config::LoadConfigField as Field;
use crate::parse_utils::{le_u32, le_u64};
use crate::{Error, Result};

/// The fixed fields of the load configuration (`IMAGE_LOAD_CONFIG_DIRECTORY32` or
/// `IMAGE_LOAD_CONFIG_DIRECTORY64`) that a tool rewrites in place.
///
/// [`LoadConfigDirectory`](crate::LoadConfigDirectory) reads only the fields that `Size`
/// covers. This view reads the fields at their fixed offsets and ignores `Size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RawLoadConfigDirectory {
    /// The offset of the load configuration.
    pub offset: usize,
    /// `Size`: the size of the structure in bytes.
    pub size: RawField<u32>,
    /// `TimeDateStamp`.
    pub time_date_stamp: RawField<u32>,
    /// `LockPrefixTable`: the VA of the lock prefix table. The field has 32 bits in a PE32
    /// image and 64 bits in a PE32+ image.
    pub lock_prefix_table: RawField<u64>,
}

impl RawLoadConfigDirectory {
    /// Read the fixed fields of the load configuration at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if a field is not in `data`.
    pub fn parse(data: &[u8], offset: usize, is_64bit: bool) -> Result<Self> {
        const N32: usize = Field::LockPrefixTable.end(false);
        const N64: usize = Field::LockPrefixTable.end(true);
        let lock_offset = at(offset, Field::LockPrefixTable.offset(is_64bit))?;
        // `LockPrefixTable` is the last field of the view. Its error is the error of today.
        let missing = || Error::offset_out_of_bounds(lock_offset, data.len());
        let rest = data.get(offset..).ok_or_else(missing)?;
        let (size, time_date_stamp, lock_prefix_table) = if is_64bit {
            let raw = rest.first_chunk::<N64>().ok_or_else(missing)?;
            (
                le_u32::<N64, { Field::Size.offset(true) }>(raw),
                le_u32::<N64, { Field::TimeDateStamp.offset(true) }>(raw),
                le_u64::<N64, { Field::LockPrefixTable.offset(true) }>(raw),
            )
        } else {
            let raw = rest.first_chunk::<N32>().ok_or_else(missing)?;
            (
                le_u32::<N32, { Field::Size.offset(false) }>(raw),
                le_u32::<N32, { Field::TimeDateStamp.offset(false) }>(raw),
                u64::from(le_u32::<N32, { Field::LockPrefixTable.offset(false) }>(raw)),
            )
        };
        // The bounds check above makes each sum below at most `lock_offset`.
        Ok(Self {
            offset,
            size: RawField {
                offset: at(offset, Field::Size.offset(is_64bit))?,
                value: size,
            },
            time_date_stamp: RawField {
                offset: at(offset, Field::TimeDateStamp.offset(is_64bit))?,
                value: time_date_stamp,
            },
            lock_prefix_table: RawField {
                offset: lock_offset,
                value: lock_prefix_table,
            },
        })
    }
}
