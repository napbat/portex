//! A raw view of the load configuration directory.

use super::{RawField, at, read_u32, read_u64};
use crate::Result;

/// The fixed fields of the load configuration (`IMAGE_LOAD_CONFIG_DIRECTORY32` or
/// `IMAGE_LOAD_CONFIG_DIRECTORY64`) that a tool rewrites in place.
///
/// [`LoadConfigDirectory`](crate::LoadConfigDirectory) reads only the fields that `Size`
/// covers. This view reads the fields at their fixed offsets and ignores `Size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        let lock_prefix_table = if is_64bit {
            read_u64(data, at(offset, 40)?)?
        } else {
            let field = read_u32(data, at(offset, 32)?)?;
            RawField {
                offset: field.offset,
                value: u64::from(field.value),
            }
        };
        Ok(Self {
            offset,
            size: read_u32(data, offset)?,
            time_date_stamp: read_u32(data, at(offset, 4)?)?,
            lock_prefix_table,
        })
    }
}
