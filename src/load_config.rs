//! Parse and build the load configuration directory.
//!
//! The load configuration directory contains security features, for example SafeSEH and CFG
//! (Control Flow Guard). It also contains other runtime configuration.
//!
//! `IMAGE_LOAD_CONFIG_DIRECTORY` grew one field group at a time, so an image declares only the
//! prefix that its linker knew. The `Size` field states that prefix:
//!
//! - A field that the prefix omits is absent. [`LoadConfigDirectory::field`] returns `None` for
//!   it, and the typed field is zero.
//! - A field that the prefix cuts is an error.
//! - Bytes after the last field that Portex knows stay in `trailing_data`.
//!
//! The field offsets follow `winnt.h` of the Windows SDK 10.0.26100.

mod builder;
mod config32;
mod config64;
mod field;

pub use builder::{CfgSettings, LoadConfigBuilder};
pub use config32::LoadConfigDirectory32;
pub use config64::LoadConfigDirectory64;
pub use field::LoadConfigField;

use crate::prelude::*;
use crate::{Error, Result};

/// Return the `Size` field and the versioned prefix of the structure.
///
/// The `Size` field limits the available versioned prefix. A `Size` of zero does not mean that
/// the directory is absent. In this case, the legacy convention applies: use the directory size.
fn directory_prefix(data: &[u8]) -> Result<(u32, &[u8])> {
    const HEADER_SIZE: usize = core::mem::size_of::<u32>();
    let Some(size_bytes) = data.first_chunk::<HEADER_SIZE>() else {
        return Err(Error::buffer_too_small(HEADER_SIZE, data.len()));
    };
    let size = u32::from_le_bytes(*size_bytes);
    // A Size that does not fit `usize` is also larger than `data`.
    let declared_size = if size == 0 {
        data.len()
    } else {
        usize::try_from(size).unwrap_or(usize::MAX)
    };
    match data.get(..declared_size) {
        Some(prefix) if declared_size >= HEADER_SIZE => Ok((size, prefix)),
        _ => Err(Error::invalid_data_directory(format!(
            "load-config size {declared_size} is outside the available {} bytes",
            data.len()
        ))),
    }
}

/// Read the field at `offset`. A version can omit a whole field, but it cannot supply only
/// part of the value.
fn directory_field<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    match data.get(offset..) {
        None | Some([]) => Ok([0; N]),
        Some(rest) => rest.first_chunk::<N>().copied().ok_or_else(|| {
            Error::invalid_data_directory(format!("load-config field at {offset:#x} is truncated"))
        }),
    }
}

/// Write `bytes` at `offset` in `buf` if the complete field fits.
///
/// A shorter record omits the whole field. In this case, the function writes nothing.
fn write_field(buf: &mut [u8], offset: usize, bytes: &[u8]) {
    if let Some(field) = buf
        .get_mut(offset..)
        .and_then(|rest| rest.get_mut(..bytes.len()))
    {
        field.copy_from_slice(bytes);
    }
}

/// Return `true` if the structure with the `Size` field `size` holds `field` completely.
///
/// A `size` of zero is the legacy convention. Then each field is present.
fn is_present(size: u32, field: LoadConfigField, is_64bit: bool) -> bool {
    size == 0 || usize::try_from(size).is_ok_and(|size| field.end(is_64bit) <= size)
}

/// Serialize the structure of one layout.
///
/// `value` returns the value of each field. The buffer length is the largest of these values:
///
/// - `size`, the `Size` field that the caller set.
/// - The minimum size of the layout, or the end of the last field that is not zero. A `SafeSEH`
///   table always gets its count.
/// - The end of `trailing`, which starts after the last known field.
///
/// If the length is in a field, the function extends it to the end of that field. The written
/// `Size` field is zero if `size` is zero, otherwise the buffer length.
fn serialize(
    size: u32,
    trailing: &[u8],
    is_64bit: bool,
    value: impl Fn(LoadConfigField) -> u64,
) -> Result<Vec<u8>> {
    let (min_size, known_end) = if is_64bit {
        (
            LoadConfigDirectory64::MIN_SIZE,
            LoadConfigDirectory64::KNOWN_SIZE,
        )
    } else {
        (
            LoadConfigDirectory32::MIN_SIZE,
            LoadConfigDirectory32::KNOWN_SIZE,
        )
    };
    let used_end = LoadConfigField::ALL
        .into_iter()
        .filter(|&field| field != LoadConfigField::Size && value(field) != 0)
        .map(|field| match field {
            LoadConfigField::SeHandlerTable => LoadConfigField::SeHandlerCount.end(is_64bit),
            _ => field.end(is_64bit),
        })
        .fold(min_size, usize::max);
    let trailing_end = if trailing.is_empty() {
        0
    } else {
        known_end
            .checked_add(trailing.len())
            .ok_or_else(|| Error::invalid_data_directory("load-config size overflow"))?
    };
    let declared_size = usize::try_from(size)
        .map_err(|_| Error::invalid_data_directory("load-config size exceeds usize"))?;
    let mut output_size = declared_size.max(used_end).max(trailing_end);
    if let Some(field) = LoadConfigField::ALL
        .into_iter()
        .find(|field| field.offset(is_64bit) < output_size && output_size < field.end(is_64bit))
    {
        output_size = field.end(is_64bit);
    }
    let encoded_size = u32::try_from(output_size)
        .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(output_size)
        .map_err(|_| Error::invalid_data_directory("load-config is too large to allocate"))?;
    buf.resize(output_size, 0);
    if let Some(tail) = buf.get_mut(known_end..) {
        for (dst, src) in tail.iter_mut().zip(trailing) {
            *dst = *src;
        }
    }
    let size_field = if size == 0 { 0 } else { encoded_size };
    for field in LoadConfigField::ALL {
        let value = match field {
            LoadConfigField::Size => u64::from(size_field),
            _ => value(field),
        };
        // The value fits the field, so its low bytes are the field bytes.
        let bytes = value.to_le_bytes();
        let width = field.size(is_64bit);
        write_field(&mut buf, field.offset(is_64bit), &bytes[..width]);
    }
    Ok(buf)
}

/// Load configuration directory, in the 32-bit or the 64-bit layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadConfigDirectory {
    /// PE32 `IMAGE_LOAD_CONFIG_DIRECTORY32`.
    Config32(LoadConfigDirectory32),
    /// PE32+ `IMAGE_LOAD_CONFIG_DIRECTORY64`.
    Config64(LoadConfigDirectory64),
}

impl LoadConfigDirectory {
    /// Parse the 32-bit or the 64-bit layout. `is_64bit` selects the layout.
    ///
    /// # Errors
    ///
    /// Returns a `BufferTooSmall` error if `data` cannot hold the `Size` field,
    /// or an `InvalidDataDirectory` error if the declared size exceeds `data`
    /// or truncates a field.
    pub fn parse(data: &[u8], is_64bit: bool) -> Result<Self> {
        if is_64bit {
            Ok(Self::Config64(LoadConfigDirectory64::parse(data)?))
        } else {
            Ok(Self::Config32(LoadConfigDirectory32::parse(data)?))
        }
    }

    /// Serialize to bytes, up to the value of the `Size` field.
    ///
    /// # Panics
    ///
    /// Panics if the serialized size exceeds `u32` or if the allocation fails. For fallible
    /// serialization, use [`Self::try_to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("load-config build failed: use try_to_bytes()")
    }

    /// Serialize to bytes, with checked arithmetic for the versioned size and the trailing size.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32` or if the
    /// allocation fails.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Config32(c) => c.try_to_bytes(),
            Self::Config64(c) => c.try_to_bytes(),
        }
    }

    /// Return `true` for the PE32+ layout.
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        matches!(self, Self::Config64(_))
    }

    /// Return the value of a field, or `None` if the `Size` field omits it.
    ///
    /// A present field can be zero. For a VA field, zero means that the image declares no such
    /// object.
    #[must_use]
    pub fn field(&self, field: LoadConfigField) -> Option<u64> {
        match self {
            Self::Config32(c) => c.field(field),
            Self::Config64(c) => c.field(field),
        }
    }

    /// Return the value of a field, or `None` if the `Size` field omits it or the value is zero.
    ///
    /// Use this function for a VA field: a zero VA declares no object.
    #[must_use]
    pub fn va(&self, field: LoadConfigField) -> Option<u64> {
        self.field(field).filter(|&value| value != 0)
    }

    /// Return `true` if `trailing_data` holds a byte that is not zero.
    ///
    /// These bytes are fields of a later version of the structure, which Portex does not know.
    #[must_use]
    pub fn has_unknown_fields(&self) -> bool {
        let trailing = match self {
            Self::Config32(c) => &c.trailing_data,
            Self::Config64(c) => &c.trailing_data,
        };
        trailing.iter().any(|&byte| byte != 0)
    }

    /// VA of the security cookie, widened to `u64`.
    #[must_use]
    pub fn security_cookie_va(&self) -> u64 {
        match self {
            Self::Config32(c) => u64::from(c.security_cookie),
            Self::Config64(c) => c.security_cookie,
        }
    }

    /// Return `true` if `GuardFlags` has [`guard_flags::CF_INSTRUMENTED`].
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        match self {
            Self::Config32(c) => c.has_cfg(),
            Self::Config64(c) => c.has_cfg(),
        }
    }

    /// Return the offsets in the serialized structure of the VA fields that are not zero.
    ///
    /// The offsets are in ascending order.
    pub(crate) fn va_field_offsets(&self) -> Vec<usize> {
        let is_64bit = self.is_64bit();
        let mut offsets: Vec<usize> = LoadConfigField::ALL
            .into_iter()
            .filter(|&field| field.is_va() && self.value(field) != 0)
            .map(|field| field.offset(is_64bit))
            .collect();
        offsets.sort_unstable();
        offsets
    }

    /// Return the value of a field, widened to `u64`, also if `Size` omits the field.
    fn value(&self, field: LoadConfigField) -> u64 {
        match self {
            Self::Config32(c) => c.value(field),
            Self::Config64(c) => c.value(field),
        }
    }
}

/// `GuardFlags` values (`IMAGE_GUARD_*`) for the load configuration directory.
pub mod guard_flags {
    /// `IMAGE_GUARD_CF_INSTRUMENTED`: module performs CFG checks.
    pub const CF_INSTRUMENTED: u32 = 0x0000_0100;
    /// `IMAGE_GUARD_CFW_INSTRUMENTED`: module performs CFG and write-integrity checks.
    pub const CFW_INSTRUMENTED: u32 = 0x0000_0200;
    /// `IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT`: module contains valid CFG target metadata.
    pub const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
    /// `IMAGE_GUARD_SECURITY_COOKIE_UNUSED`: module does not use the `/GS` security cookie.
    pub const SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
    /// `IMAGE_GUARD_PROTECT_DELAYLOAD_IAT`: module supports read-only delay-load IAT.
    pub const PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
    /// `IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION`: delay-load IAT is in its own section.
    pub const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
    /// `IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT`: module contains suppressed-export
    /// information.
    pub const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
    /// `IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION`: module enables suppression of exports.
    pub const CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
    /// `IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT`: module contains longjmp target information.
    pub const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
    /// `IMAGE_GUARD_RF_INSTRUMENTED`: module contains return-flow instrumentation.
    pub const RF_INSTRUMENTED: u32 = 0x0002_0000;
    /// `IMAGE_GUARD_RF_ENABLE`: module requests return-flow protection.
    pub const RF_ENABLE: u32 = 0x0004_0000;
    /// `IMAGE_GUARD_RF_STRICT`: module requests return-flow protection in strict mode.
    pub const RF_STRICT: u32 = 0x0008_0000;
    /// `IMAGE_GUARD_RETPOLINE_PRESENT`: module was built with retpoline support.
    pub const RETPOLINE_PRESENT: u32 = 0x0010_0000;
    /// `IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT`: module contains EH continuation target
    /// information.
    pub const EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
    /// `IMAGE_GUARD_XFG_ENABLED`: module was built with XFG.
    pub const XFG_ENABLED: u32 = 0x0080_0000;
    /// `IMAGE_GUARD_CASTGUARD_PRESENT`: module has `CastGuard` instrumentation.
    pub const CASTGUARD_PRESENT: u32 = 0x0100_0000;
    /// `IMAGE_GUARD_MEMCPY_PRESENT`: module has guarded `memcpy` instrumentation.
    pub const MEMCPY_PRESENT: u32 = 0x0200_0000;
    /// `IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK`: the bits that hold the count of extra bytes
    /// in each `GuardCFFunctionTable` entry.
    pub const CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF000_0000;
    /// `IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT`: the shift of
    /// [`CF_FUNCTION_TABLE_SIZE_MASK`].
    pub const CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;
}

#[cfg(test)]
mod tests;
