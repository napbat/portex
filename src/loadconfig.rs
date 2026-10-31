//! Parse and build the load configuration directory.
//!
//! The load configuration directory contains security features, for example SafeSEH and CFG
//! (Control Flow Guard). It also contains other runtime configuration.

mod builder;
mod config32;
mod config64;

pub use builder::{CfgSettings, LoadConfigBuilder};
pub use config32::LoadConfigDirectory32;
pub use config64::LoadConfigDirectory64;

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

/// Make the zeroed output buffer for a serialized load configuration.
///
/// The buffer length is the largest of these values:
///
/// - `size`, the `Size` field that the caller set.
/// - `known_size`, the end of the last field that is not zero.
/// - The end of `trailing`, which starts at the last value of `field_ends`.
///
/// If the length is in a typed field, the function extends it to the end of that field.
/// `field_ends` holds the end offsets of the typed fields in ascending order.
///
/// The function copies `trailing` into the buffer. It returns the buffer and the value of the
/// `Size` field to write: zero if `size` is zero, otherwise the buffer length.
fn output_buffer(
    size: u32,
    known_size: usize,
    field_ends: &[usize],
    trailing: &[u8],
) -> Result<(Vec<u8>, u32)> {
    let trailing_start = field_ends.last().copied().unwrap_or_default();
    let trailing_end = if trailing.is_empty() {
        0
    } else {
        trailing_start
            .checked_add(trailing.len())
            .ok_or_else(|| Error::invalid_data_directory("load-config size overflow"))?
    };
    let declared_size = usize::try_from(size)
        .map_err(|_| Error::invalid_data_directory("load-config size exceeds usize"))?;
    let mut output_size = declared_size.max(known_size).max(trailing_end);
    if let Some(&field_end) = field_ends.iter().find(|&&end| end >= output_size) {
        output_size = field_end;
    }
    let encoded_size = u32::try_from(output_size)
        .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(output_size)
        .map_err(|_| Error::invalid_data_directory("load-config is too large to allocate"))?;
    buf.resize(output_size, 0);
    if let Some(tail) = buf.get_mut(trailing_start..) {
        for (dst, src) in tail.iter_mut().zip(trailing) {
            *dst = *src;
        }
    }
    let size_field = if size == 0 { 0 } else { encoded_size };
    Ok((buf, size_field))
}

/// Return the offsets of the pointer-sized values in `trailing` that are not zero.
///
/// `trailing` starts at `trailing_start` in the structure. The function checks only the
/// offsets in `offsets` that `trailing` holds completely.
fn trailing_va_offsets<'a, const N: usize>(
    trailing: &'a [u8],
    trailing_start: usize,
    offsets: &'a [usize],
) -> impl Iterator<Item = usize> + 'a {
    offsets.iter().copied().filter(move |&offset| {
        offset
            .checked_sub(trailing_start)
            .and_then(|start| trailing.get(start..))
            .and_then(<[u8]>::first_chunk::<N>)
            .is_some_and(|value| value.iter().any(|&byte| byte != 0))
    })
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
    /// The list includes the VA fields in `trailing_data`, up to `GuardMemcpyFunctionPointer`.
    /// The offsets are in ascending order.
    pub(crate) fn va_field_offsets(&self) -> Vec<usize> {
        match self {
            Self::Config32(c) => c
                .typed_va_offsets()
                .chain(trailing_va_offsets::<4>(
                    &c.trailing_data,
                    LoadConfigDirectory32::SIZE_WITH_CFG,
                    &LoadConfigDirectory32::TRAILING_VA_OFFSETS,
                ))
                .collect(),
            Self::Config64(c) => c
                .typed_va_offsets()
                .chain(trailing_va_offsets::<8>(
                    &c.trailing_data,
                    LoadConfigDirectory64::SIZE_WITH_CFG,
                    &LoadConfigDirectory64::TRAILING_VA_OFFSETS,
                ))
                .collect(),
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
mod tests {
    use super::*;

    #[test]
    fn legacy_prefixes_preserve_present_fields_and_omit_only_whole_fields() {
        let mut early32 = vec![0; 60];
        early32[..4].copy_from_slice(&60_u32.to_le_bytes());
        early32[32..36].copy_from_slice(&0x0040_1000_u32.to_le_bytes());
        let parsed32 = LoadConfigDirectory32::parse(&early32).expect("a whole pre-cookie prefix");
        assert_eq!(parsed32.lock_prefix_table, 0x0040_1000);
        assert_eq!(parsed32.security_cookie, 0);
        assert_eq!(parsed32.se_handler_table, 0);
        let mut cookie64 = vec![0; 96];
        cookie64[..4].copy_from_slice(&96_u32.to_le_bytes());
        cookie64[88..96].copy_from_slice(&0x1_4000_1000_u64.to_le_bytes());
        let parsed64 = LoadConfigDirectory64::parse(&cookie64)
            .expect("the cookie predates reserved SEH fields");
        assert_eq!(parsed64.security_cookie, 0x1_4000_1000);
        assert_eq!(parsed64.se_handler_table, 0);
        assert_eq!(parsed64.guard_flags, 0);
        cookie64[..4].fill(0);
        assert_eq!(
            LoadConfigDirectory64::parse(&cookie64)
                .expect("legacy Size zero uses available bytes")
                .security_cookie,
            parsed64.security_cookie
        );
        let mut bounded = vec![0xff; 148];
        bounded[..4].copy_from_slice(&4_u32.to_le_bytes());
        let absent = LoadConfigDirectory64::parse(&bounded)
            .expect("bytes beyond declared Size are not fields");
        assert_eq!(absent.security_cookie, 0);
        assert_eq!(absent.trailing_data, Vec::<u8>::new());
    }

    #[test]
    fn versioned_prefixes_reject_partial_fields_and_unreadable_declared_sizes() {
        for size in [5_usize, 9, 53, 61, 65, 73, 89] {
            let mut bytes = vec![0; size];
            bytes[..4].copy_from_slice(
                &u32::try_from(size)
                    .expect("test size fits u32")
                    .to_le_bytes(),
            );
            assert!(
                LoadConfigDirectory32::parse(&bytes).is_err(),
                "partial PE32 field at Size {size}"
            );
        }
        for size in [5_usize, 9, 25, 41, 77, 89, 97, 105, 113, 145] {
            let mut bytes = vec![0; size];
            bytes[..4].copy_from_slice(
                &u32::try_from(size)
                    .expect("test size fits u32")
                    .to_le_bytes(),
            );
            assert!(
                LoadConfigDirectory64::parse(&bytes).is_err(),
                "partial PE32+ field at Size {size}"
            );
        }
        for declared in [1_u32, 3, 97] {
            let mut bytes = vec![0; 96];
            bytes[..4].copy_from_slice(&declared.to_le_bytes());
            assert!(LoadConfigDirectory64::parse(&bytes).is_err());
        }
        assert!(LoadConfigDirectory32::parse(&[]).is_err());
        assert!(LoadConfigDirectory64::parse(&[0; 3]).is_err());
    }

    #[test]
    fn serialization_keeps_trailing_data_and_declared_size() {
        let config32 = LoadConfigDirectory32 {
            size: 70,
            security_cookie: 0x0040_1000,
            trailing_data: vec![0xAA, 0xBB],
            ..Default::default()
        };
        let bytes32 = config32.try_to_bytes().expect("a small PE32 record");
        assert_eq!(bytes32.len(), LoadConfigDirectory32::SIZE_WITH_CFG + 2);
        assert_eq!(bytes32[92..], [0xAA, 0xBB]);
        let parsed32 = LoadConfigDirectory32::parse(&bytes32).expect("serialized PE32 record");
        assert_eq!(parsed32.trailing_data, config32.trailing_data);
        assert_eq!(parsed32.security_cookie, config32.security_cookie);

        let config64 = LoadConfigDirectory64 {
            size: 200,
            guard_flags: guard_flags::CF_INSTRUMENTED,
            trailing_data: vec![0xCC],
            ..Default::default()
        };
        let bytes64 = config64.try_to_bytes().expect("a small PE32+ record");
        assert_eq!(bytes64.len(), 200);
        assert_eq!(bytes64[148], 0xCC);
        assert!(bytes64[149..].iter().all(|&byte| byte == 0));
        let parsed64 = LoadConfigDirectory64::parse(&bytes64).expect("serialized PE32+ record");
        assert_eq!(parsed64.guard_flags, config64.guard_flags);
        assert_eq!(parsed64.size, 200);
    }

    #[test]
    fn va_field_offsets_cover_typed_and_trailing_fields() {
        let mut trailing = vec![0; 0xC0 - LoadConfigDirectory32::SIZE_WITH_CFG];
        // `GuardEHContinuationTable` at 0xA4, and a partial `GuardMemcpyFunctionPointer`.
        trailing[0xA4 - 92..0xA8 - 92].copy_from_slice(&0x0040_5000_u32.to_le_bytes());
        trailing.truncate(0xBE - 92);
        trailing[0xBC - 92] = 1;
        let config32 = LoadConfigDirectory::Config32(LoadConfigDirectory32 {
            security_cookie: 0x0040_1000,
            guard_cf_function_table: 0x0040_2000,
            trailing_data: trailing,
            ..Default::default()
        });
        assert_eq!(config32.va_field_offsets(), [60, 80, 0xA4]);

        let mut trailing = vec![0; 0xC8 - LoadConfigDirectory64::SIZE_WITH_CFG];
        trailing[0xC0 - 148..].copy_from_slice(&0x1_4000_6000_u64.to_le_bytes());
        let config64 = LoadConfigDirectory::Config64(LoadConfigDirectory64 {
            lock_prefix_table: 0x1_4000_1000,
            security_cookie: 0x1_4000_2000,
            trailing_data: trailing,
            ..Default::default()
        });
        assert_eq!(config64.va_field_offsets(), [40, 88, 0xC0]);
    }
}
