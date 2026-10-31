//! Builder for the load configuration directory.

use super::{LoadConfigDirectory, LoadConfigDirectory32, LoadConfigDirectory64};
use crate::prelude::*;
use crate::{Error, Result};

/// Control Flow Guard settings for [`LoadConfigBuilder::build_with_cfg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CfgSettings {
    /// VA of the `/GS` security cookie.
    pub security_cookie_va: u64,
    /// VA of the CFG check function pointer (`GuardCFCheckFunctionPointer`).
    pub guard_cf_check_va: u64,
    /// VA of the CFG dispatch function pointer (`GuardCFDispatchFunctionPointer`).
    pub guard_cf_dispatch_va: u64,
    /// VA of the CFG function table (`GuardCFFunctionTable`).
    pub guard_cf_table_va: u64,
    /// Number of entries in the CFG function table (`GuardCFFunctionCount`).
    pub guard_cf_count: u64,
    /// `GuardFlags` value; see [`guard_flags`](super::guard_flags).
    pub flags: u32,
}

/// Builder for load configuration directories.
///
/// A load configuration directory contains security features, for example `SafeSEH` and CFG.
/// This builder makes it easier to create and change these complex structures.
///
/// # Example
///
/// ```
/// use portex::loadconfig::{LoadConfigBuilder, guard_flags};
///
/// // Create a LoadConfig builder for 64-bit PE
/// let builder = LoadConfigBuilder::new(true);
///
/// // Build with security cookie
/// let (data, size) = builder.build_with_cookie(0x140001000);
/// assert!(size > 0);
/// ```
#[derive(Debug, Clone)]
pub struct LoadConfigBuilder {
    /// `true` for a 64-bit PE.
    is_64bit: bool,
}

impl LoadConfigBuilder {
    /// Create a new load configuration builder.
    #[must_use]
    pub fn new(is_64bit: bool) -> Self {
        Self { is_64bit }
    }

    /// Build a basic load configuration directory with only a security cookie.
    ///
    /// `security_cookie_va` is the VA of the security cookie.
    ///
    /// Returns the data and its size as `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if the builder is for PE32 and the cookie VA exceeds `u32`. For fallible
    /// building, use [`Self::try_build_with_cookie`].
    #[must_use]
    pub fn build_with_cookie(&self, security_cookie_va: u64) -> (Vec<u8>, u32) {
        self.try_build_with_cookie(security_cookie_va)
            .expect("load-config build failed: use try_build_with_cookie()")
    }

    /// Build a basic load configuration directory. PE32 values are not truncated.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the builder is for PE32 and
    /// `security_cookie_va` does not fit in `u32`.
    pub fn try_build_with_cookie(&self, security_cookie_va: u64) -> Result<(Vec<u8>, u32)> {
        if self.is_64bit {
            let config = LoadConfigDirectory64 {
                size: Self::size_field(LoadConfigDirectory64::MIN_SIZE)?,
                security_cookie: security_cookie_va,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config64(config))
        } else {
            let config = LoadConfigDirectory32 {
                size: Self::size_field(LoadConfigDirectory32::MIN_SIZE)?,
                security_cookie: Self::pe32_value(security_cookie_va, "security cookie")?,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config32(config))
        }
    }

    /// Build from an existing `LoadConfigDirectory`.
    ///
    /// Returns the data and its size as `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics in these conditions:
    /// - The bitness of the directory is not the bitness of the builder.
    /// - The size of the directory exceeds `u32`.
    /// - The allocation fails.
    ///
    /// For fallible building, use [`Self::try_build`].
    #[must_use]
    pub fn build(&self, config: &LoadConfigDirectory) -> (Vec<u8>, u32) {
        self.try_build(config)
            .expect("load-config build failed: use try_build()")
    }

    /// Build from an existing directory. The directory must have the PE width of the builder.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error in these conditions:
    /// - The bitness of the directory is not the bitness of the builder.
    /// - The serialized size exceeds `u32`.
    /// - The allocation fails.
    pub fn try_build(&self, config: &LoadConfigDirectory) -> Result<(Vec<u8>, u32)> {
        let matches_width = matches!(
            (self.is_64bit, config),
            (true, LoadConfigDirectory::Config64(_)) | (false, LoadConfigDirectory::Config32(_))
        );
        if !matches_width {
            return Err(Error::invalid_data_directory(
                "load-config bitness does not match the target image",
            ));
        }
        Self::serialize(config)
    }

    /// Build a load configuration directory with CFG (Control Flow Guard) settings.
    ///
    /// Returns the data and its size as `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if the builder is for PE32 and a value in `cfg` exceeds `u32`. For fallible
    /// building, use [`Self::try_build_with_cfg`].
    #[must_use]
    pub fn build_with_cfg(&self, cfg: &CfgSettings) -> (Vec<u8>, u32) {
        self.try_build_with_cfg(cfg)
            .expect("load-config build failed: use try_build_with_cfg()")
    }

    /// Build a load configuration directory with CFG enabled. PE32 values are checked.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the builder is for PE32 and a VA or the
    /// function count in `cfg` does not fit in `u32`.
    pub fn try_build_with_cfg(&self, cfg: &CfgSettings) -> Result<(Vec<u8>, u32)> {
        if self.is_64bit {
            let config = LoadConfigDirectory64 {
                size: Self::size_field(LoadConfigDirectory64::SIZE_WITH_CFG)?,
                security_cookie: cfg.security_cookie_va,
                guard_cf_check_function_pointer: cfg.guard_cf_check_va,
                guard_cf_dispatch_function_pointer: cfg.guard_cf_dispatch_va,
                guard_cf_function_table: cfg.guard_cf_table_va,
                guard_cf_function_count: cfg.guard_cf_count,
                guard_flags: cfg.flags,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config64(config))
        } else {
            let config = LoadConfigDirectory32 {
                size: Self::size_field(LoadConfigDirectory32::SIZE_WITH_CFG)?,
                security_cookie: Self::pe32_value(cfg.security_cookie_va, "security cookie")?,
                guard_cf_check_function_pointer: Self::pe32_value(
                    cfg.guard_cf_check_va,
                    "CFG check function",
                )?,
                guard_cf_dispatch_function_pointer: Self::pe32_value(
                    cfg.guard_cf_dispatch_va,
                    "CFG dispatch function",
                )?,
                guard_cf_function_table: Self::pe32_value(
                    cfg.guard_cf_table_va,
                    "CFG function table",
                )?,
                guard_cf_function_count: Self::pe32_value(
                    cfg.guard_cf_count,
                    "CFG function count",
                )?,
                guard_flags: cfg.flags,
                ..Default::default()
            };
            Self::serialize(&LoadConfigDirectory::Config32(config))
        }
    }

    fn size_field(size: usize) -> Result<u32> {
        u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))
    }

    fn serialize(config: &LoadConfigDirectory) -> Result<(Vec<u8>, u32)> {
        let data = config.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("load-config size exceeds u32"))?;
        Ok((data, size))
    }

    fn pe32_value(value: u64, field: &str) -> Result<u32> {
        u32::try_from(value).map_err(|_| {
            Error::invalid_data_directory(format!("{field} does not fit a PE32 load config"))
        })
    }

    /// Calculate the size of the load configuration data.
    #[must_use]
    pub fn size(&self, with_cfg: bool) -> usize {
        if self.is_64bit {
            if with_cfg {
                LoadConfigDirectory64::SIZE_WITH_CFG
            } else {
                LoadConfigDirectory64::MIN_SIZE
            }
        } else if with_cfg {
            LoadConfigDirectory32::SIZE_WITH_CFG
        } else {
            LoadConfigDirectory32::MIN_SIZE
        }
    }
}

/// On a 32-bit target, a `Size` of `u32::MAX` exceeds `isize::MAX`. Before the fix, `vec!`
/// panicked with a capacity overflow.
#[cfg(all(test, target_pointer_width = "32"))]
mod tests {
    use super::*;

    #[test]
    fn serialization_reports_unallocatable_size() {
        let config32 = LoadConfigDirectory32 {
            size: u32::MAX,
            ..Default::default()
        };
        assert!(config32.try_to_bytes().is_err());
        let config64 = LoadConfigDirectory64 {
            size: u32::MAX,
            ..Default::default()
        };
        assert!(config64.try_to_bytes().is_err());
        assert!(
            LoadConfigBuilder::new(false)
                .try_build(&LoadConfigDirectory::Config32(config32))
                .is_err()
        );
    }
}
