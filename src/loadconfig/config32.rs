//! The PE32 load configuration directory (`IMAGE_LOAD_CONFIG_DIRECTORY32`).

use super::{directory_field, directory_prefix, guard_flags, output_buffer, write_field};
use crate::Result;
use crate::prelude::*;

/// `IMAGE_LOAD_CONFIG_DIRECTORY32` (Windows 10 and later): 192 bytes.
///
/// The size changes with the Windows version. The parser reads the fields that are present.
///
/// The type is `#[non_exhaustive]`: a later version can parse more versioned fields. Then
/// these bytes move from `trailing_data` to typed fields, and `trailing_data` gets shorter.
/// To make a value, start from [`Default::default`] and set the fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct LoadConfigDirectory32 {
    /// Size of this structure, in bytes.
    ///
    /// A value of zero is the legacy convention: the reader uses the data directory size.
    /// Serialization keeps a zero value.
    pub size: u32,
    /// Time and date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Global flags to clear.
    pub global_flags_clear: u32,
    /// Global flags to set.
    pub global_flags_set: u32,
    /// Default timeout for critical sections.
    pub critical_section_default_timeout: u32,
    /// Size of minimum memory to de-commit.
    pub de_commit_free_block_threshold: u32,
    /// Size of minimum total memory to de-commit.
    pub de_commit_total_free_threshold: u32,
    /// VA of the lock prefix table (x86 only).
    pub lock_prefix_table: u32,
    /// Maximum allocation size.
    pub maximum_allocation_size: u32,
    /// Maximum virtual memory size.
    pub virtual_memory_threshold: u32,
    /// Process affinity mask.
    pub process_affinity_mask: u32,
    /// Process heap flags.
    pub process_heap_flags: u32,
    /// Service pack version.
    pub csd_version: u16,
    /// Dependent load flags.
    pub dependent_load_flags: u16,
    /// VA of the edit list (reserved).
    pub edit_list: u32,
    /// VA of the security cookie.
    pub security_cookie: u32,
    /// VA of the SEH handler table.
    pub se_handler_table: u32,
    /// Number of SEH handlers.
    pub se_handler_count: u32,
    /// VA of the CFG check function pointer.
    pub guard_cf_check_function_pointer: u32,
    /// VA of the CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u32,
    /// VA of the CFG function table.
    pub guard_cf_function_table: u32,
    /// Number of entries in the CFG function table.
    pub guard_cf_function_count: u32,
    /// CFG flags.
    pub guard_flags: u32,
    /// Bytes of the versioned structure after the fields that this type knows.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory32 {
    /// Default output size, without the optional SafeSEH and CFG fields.
    pub const MIN_SIZE: usize = 64;
    /// Size up to and including `GuardFlags`. Later versioned fields stay as opaque bytes.
    pub const SIZE_WITH_CFG: usize = 92;

    /// End offsets of the fields up to and including `GuardFlags`.
    const FIELD_ENDS: [usize; 25] = [
        4, 8, 10, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 54, 56, 60, 64, 68, 72, 76, 80, 84,
        88, 92,
    ];

    /// Offsets of the VA fields after `GuardFlags`, up to `GuardMemcpyFunctionPointer`.
    pub(super) const TRAILING_VA_OFFSETS: [usize; 15] = [
        0x68, 0x70, 0x78, 0x7C, 0x80, 0x84, 0x90, 0x9C, 0xA0, 0xA4, 0xAC, 0xB0, 0xB4, 0xB8, 0xBC,
    ];

    /// Parse a versioned prefix of whole fields. Legacy short records are also valid.
    ///
    /// # Errors
    ///
    /// Returns a `BufferTooSmall` error if `data` cannot hold the `Size` field,
    /// or an `InvalidDataDirectory` error if the declared size exceeds `data`
    /// or truncates a field.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (size, data) = directory_prefix(data)?;
        let word = |offset| directory_field(data, offset).map(u32::from_le_bytes);
        let half = |offset| directory_field(data, offset).map(u16::from_le_bytes);
        Ok(Self {
            size,
            time_date_stamp: word(4)?,
            major_version: half(8)?,
            minor_version: half(10)?,
            global_flags_clear: word(12)?,
            global_flags_set: word(16)?,
            critical_section_default_timeout: word(20)?,
            de_commit_free_block_threshold: word(24)?,
            de_commit_total_free_threshold: word(28)?,
            lock_prefix_table: word(32)?,
            maximum_allocation_size: word(36)?,
            virtual_memory_threshold: word(40)?,
            process_heap_flags: word(44)?,
            process_affinity_mask: word(48)?,
            csd_version: half(52)?,
            dependent_load_flags: half(54)?,
            edit_list: word(56)?,
            security_cookie: word(60)?,
            se_handler_table: word(64)?,
            se_handler_count: word(68)?,
            guard_cf_check_function_pointer: word(72)?,
            guard_cf_dispatch_function_pointer: word(76)?,
            guard_cf_function_table: word(80)?,
            guard_cf_function_count: word(84)?,
            guard_flags: word(88)?,
            trailing_data: data.get(Self::SIZE_WITH_CFG..).unwrap_or_default().to_vec(),
        })
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
    /// The output holds only whole fields. If `size` ends in a field before `GuardFlags`, the
    /// function extends the output to the end of that field. The written `Size` field is the
    /// output length. If `size` is zero, the function writes zero (the legacy convention).
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32` or if the
    /// allocation fails.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let known_size = if self.guard_flags != 0 {
            Self::SIZE_WITH_CFG
        } else if self.guard_cf_function_count != 0 {
            88
        } else if self.guard_cf_function_table != 0 {
            84
        } else if self.guard_cf_dispatch_function_pointer != 0 {
            80
        } else if self.guard_cf_check_function_pointer != 0 {
            76
        } else if self.se_handler_table != 0 || self.se_handler_count != 0 {
            72
        } else {
            Self::MIN_SIZE
        };
        let (mut buf, encoded_size) = output_buffer(
            self.size,
            known_size,
            &Self::FIELD_ENDS,
            &self.trailing_data,
        )?;
        // The buffer holds at least `MIN_SIZE` bytes. Write a later field only if the buffer
        // holds the complete field.
        let mut put = |offset, bytes: &[u8]| write_field(&mut buf, offset, bytes);
        put(0, &encoded_size.to_le_bytes());
        put(4, &self.time_date_stamp.to_le_bytes());
        put(8, &self.major_version.to_le_bytes());
        put(10, &self.minor_version.to_le_bytes());
        put(12, &self.global_flags_clear.to_le_bytes());
        put(16, &self.global_flags_set.to_le_bytes());
        put(20, &self.critical_section_default_timeout.to_le_bytes());
        put(24, &self.de_commit_free_block_threshold.to_le_bytes());
        put(28, &self.de_commit_total_free_threshold.to_le_bytes());
        put(32, &self.lock_prefix_table.to_le_bytes());
        put(36, &self.maximum_allocation_size.to_le_bytes());
        put(40, &self.virtual_memory_threshold.to_le_bytes());
        put(44, &self.process_heap_flags.to_le_bytes());
        put(48, &self.process_affinity_mask.to_le_bytes());
        put(52, &self.csd_version.to_le_bytes());
        put(54, &self.dependent_load_flags.to_le_bytes());
        put(56, &self.edit_list.to_le_bytes());
        put(60, &self.security_cookie.to_le_bytes());
        put(64, &self.se_handler_table.to_le_bytes());
        put(68, &self.se_handler_count.to_le_bytes());
        put(72, &self.guard_cf_check_function_pointer.to_le_bytes());
        put(76, &self.guard_cf_dispatch_function_pointer.to_le_bytes());
        put(80, &self.guard_cf_function_table.to_le_bytes());
        put(84, &self.guard_cf_function_count.to_le_bytes());
        put(88, &self.guard_flags.to_le_bytes());
        Ok(buf)
    }

    /// Return `true` if `GuardFlags` has [`guard_flags::CF_INSTRUMENTED`].
    ///
    /// The Windows loader uses this flag to enable CFG for the module.
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        self.guard_flags & guard_flags::CF_INSTRUMENTED != 0
    }

    /// Check if `SafeSEH` is present.
    #[must_use]
    pub fn has_safe_seh(&self) -> bool {
        self.se_handler_table != 0
    }

    /// Return the offsets of the typed VA fields that are not zero.
    pub(super) fn typed_va_offsets(&self) -> impl Iterator<Item = usize> {
        [
            (32, self.lock_prefix_table),
            (56, self.edit_list),
            (60, self.security_cookie),
            (64, self.se_handler_table),
            (72, self.guard_cf_check_function_pointer),
            (76, self.guard_cf_dispatch_function_pointer),
            (80, self.guard_cf_function_table),
        ]
        .into_iter()
        .filter(|&(_, va)| va != 0)
        .map(|(offset, _)| offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config_32_min_size() {
        assert_eq!(LoadConfigDirectory32::MIN_SIZE, 64);
    }

    #[test]
    fn test_load_config_32_roundtrip() {
        let original = LoadConfigDirectory32 {
            size: 104,
            time_date_stamp: 0x1234_5678,
            major_version: 1,
            minor_version: 0,
            security_cookie: 0x0040_1000,
            se_handler_table: 0x0040_2000,
            se_handler_count: 5,
            guard_cf_function_table: 0x0040_3000,
            guard_cf_function_count: 10,
            guard_flags: guard_flags::CF_INSTRUMENTED,
            ..Default::default()
        };

        let bytes = original.to_bytes();
        let parsed = LoadConfigDirectory32::parse(&bytes).unwrap();
        assert_eq!(original.size, parsed.size);
        assert_eq!(original.security_cookie, parsed.security_cookie);
        assert_eq!(original.guard_flags, parsed.guard_flags);
    }

    /// Before the fix, a `Size` of 70 gave 70 bytes. The parser then rejected the
    /// truncated field at 0x44.
    #[test]
    fn size_inside_a_field_is_extended_to_the_field_end() {
        let config = LoadConfigDirectory32 {
            size: 70,
            security_cookie: 0x0040_1000,
            ..Default::default()
        };
        let bytes = config.try_to_bytes().unwrap();
        assert_eq!(bytes.len(), 72);
        let parsed = LoadConfigDirectory32::parse(&bytes).unwrap();
        assert_eq!(parsed.size, 72);
        assert_eq!(parsed.security_cookie, config.security_cookie);
    }

    /// Before the fix, `has_cfg` was true for any `GuardFlags` value that is not zero.
    #[test]
    fn has_cfg_requires_cf_instrumented() {
        let mut config = LoadConfigDirectory32 {
            guard_flags: guard_flags::SECURITY_COOKIE_UNUSED,
            ..Default::default()
        };
        assert!(!config.has_cfg());
        config.guard_flags = 0;
        config.guard_cf_function_table = 0x0040_3000;
        assert!(!config.has_cfg());
        config.guard_flags = guard_flags::CF_INSTRUMENTED;
        assert!(config.has_cfg());
    }
}
