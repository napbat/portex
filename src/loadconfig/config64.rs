//! The PE32+ load configuration directory (`IMAGE_LOAD_CONFIG_DIRECTORY64`).

use super::{directory_field, directory_prefix, guard_flags, output_buffer, write_field};
use crate::Result;
use crate::prelude::*;

/// `IMAGE_LOAD_CONFIG_DIRECTORY64` (Windows 10 and later).
///
/// The type is `#[non_exhaustive]`: a later version can parse more versioned fields. Then
/// these bytes move from `trailing_data` to typed fields, and `trailing_data` gets shorter.
/// To make a value, start from [`Default::default`] and set the fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct LoadConfigDirectory64 {
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
    pub de_commit_free_block_threshold: u64,
    /// Size of minimum total memory to de-commit.
    pub de_commit_total_free_threshold: u64,
    /// VA of the lock prefix table (x86 only).
    pub lock_prefix_table: u64,
    /// Maximum allocation size.
    pub maximum_allocation_size: u64,
    /// Maximum virtual memory size.
    pub virtual_memory_threshold: u64,
    /// Process affinity mask.
    pub process_affinity_mask: u64,
    /// Process heap flags.
    pub process_heap_flags: u32,
    /// Service pack version.
    pub csd_version: u16,
    /// Dependent load flags.
    pub dependent_load_flags: u16,
    /// VA of the edit list (reserved).
    pub edit_list: u64,
    /// VA of the security cookie.
    pub security_cookie: u64,
    /// VA of the SEH handler table (not used on x64).
    pub se_handler_table: u64,
    /// Number of SEH handlers (not used on x64).
    pub se_handler_count: u64,
    /// VA of the CFG check function pointer.
    pub guard_cf_check_function_pointer: u64,
    /// VA of the CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u64,
    /// VA of the CFG function table.
    pub guard_cf_function_table: u64,
    /// Number of entries in the CFG function table.
    pub guard_cf_function_count: u64,
    /// CFG flags.
    pub guard_flags: u32,
    /// Bytes of the versioned structure after the fields that this type knows.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory64 {
    /// Default output size, without the optional CFG fields.
    pub const MIN_SIZE: usize = 112;
    /// Size up to and including `GuardFlags`. Later versioned fields stay as opaque bytes.
    pub const SIZE_WITH_CFG: usize = 148;

    /// End offsets of the fields up to and including `GuardFlags`.
    const FIELD_ENDS: [usize; 25] = [
        4, 8, 10, 12, 16, 20, 24, 32, 40, 48, 56, 64, 72, 76, 78, 80, 88, 96, 104, 112, 120, 128,
        136, 144, 148,
    ];

    /// Offsets of the VA fields after `GuardFlags`, up to `GuardMemcpyFunctionPointer`.
    pub(super) const TRAILING_VA_OFFSETS: [usize; 15] = [
        0xA0, 0xB0, 0xC0, 0xC8, 0xD0, 0xD8, 0xE8, 0xF8, 0x100, 0x108, 0x118, 0x120, 0x128, 0x130,
        0x138,
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
        let wide = |offset| directory_field(data, offset).map(u64::from_le_bytes);
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
            de_commit_free_block_threshold: wide(24)?,
            de_commit_total_free_threshold: wide(32)?,
            lock_prefix_table: wide(40)?,
            maximum_allocation_size: wide(48)?,
            virtual_memory_threshold: wide(56)?,
            process_affinity_mask: wide(64)?,
            process_heap_flags: word(72)?,
            csd_version: half(76)?,
            dependent_load_flags: half(78)?,
            edit_list: wide(80)?,
            security_cookie: wide(88)?,
            se_handler_table: wide(96)?,
            se_handler_count: wide(104)?,
            guard_cf_check_function_pointer: wide(112)?,
            guard_cf_dispatch_function_pointer: wide(120)?,
            guard_cf_function_table: wide(128)?,
            guard_cf_function_count: wide(136)?,
            guard_flags: word(144)?,
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
            144
        } else if self.guard_cf_function_table != 0 {
            136
        } else if self.guard_cf_dispatch_function_pointer != 0 {
            128
        } else if self.guard_cf_check_function_pointer != 0 {
            120
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
        put(32, &self.de_commit_total_free_threshold.to_le_bytes());
        put(40, &self.lock_prefix_table.to_le_bytes());
        put(48, &self.maximum_allocation_size.to_le_bytes());
        put(56, &self.virtual_memory_threshold.to_le_bytes());
        put(64, &self.process_affinity_mask.to_le_bytes());
        put(72, &self.process_heap_flags.to_le_bytes());
        put(76, &self.csd_version.to_le_bytes());
        put(78, &self.dependent_load_flags.to_le_bytes());
        put(80, &self.edit_list.to_le_bytes());
        put(88, &self.security_cookie.to_le_bytes());
        put(96, &self.se_handler_table.to_le_bytes());
        put(104, &self.se_handler_count.to_le_bytes());
        put(112, &self.guard_cf_check_function_pointer.to_le_bytes());
        put(120, &self.guard_cf_dispatch_function_pointer.to_le_bytes());
        put(128, &self.guard_cf_function_table.to_le_bytes());
        put(136, &self.guard_cf_function_count.to_le_bytes());
        put(144, &self.guard_flags.to_le_bytes());
        Ok(buf)
    }

    /// Return `true` if `GuardFlags` has [`guard_flags::CF_INSTRUMENTED`].
    ///
    /// The Windows loader uses this flag to enable CFG for the module.
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        self.guard_flags & guard_flags::CF_INSTRUMENTED != 0
    }

    /// Return the offsets of the typed VA fields that are not zero.
    pub(super) fn typed_va_offsets(&self) -> impl Iterator<Item = usize> {
        [
            (40, self.lock_prefix_table),
            (80, self.edit_list),
            (88, self.security_cookie),
            (96, self.se_handler_table),
            (112, self.guard_cf_check_function_pointer),
            (120, self.guard_cf_dispatch_function_pointer),
            (128, self.guard_cf_function_table),
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
    fn test_load_config_64_min_size() {
        assert_eq!(LoadConfigDirectory64::MIN_SIZE, 112);
    }

    #[test]
    fn test_load_config_64_roundtrip() {
        let original = LoadConfigDirectory64 {
            size: 148,
            security_cookie: 0x0000_0001_4000_1000,
            guard_cf_function_table: 0x0000_0001_4000_2000,
            guard_cf_function_count: 20,
            guard_flags: guard_flags::CF_INSTRUMENTED | guard_flags::CF_FUNCTION_TABLE_PRESENT,
            ..Default::default()
        };

        let bytes = original.to_bytes();
        let parsed = LoadConfigDirectory64::parse(&bytes).unwrap();
        assert_eq!(original.size, parsed.size);
        assert_eq!(original.security_cookie, parsed.security_cookie);
        assert_eq!(original.guard_flags, parsed.guard_flags);
    }

    /// Before the fix, a parsed legacy `Size` of zero was written back as 112.
    #[test]
    fn legacy_zero_size_is_kept() {
        let mut bytes = vec![0; LoadConfigDirectory64::MIN_SIZE];
        bytes[88..96].copy_from_slice(&0x1_4000_1000_u64.to_le_bytes());
        let parsed = LoadConfigDirectory64::parse(&bytes).unwrap();
        assert_eq!(parsed.size, 0);
        assert_eq!(parsed.try_to_bytes().unwrap(), bytes);
    }

    /// Before the fix, a `Size` of 116 gave 116 bytes. The parser then rejected the
    /// truncated field at 0x70.
    #[test]
    fn size_inside_a_field_is_extended_to_the_field_end() {
        let config = LoadConfigDirectory64 {
            size: 116,
            ..Default::default()
        };
        let bytes = config.try_to_bytes().unwrap();
        assert_eq!(bytes.len(), 120);
        assert_eq!(LoadConfigDirectory64::parse(&bytes).unwrap().size, 120);
    }

    #[test]
    fn has_cfg_requires_cf_instrumented() {
        let config = LoadConfigDirectory64 {
            guard_flags: guard_flags::RF_INSTRUMENTED,
            guard_cf_function_table: 0x1_4000_2000,
            ..Default::default()
        };
        assert!(!config.has_cfg());
    }
}
