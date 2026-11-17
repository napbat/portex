//! The PE32+ load configuration directory (`IMAGE_LOAD_CONFIG_DIRECTORY64`).

use super::{LoadConfigField as Field, directory_field, directory_prefix, guard_flags};
use crate::Result;
use crate::prelude::*;

/// `IMAGE_LOAD_CONFIG_DIRECTORY64`, with every field of the Windows SDK 10.0.26100.
///
/// The `Size` field states the versioned prefix of the structure. A field after this prefix
/// is zero in the parsed value, and [`Self::field`] returns `None` for it.
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
    /// VA of the SEH handler table.
    pub se_handler_table: u64,
    /// Number of SEH handlers.
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
    /// `CodeIntegrity.Flags` (`IMAGE_LOAD_CONFIG_CODE_INTEGRITY`).
    pub code_integrity_flags: u16,
    /// `CodeIntegrity.Catalog`.
    pub code_integrity_catalog: u16,
    /// `CodeIntegrity.CatalogOffset`.
    pub code_integrity_catalog_offset: u32,
    /// `CodeIntegrity.Reserved`.
    pub code_integrity_reserved: u32,
    /// VA of the table of address-taken IAT entries.
    pub guard_address_taken_iat_entry_table: u64,
    /// Number of address-taken IAT entries.
    pub guard_address_taken_iat_entry_count: u64,
    /// VA of the table of long jump targets.
    pub guard_long_jump_target_table: u64,
    /// Number of long jump targets.
    pub guard_long_jump_target_count: u64,
    /// VA of the dynamic value relocation table (the address form of its location).
    pub dynamic_value_reloc_table: u64,
    /// VA of the hybrid metadata of an ARM64EC or x86 CHPE image.
    pub chpe_metadata_pointer: u64,
    /// VA of the return flow failure routine.
    pub guard_rf_failure_routine: u64,
    /// VA of the return flow failure routine function pointer.
    pub guard_rf_failure_routine_function_pointer: u64,
    /// Offset of the dynamic value relocation table in its section.
    pub dynamic_value_reloc_table_offset: u32,
    /// One-based number of the section that holds the dynamic value relocation table.
    pub dynamic_value_reloc_table_section: u16,
    /// `Reserved2`.
    pub reserved2: u16,
    /// VA of the return flow stack pointer check function pointer.
    pub guard_rf_verify_stack_pointer_function_pointer: u64,
    /// Offset of the hot patch table.
    pub hot_patch_table_offset: u32,
    /// `Reserved3`.
    pub reserved3: u32,
    /// VA of the enclave configuration.
    pub enclave_configuration_pointer: u64,
    /// VA of the volatile metadata.
    pub volatile_metadata_pointer: u64,
    /// VA of the table of EH continuation targets.
    pub guard_eh_continuation_table: u64,
    /// Number of EH continuation targets.
    pub guard_eh_continuation_count: u64,
    /// VA of the XFG check function pointer.
    pub guard_xfg_check_function_pointer: u64,
    /// VA of the XFG dispatch function pointer.
    pub guard_xfg_dispatch_function_pointer: u64,
    /// VA of the XFG table dispatch function pointer.
    pub guard_xfg_table_dispatch_function_pointer: u64,
    /// VA of the `CastGuard` failure mode that the operating system sets.
    pub cast_guard_os_determined_failure_mode: u64,
    /// VA of the guarded `memcpy` function pointer.
    pub guard_memcpy_function_pointer: u64,
    /// VA of the table of user memory access function pointers.
    pub uma_function_pointers: u64,
    /// Bytes of the versioned structure after `UmaFunctionPointers`, the last field that this
    /// type knows.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory64 {
    /// Default output size, without the optional CFG fields.
    pub const MIN_SIZE: usize = 112;
    /// Size up to and including `GuardFlags`.
    pub const SIZE_WITH_CFG: usize = 148;
    /// Size up to and including `UmaFunctionPointers`, the last field that this type knows.
    pub const KNOWN_SIZE: usize = 0x148;

    /// Parse a versioned prefix of whole fields. Legacy short records are also valid.
    ///
    /// # Errors
    ///
    /// Returns a `BufferTooSmall` error if `data` cannot hold the `Size` field,
    /// or an `InvalidDataDirectory` error if the declared size exceeds `data`
    /// or truncates a field.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (size, data) = directory_prefix(data)?;
        let wide = |field: Field| directory_field(data, field.offset(true)).map(u64::from_le_bytes);
        let word = |field: Field| directory_field(data, field.offset(true)).map(u32::from_le_bytes);
        let half = |field: Field| directory_field(data, field.offset(true)).map(u16::from_le_bytes);
        Ok(Self {
            size,
            time_date_stamp: word(Field::TimeDateStamp)?,
            major_version: half(Field::MajorVersion)?,
            minor_version: half(Field::MinorVersion)?,
            global_flags_clear: word(Field::GlobalFlagsClear)?,
            global_flags_set: word(Field::GlobalFlagsSet)?,
            critical_section_default_timeout: word(Field::CriticalSectionDefaultTimeout)?,
            de_commit_free_block_threshold: wide(Field::DeCommitFreeBlockThreshold)?,
            de_commit_total_free_threshold: wide(Field::DeCommitTotalFreeThreshold)?,
            lock_prefix_table: wide(Field::LockPrefixTable)?,
            maximum_allocation_size: wide(Field::MaximumAllocationSize)?,
            virtual_memory_threshold: wide(Field::VirtualMemoryThreshold)?,
            process_affinity_mask: wide(Field::ProcessAffinityMask)?,
            process_heap_flags: word(Field::ProcessHeapFlags)?,
            csd_version: half(Field::CsdVersion)?,
            dependent_load_flags: half(Field::DependentLoadFlags)?,
            edit_list: wide(Field::EditList)?,
            security_cookie: wide(Field::SecurityCookie)?,
            se_handler_table: wide(Field::SeHandlerTable)?,
            se_handler_count: wide(Field::SeHandlerCount)?,
            guard_cf_check_function_pointer: wide(Field::GuardCfCheckFunctionPointer)?,
            guard_cf_dispatch_function_pointer: wide(Field::GuardCfDispatchFunctionPointer)?,
            guard_cf_function_table: wide(Field::GuardCfFunctionTable)?,
            guard_cf_function_count: wide(Field::GuardCfFunctionCount)?,
            guard_flags: word(Field::GuardFlags)?,
            code_integrity_flags: half(Field::CodeIntegrityFlags)?,
            code_integrity_catalog: half(Field::CodeIntegrityCatalog)?,
            code_integrity_catalog_offset: word(Field::CodeIntegrityCatalogOffset)?,
            code_integrity_reserved: word(Field::CodeIntegrityReserved)?,
            guard_address_taken_iat_entry_table: wide(Field::GuardAddressTakenIatEntryTable)?,
            guard_address_taken_iat_entry_count: wide(Field::GuardAddressTakenIatEntryCount)?,
            guard_long_jump_target_table: wide(Field::GuardLongJumpTargetTable)?,
            guard_long_jump_target_count: wide(Field::GuardLongJumpTargetCount)?,
            dynamic_value_reloc_table: wide(Field::DynamicValueRelocTable)?,
            chpe_metadata_pointer: wide(Field::ChpeMetadataPointer)?,
            guard_rf_failure_routine: wide(Field::GuardRfFailureRoutine)?,
            guard_rf_failure_routine_function_pointer: wide(
                Field::GuardRfFailureRoutineFunctionPointer,
            )?,
            dynamic_value_reloc_table_offset: word(Field::DynamicValueRelocTableOffset)?,
            dynamic_value_reloc_table_section: half(Field::DynamicValueRelocTableSection)?,
            reserved2: half(Field::Reserved2)?,
            guard_rf_verify_stack_pointer_function_pointer: wide(
                Field::GuardRfVerifyStackPointerFunctionPointer,
            )?,
            hot_patch_table_offset: word(Field::HotPatchTableOffset)?,
            reserved3: word(Field::Reserved3)?,
            enclave_configuration_pointer: wide(Field::EnclaveConfigurationPointer)?,
            volatile_metadata_pointer: wide(Field::VolatileMetadataPointer)?,
            guard_eh_continuation_table: wide(Field::GuardEhContinuationTable)?,
            guard_eh_continuation_count: wide(Field::GuardEhContinuationCount)?,
            guard_xfg_check_function_pointer: wide(Field::GuardXfgCheckFunctionPointer)?,
            guard_xfg_dispatch_function_pointer: wide(Field::GuardXfgDispatchFunctionPointer)?,
            guard_xfg_table_dispatch_function_pointer: wide(
                Field::GuardXfgTableDispatchFunctionPointer,
            )?,
            cast_guard_os_determined_failure_mode: wide(Field::CastGuardOsDeterminedFailureMode)?,
            guard_memcpy_function_pointer: wide(Field::GuardMemcpyFunctionPointer)?,
            uma_function_pointers: wide(Field::UmaFunctionPointers)?,
            trailing_data: data.get(Self::KNOWN_SIZE..).unwrap_or_default().to_vec(),
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
    /// The output holds only whole fields. It reaches to the end of the last field that is not
    /// zero, and at least to `size`. If `size` ends in a field, the function extends the output
    /// to the end of that field. The written `Size` field is the output length. If `size` is
    /// zero, the function writes zero (the legacy convention).
    ///
    /// # Errors
    ///
    /// Returns an `InvalidDataDirectory` error if the serialized size exceeds `u32` or if the
    /// allocation fails.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        super::serialize(self.size, &self.trailing_data, true, |field| {
            self.value(field)
        })
    }

    /// Return the value of a field, or `None` if the `Size` field omits it.
    ///
    /// If `size` is zero (the legacy convention), each field is present. The value of a
    /// pointer-sized field or a narrower field is widened to `u64`.
    #[must_use]
    pub fn field(&self, field: Field) -> Option<u64> {
        super::is_present(self.size, field, true).then(|| self.value(field))
    }

    /// Return `true` if `GuardFlags` has [`guard_flags::CF_INSTRUMENTED`].
    ///
    /// The Windows loader uses this flag to enable CFG for the module.
    #[must_use]
    pub fn has_cfg(&self) -> bool {
        self.guard_flags & guard_flags::CF_INSTRUMENTED != 0
    }

    /// Return the value of a field, widened to `u64`, also if `Size` omits the field.
    pub(super) fn value(&self, field: Field) -> u64 {
        match field {
            Field::Size => u64::from(self.size),
            Field::TimeDateStamp => u64::from(self.time_date_stamp),
            Field::MajorVersion => u64::from(self.major_version),
            Field::MinorVersion => u64::from(self.minor_version),
            Field::GlobalFlagsClear => u64::from(self.global_flags_clear),
            Field::GlobalFlagsSet => u64::from(self.global_flags_set),
            Field::CriticalSectionDefaultTimeout => {
                u64::from(self.critical_section_default_timeout)
            }
            Field::DeCommitFreeBlockThreshold => self.de_commit_free_block_threshold,
            Field::DeCommitTotalFreeThreshold => self.de_commit_total_free_threshold,
            Field::LockPrefixTable => self.lock_prefix_table,
            Field::MaximumAllocationSize => self.maximum_allocation_size,
            Field::VirtualMemoryThreshold => self.virtual_memory_threshold,
            Field::ProcessAffinityMask => self.process_affinity_mask,
            Field::ProcessHeapFlags => u64::from(self.process_heap_flags),
            Field::CsdVersion => u64::from(self.csd_version),
            Field::DependentLoadFlags => u64::from(self.dependent_load_flags),
            Field::EditList => self.edit_list,
            Field::SecurityCookie => self.security_cookie,
            Field::SeHandlerTable => self.se_handler_table,
            Field::SeHandlerCount => self.se_handler_count,
            Field::GuardCfCheckFunctionPointer => self.guard_cf_check_function_pointer,
            Field::GuardCfDispatchFunctionPointer => self.guard_cf_dispatch_function_pointer,
            Field::GuardCfFunctionTable => self.guard_cf_function_table,
            Field::GuardCfFunctionCount => self.guard_cf_function_count,
            Field::GuardFlags => u64::from(self.guard_flags),
            Field::CodeIntegrityFlags => u64::from(self.code_integrity_flags),
            Field::CodeIntegrityCatalog => u64::from(self.code_integrity_catalog),
            Field::CodeIntegrityCatalogOffset => u64::from(self.code_integrity_catalog_offset),
            Field::CodeIntegrityReserved => u64::from(self.code_integrity_reserved),
            Field::GuardAddressTakenIatEntryTable => self.guard_address_taken_iat_entry_table,
            Field::GuardAddressTakenIatEntryCount => self.guard_address_taken_iat_entry_count,
            Field::GuardLongJumpTargetTable => self.guard_long_jump_target_table,
            Field::GuardLongJumpTargetCount => self.guard_long_jump_target_count,
            Field::DynamicValueRelocTable => self.dynamic_value_reloc_table,
            Field::ChpeMetadataPointer => self.chpe_metadata_pointer,
            Field::GuardRfFailureRoutine => self.guard_rf_failure_routine,
            Field::GuardRfFailureRoutineFunctionPointer => {
                self.guard_rf_failure_routine_function_pointer
            }
            Field::DynamicValueRelocTableOffset => u64::from(self.dynamic_value_reloc_table_offset),
            Field::DynamicValueRelocTableSection => {
                u64::from(self.dynamic_value_reloc_table_section)
            }
            Field::Reserved2 => u64::from(self.reserved2),
            Field::GuardRfVerifyStackPointerFunctionPointer => {
                self.guard_rf_verify_stack_pointer_function_pointer
            }
            Field::HotPatchTableOffset => u64::from(self.hot_patch_table_offset),
            Field::Reserved3 => u64::from(self.reserved3),
            Field::EnclaveConfigurationPointer => self.enclave_configuration_pointer,
            Field::VolatileMetadataPointer => self.volatile_metadata_pointer,
            Field::GuardEhContinuationTable => self.guard_eh_continuation_table,
            Field::GuardEhContinuationCount => self.guard_eh_continuation_count,
            Field::GuardXfgCheckFunctionPointer => self.guard_xfg_check_function_pointer,
            Field::GuardXfgDispatchFunctionPointer => self.guard_xfg_dispatch_function_pointer,
            Field::GuardXfgTableDispatchFunctionPointer => {
                self.guard_xfg_table_dispatch_function_pointer
            }
            Field::CastGuardOsDeterminedFailureMode => self.cast_guard_os_determined_failure_mode,
            Field::GuardMemcpyFunctionPointer => self.guard_memcpy_function_pointer,
            Field::UmaFunctionPointers => self.uma_function_pointers,
        }
    }
}

#[cfg(test)]
mod tests;
