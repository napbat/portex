//! The PE32 load configuration directory (`IMAGE_LOAD_CONFIG_DIRECTORY32`).

use super::{LoadConfigField as Field, directory_field, directory_prefix, guard_flags};
use crate::Result;
use crate::prelude::*;

/// `IMAGE_LOAD_CONFIG_DIRECTORY32`, with every field of the Windows SDK 10.0.26100.
///
/// The `Size` field states the versioned prefix of the structure. A field after this prefix
/// is zero in the parsed value, and [`Self::field`] returns `None` for it.
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
    /// `CodeIntegrity.Flags` (`IMAGE_LOAD_CONFIG_CODE_INTEGRITY`).
    pub code_integrity_flags: u16,
    /// `CodeIntegrity.Catalog`.
    pub code_integrity_catalog: u16,
    /// `CodeIntegrity.CatalogOffset`.
    pub code_integrity_catalog_offset: u32,
    /// `CodeIntegrity.Reserved`.
    pub code_integrity_reserved: u32,
    /// VA of the table of address-taken IAT entries.
    pub guard_address_taken_iat_entry_table: u32,
    /// Number of address-taken IAT entries.
    pub guard_address_taken_iat_entry_count: u32,
    /// VA of the table of long jump targets.
    pub guard_long_jump_target_table: u32,
    /// Number of long jump targets.
    pub guard_long_jump_target_count: u32,
    /// VA of the dynamic value relocation table (the address form of its location).
    pub dynamic_value_reloc_table: u32,
    /// VA of the hybrid metadata of an ARM64EC or x86 CHPE image.
    pub chpe_metadata_pointer: u32,
    /// VA of the return flow failure routine.
    pub guard_rf_failure_routine: u32,
    /// VA of the return flow failure routine function pointer.
    pub guard_rf_failure_routine_function_pointer: u32,
    /// Offset of the dynamic value relocation table in its section.
    pub dynamic_value_reloc_table_offset: u32,
    /// One-based number of the section that holds the dynamic value relocation table.
    pub dynamic_value_reloc_table_section: u16,
    /// `Reserved2`.
    pub reserved2: u16,
    /// VA of the return flow stack pointer check function pointer.
    pub guard_rf_verify_stack_pointer_function_pointer: u32,
    /// Offset of the hot patch table.
    pub hot_patch_table_offset: u32,
    /// `Reserved3`.
    pub reserved3: u32,
    /// VA of the enclave configuration.
    pub enclave_configuration_pointer: u32,
    /// VA of the volatile metadata.
    pub volatile_metadata_pointer: u32,
    /// VA of the table of EH continuation targets.
    pub guard_eh_continuation_table: u32,
    /// Number of EH continuation targets.
    pub guard_eh_continuation_count: u32,
    /// VA of the XFG check function pointer.
    pub guard_xfg_check_function_pointer: u32,
    /// VA of the XFG dispatch function pointer.
    pub guard_xfg_dispatch_function_pointer: u32,
    /// VA of the XFG table dispatch function pointer.
    pub guard_xfg_table_dispatch_function_pointer: u32,
    /// VA of the `CastGuard` failure mode that the operating system sets.
    pub cast_guard_os_determined_failure_mode: u32,
    /// VA of the guarded `memcpy` function pointer.
    pub guard_memcpy_function_pointer: u32,
    /// VA of the table of user memory access function pointers.
    pub uma_function_pointers: u32,
    /// Bytes of the versioned structure after `UmaFunctionPointers`, the last field that this
    /// type knows.
    pub trailing_data: Vec<u8>,
}

impl LoadConfigDirectory32 {
    /// Default output size, without the optional SafeSEH and CFG fields.
    pub const MIN_SIZE: usize = 64;
    /// Size up to and including `GuardFlags`.
    pub const SIZE_WITH_CFG: usize = 92;
    /// Size up to and including `UmaFunctionPointers`, the last field that this type knows.
    pub const KNOWN_SIZE: usize = 0xc4;

    /// Parse a versioned prefix of whole fields. Legacy short records are also valid.
    ///
    /// # Errors
    ///
    /// Returns a `BufferTooSmall` error if `data` cannot hold the `Size` field,
    /// or an `InvalidDataDirectory` error if the declared size exceeds `data`
    /// or truncates a field.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (size, data) = directory_prefix(data)?;
        let word =
            |field: Field| directory_field(data, field.offset(false)).map(u32::from_le_bytes);
        let half =
            |field: Field| directory_field(data, field.offset(false)).map(u16::from_le_bytes);
        Ok(Self {
            size,
            time_date_stamp: word(Field::TimeDateStamp)?,
            major_version: half(Field::MajorVersion)?,
            minor_version: half(Field::MinorVersion)?,
            global_flags_clear: word(Field::GlobalFlagsClear)?,
            global_flags_set: word(Field::GlobalFlagsSet)?,
            critical_section_default_timeout: word(Field::CriticalSectionDefaultTimeout)?,
            de_commit_free_block_threshold: word(Field::DeCommitFreeBlockThreshold)?,
            de_commit_total_free_threshold: word(Field::DeCommitTotalFreeThreshold)?,
            lock_prefix_table: word(Field::LockPrefixTable)?,
            maximum_allocation_size: word(Field::MaximumAllocationSize)?,
            virtual_memory_threshold: word(Field::VirtualMemoryThreshold)?,
            process_affinity_mask: word(Field::ProcessAffinityMask)?,
            process_heap_flags: word(Field::ProcessHeapFlags)?,
            csd_version: half(Field::CsdVersion)?,
            dependent_load_flags: half(Field::DependentLoadFlags)?,
            edit_list: word(Field::EditList)?,
            security_cookie: word(Field::SecurityCookie)?,
            se_handler_table: word(Field::SeHandlerTable)?,
            se_handler_count: word(Field::SeHandlerCount)?,
            guard_cf_check_function_pointer: word(Field::GuardCfCheckFunctionPointer)?,
            guard_cf_dispatch_function_pointer: word(Field::GuardCfDispatchFunctionPointer)?,
            guard_cf_function_table: word(Field::GuardCfFunctionTable)?,
            guard_cf_function_count: word(Field::GuardCfFunctionCount)?,
            guard_flags: word(Field::GuardFlags)?,
            code_integrity_flags: half(Field::CodeIntegrityFlags)?,
            code_integrity_catalog: half(Field::CodeIntegrityCatalog)?,
            code_integrity_catalog_offset: word(Field::CodeIntegrityCatalogOffset)?,
            code_integrity_reserved: word(Field::CodeIntegrityReserved)?,
            guard_address_taken_iat_entry_table: word(Field::GuardAddressTakenIatEntryTable)?,
            guard_address_taken_iat_entry_count: word(Field::GuardAddressTakenIatEntryCount)?,
            guard_long_jump_target_table: word(Field::GuardLongJumpTargetTable)?,
            guard_long_jump_target_count: word(Field::GuardLongJumpTargetCount)?,
            dynamic_value_reloc_table: word(Field::DynamicValueRelocTable)?,
            chpe_metadata_pointer: word(Field::ChpeMetadataPointer)?,
            guard_rf_failure_routine: word(Field::GuardRfFailureRoutine)?,
            guard_rf_failure_routine_function_pointer: word(
                Field::GuardRfFailureRoutineFunctionPointer,
            )?,
            dynamic_value_reloc_table_offset: word(Field::DynamicValueRelocTableOffset)?,
            dynamic_value_reloc_table_section: half(Field::DynamicValueRelocTableSection)?,
            reserved2: half(Field::Reserved2)?,
            guard_rf_verify_stack_pointer_function_pointer: word(
                Field::GuardRfVerifyStackPointerFunctionPointer,
            )?,
            hot_patch_table_offset: word(Field::HotPatchTableOffset)?,
            reserved3: word(Field::Reserved3)?,
            enclave_configuration_pointer: word(Field::EnclaveConfigurationPointer)?,
            volatile_metadata_pointer: word(Field::VolatileMetadataPointer)?,
            guard_eh_continuation_table: word(Field::GuardEhContinuationTable)?,
            guard_eh_continuation_count: word(Field::GuardEhContinuationCount)?,
            guard_xfg_check_function_pointer: word(Field::GuardXfgCheckFunctionPointer)?,
            guard_xfg_dispatch_function_pointer: word(Field::GuardXfgDispatchFunctionPointer)?,
            guard_xfg_table_dispatch_function_pointer: word(
                Field::GuardXfgTableDispatchFunctionPointer,
            )?,
            cast_guard_os_determined_failure_mode: word(Field::CastGuardOsDeterminedFailureMode)?,
            guard_memcpy_function_pointer: word(Field::GuardMemcpyFunctionPointer)?,
            uma_function_pointers: word(Field::UmaFunctionPointers)?,
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
        super::serialize(self.size, &self.trailing_data, false, |field| {
            self.value(field)
        })
    }

    /// Return the value of a field, or `None` if the `Size` field omits it.
    ///
    /// If `size` is zero (the legacy convention), each field is present. The value of a
    /// pointer-sized field or a narrower field is widened to `u64`.
    #[must_use]
    pub fn field(&self, field: Field) -> Option<u64> {
        super::is_present(self.size, field, false).then(|| self.value(field))
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
            Field::DeCommitFreeBlockThreshold => u64::from(self.de_commit_free_block_threshold),
            Field::DeCommitTotalFreeThreshold => u64::from(self.de_commit_total_free_threshold),
            Field::LockPrefixTable => u64::from(self.lock_prefix_table),
            Field::MaximumAllocationSize => u64::from(self.maximum_allocation_size),
            Field::VirtualMemoryThreshold => u64::from(self.virtual_memory_threshold),
            Field::ProcessAffinityMask => u64::from(self.process_affinity_mask),
            Field::ProcessHeapFlags => u64::from(self.process_heap_flags),
            Field::CsdVersion => u64::from(self.csd_version),
            Field::DependentLoadFlags => u64::from(self.dependent_load_flags),
            Field::EditList => u64::from(self.edit_list),
            Field::SecurityCookie => u64::from(self.security_cookie),
            Field::SeHandlerTable => u64::from(self.se_handler_table),
            Field::SeHandlerCount => u64::from(self.se_handler_count),
            Field::GuardCfCheckFunctionPointer => u64::from(self.guard_cf_check_function_pointer),
            Field::GuardCfDispatchFunctionPointer => {
                u64::from(self.guard_cf_dispatch_function_pointer)
            }
            Field::GuardCfFunctionTable => u64::from(self.guard_cf_function_table),
            Field::GuardCfFunctionCount => u64::from(self.guard_cf_function_count),
            Field::GuardFlags => u64::from(self.guard_flags),
            Field::CodeIntegrityFlags => u64::from(self.code_integrity_flags),
            Field::CodeIntegrityCatalog => u64::from(self.code_integrity_catalog),
            Field::CodeIntegrityCatalogOffset => u64::from(self.code_integrity_catalog_offset),
            Field::CodeIntegrityReserved => u64::from(self.code_integrity_reserved),
            Field::GuardAddressTakenIatEntryTable => {
                u64::from(self.guard_address_taken_iat_entry_table)
            }
            Field::GuardAddressTakenIatEntryCount => {
                u64::from(self.guard_address_taken_iat_entry_count)
            }
            Field::GuardLongJumpTargetTable => u64::from(self.guard_long_jump_target_table),
            Field::GuardLongJumpTargetCount => u64::from(self.guard_long_jump_target_count),
            Field::DynamicValueRelocTable => u64::from(self.dynamic_value_reloc_table),
            Field::ChpeMetadataPointer => u64::from(self.chpe_metadata_pointer),
            Field::GuardRfFailureRoutine => u64::from(self.guard_rf_failure_routine),
            Field::GuardRfFailureRoutineFunctionPointer => {
                u64::from(self.guard_rf_failure_routine_function_pointer)
            }
            Field::DynamicValueRelocTableOffset => u64::from(self.dynamic_value_reloc_table_offset),
            Field::DynamicValueRelocTableSection => {
                u64::from(self.dynamic_value_reloc_table_section)
            }
            Field::Reserved2 => u64::from(self.reserved2),
            Field::GuardRfVerifyStackPointerFunctionPointer => {
                u64::from(self.guard_rf_verify_stack_pointer_function_pointer)
            }
            Field::HotPatchTableOffset => u64::from(self.hot_patch_table_offset),
            Field::Reserved3 => u64::from(self.reserved3),
            Field::EnclaveConfigurationPointer => u64::from(self.enclave_configuration_pointer),
            Field::VolatileMetadataPointer => u64::from(self.volatile_metadata_pointer),
            Field::GuardEhContinuationTable => u64::from(self.guard_eh_continuation_table),
            Field::GuardEhContinuationCount => u64::from(self.guard_eh_continuation_count),
            Field::GuardXfgCheckFunctionPointer => u64::from(self.guard_xfg_check_function_pointer),
            Field::GuardXfgDispatchFunctionPointer => {
                u64::from(self.guard_xfg_dispatch_function_pointer)
            }
            Field::GuardXfgTableDispatchFunctionPointer => {
                u64::from(self.guard_xfg_table_dispatch_function_pointer)
            }
            Field::CastGuardOsDeterminedFailureMode => {
                u64::from(self.cast_guard_os_determined_failure_mode)
            }
            Field::GuardMemcpyFunctionPointer => u64::from(self.guard_memcpy_function_pointer),
            Field::UmaFunctionPointers => u64::from(self.uma_function_pointers),
        }
    }
}

#[cfg(test)]
mod tests;
