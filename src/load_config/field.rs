//! The names, offsets and widths of the load configuration fields.

use core::mem::{offset_of, size_of};

/// One field of `IMAGE_LOAD_CONFIG_DIRECTORY32` or `IMAGE_LOAD_CONFIG_DIRECTORY64`.
///
/// The list holds every field of the structure in `winnt.h` of the Windows SDK 10.0.26100. A
/// field marked "VA" holds a virtual address at the preferred image base. A pointer-sized field
/// has 32 bits in a PE32 image and 64 bits in a PE32+ image.
///
/// Use [`LoadConfigDirectory::field`](super::LoadConfigDirectory::field) to read a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadConfigField {
    /// `Size`: the size of the structure, in bytes.
    Size,
    /// `TimeDateStamp`.
    TimeDateStamp,
    /// `MajorVersion`.
    MajorVersion,
    /// `MinorVersion`.
    MinorVersion,
    /// `GlobalFlagsClear`: the global flags that the loader clears.
    GlobalFlagsClear,
    /// `GlobalFlagsSet`: the global flags that the loader sets.
    GlobalFlagsSet,
    /// `CriticalSectionDefaultTimeout`.
    CriticalSectionDefaultTimeout,
    /// `DeCommitFreeBlockThreshold` (pointer-sized).
    DeCommitFreeBlockThreshold,
    /// `DeCommitTotalFreeThreshold` (pointer-sized).
    DeCommitTotalFreeThreshold,
    /// `LockPrefixTable` (VA): the x86 `LOCK` prefix addresses.
    LockPrefixTable,
    /// `MaximumAllocationSize` (pointer-sized).
    MaximumAllocationSize,
    /// `VirtualMemoryThreshold` (pointer-sized).
    VirtualMemoryThreshold,
    /// `ProcessAffinityMask` (pointer-sized).
    ProcessAffinityMask,
    /// `ProcessHeapFlags`.
    ProcessHeapFlags,
    /// `CSDVersion`: the service pack version.
    CsdVersion,
    /// `DependentLoadFlags`.
    DependentLoadFlags,
    /// `EditList` (VA, reserved).
    EditList,
    /// `SecurityCookie` (VA): the `/GS` security cookie.
    SecurityCookie,
    /// `SEHandlerTable` (VA): the sorted RVAs of the safe x86 exception handlers.
    SeHandlerTable,
    /// `SEHandlerCount` (pointer-sized).
    SeHandlerCount,
    /// `GuardCFCheckFunctionPointer` (VA).
    GuardCfCheckFunctionPointer,
    /// `GuardCFDispatchFunctionPointer` (VA).
    GuardCfDispatchFunctionPointer,
    /// `GuardCFFunctionTable` (VA).
    GuardCfFunctionTable,
    /// `GuardCFFunctionCount` (pointer-sized).
    GuardCfFunctionCount,
    /// `GuardFlags`: see [`guard_flags`](super::guard_flags).
    GuardFlags,
    /// `ImageLoadConfigCodeIntegrity.Flags` (`IMAGE_LOAD_CONFIG_CODE_INTEGRITY`).
    CodeIntegrityFlags,
    /// `ImageLoadConfigCodeIntegrity.Catalog`.
    CodeIntegrityCatalog,
    /// `ImageLoadConfigCodeIntegrity.CatalogOffset`.
    CodeIntegrityCatalogOffset,
    /// `ImageLoadConfigCodeIntegrity.Reserved`.
    CodeIntegrityReserved,
    /// `GuardAddressTakenIatEntryTable` (VA).
    GuardAddressTakenIatEntryTable,
    /// `GuardAddressTakenIatEntryCount` (pointer-sized).
    GuardAddressTakenIatEntryCount,
    /// `GuardLongJumpTargetTable` (VA).
    GuardLongJumpTargetTable,
    /// `GuardLongJumpTargetCount` (pointer-sized).
    GuardLongJumpTargetCount,
    /// `DynamicValueRelocTable` (VA): the address form of the location of the dynamic value
    /// relocation table.
    DynamicValueRelocTable,
    /// `CHPEMetadataPointer` (VA): the hybrid metadata of an ARM64EC or x86 CHPE image.
    ChpeMetadataPointer,
    /// `GuardRFFailureRoutine` (VA).
    GuardRfFailureRoutine,
    /// `GuardRFFailureRoutineFunctionPointer` (VA).
    GuardRfFailureRoutineFunctionPointer,
    /// `DynamicValueRelocTableOffset`: the offset of the dynamic value relocation table in its
    /// section.
    DynamicValueRelocTableOffset,
    /// `DynamicValueRelocTableSection`: the one-based number of the section that holds the
    /// dynamic value relocation table.
    DynamicValueRelocTableSection,
    /// `Reserved2`.
    Reserved2,
    /// `GuardRFVerifyStackPointerFunctionPointer` (VA).
    GuardRfVerifyStackPointerFunctionPointer,
    /// `HotPatchTableOffset`.
    HotPatchTableOffset,
    /// `Reserved3`.
    Reserved3,
    /// `EnclaveConfigurationPointer` (VA).
    EnclaveConfigurationPointer,
    /// `VolatileMetadataPointer` (VA).
    VolatileMetadataPointer,
    /// `GuardEHContinuationTable` (VA).
    GuardEhContinuationTable,
    /// `GuardEHContinuationCount` (pointer-sized).
    GuardEhContinuationCount,
    /// `GuardXFGCheckFunctionPointer` (VA).
    GuardXfgCheckFunctionPointer,
    /// `GuardXFGDispatchFunctionPointer` (VA).
    GuardXfgDispatchFunctionPointer,
    /// `GuardXFGTableDispatchFunctionPointer` (VA).
    GuardXfgTableDispatchFunctionPointer,
    /// `CastGuardOsDeterminedFailureMode` (VA).
    CastGuardOsDeterminedFailureMode,
    /// `GuardMemcpyFunctionPointer` (VA).
    GuardMemcpyFunctionPointer,
    /// `UmaFunctionPointers` (VA).
    UmaFunctionPointers,
}

/// `IMAGE_LOAD_CONFIG_CODE_INTEGRITY`.
#[repr(C)]
struct ImageLoadConfigCodeIntegrity {
    flags: u16,
    catalog: u16,
    catalog_offset: u32,
    reserved: u32,
}

/// The layout of `IMAGE_LOAD_CONFIG_DIRECTORY32` in `winnt.h` of the Windows SDK 10.0.26100.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct ImageLoadConfigDirectory32 {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u32,
    de_commit_total_free_threshold: u32,
    lock_prefix_table: u32,
    maximum_allocation_size: u32,
    virtual_memory_threshold: u32,
    process_heap_flags: u32,
    process_affinity_mask: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u32,
    security_cookie: u32,
    se_handler_table: u32,
    se_handler_count: u32,
    guard_cf_check_function_pointer: u32,
    guard_cf_dispatch_function_pointer: u32,
    guard_cf_function_table: u32,
    guard_cf_function_count: u32,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u32,
    guard_address_taken_iat_entry_count: u32,
    guard_long_jump_target_table: u32,
    guard_long_jump_target_count: u32,
    dynamic_value_reloc_table: u32,
    chpe_metadata_pointer: u32,
    guard_rf_failure_routine: u32,
    guard_rf_failure_routine_function_pointer: u32,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u32,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u32,
    volatile_metadata_pointer: u32,
    guard_eh_continuation_table: u32,
    guard_eh_continuation_count: u32,
    guard_xfg_check_function_pointer: u32,
    guard_xfg_dispatch_function_pointer: u32,
    guard_xfg_table_dispatch_function_pointer: u32,
    cast_guard_os_determined_failure_mode: u32,
    guard_memcpy_function_pointer: u32,
    uma_function_pointers: u32,
}

/// The layout of `IMAGE_LOAD_CONFIG_DIRECTORY64` in `winnt.h` of the Windows SDK 10.0.26100.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct ImageLoadConfigDirectory64 {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u64,
    de_commit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    se_handler_table: u64,
    se_handler_count: u64,
    guard_cf_check_function_pointer: u64,
    guard_cf_dispatch_function_pointer: u64,
    guard_cf_function_table: u64,
    guard_cf_function_count: u64,
    guard_flags: u32,
    code_integrity: ImageLoadConfigCodeIntegrity,
    guard_address_taken_iat_entry_table: u64,
    guard_address_taken_iat_entry_count: u64,
    guard_long_jump_target_table: u64,
    guard_long_jump_target_count: u64,
    dynamic_value_reloc_table: u64,
    chpe_metadata_pointer: u64,
    guard_rf_failure_routine: u64,
    guard_rf_failure_routine_function_pointer: u64,
    dynamic_value_reloc_table_offset: u32,
    dynamic_value_reloc_table_section: u16,
    reserved2: u16,
    guard_rf_verify_stack_pointer_function_pointer: u64,
    hot_patch_table_offset: u32,
    reserved3: u32,
    enclave_configuration_pointer: u64,
    volatile_metadata_pointer: u64,
    guard_eh_continuation_table: u64,
    guard_eh_continuation_count: u64,
    guard_xfg_check_function_pointer: u64,
    guard_xfg_dispatch_function_pointer: u64,
    guard_xfg_table_dispatch_function_pointer: u64,
    cast_guard_os_determined_failure_mode: u64,
    guard_memcpy_function_pointer: u64,
    uma_function_pointers: u64,
}

// Anchors from `winnt.h` that the layouts must keep.
const _: () = {
    assert!(offset_of!(ImageLoadConfigDirectory32, guard_flags) == 0x58);
    assert!(offset_of!(ImageLoadConfigDirectory32, dynamic_value_reloc_table_offset) == 0x88);
    assert!(offset_of!(ImageLoadConfigDirectory32, uma_function_pointers) == 0xc0);
    assert!(size_of::<ImageLoadConfigDirectory32>() == 0xc4);
    assert!(offset_of!(ImageLoadConfigDirectory64, process_heap_flags) == 0x48);
    assert!(offset_of!(ImageLoadConfigDirectory64, guard_flags) == 0x90);
    assert!(offset_of!(ImageLoadConfigDirectory64, dynamic_value_reloc_table_offset) == 0xe0);
    assert!(offset_of!(ImageLoadConfigDirectory64, uma_function_pointers) == 0x140);
    assert!(size_of::<ImageLoadConfigDirectory64>() == 0x148);
};

/// Return the size of the field that `field` selects.
const fn width<T, F>(_field: fn(&T) -> &F) -> usize {
    size_of::<F>()
}

/// Return the offset and the width of one field of the layout that `$is_64bit` selects.
macro_rules! place {
    ($is_64bit:ident, $($field:ident).+) => {
        if $is_64bit {
            (
                offset_of!(ImageLoadConfigDirectory64, $($field).+),
                width(|directory: &ImageLoadConfigDirectory64| &directory.$($field).+),
            )
        } else {
            (
                offset_of!(ImageLoadConfigDirectory32, $($field).+),
                width(|directory: &ImageLoadConfigDirectory32| &directory.$($field).+),
            )
        }
    };
}

impl LoadConfigField {
    /// Every field, in the order of the PE32+ structure.
    pub const ALL: [Self; 53] = [
        Self::Size,
        Self::TimeDateStamp,
        Self::MajorVersion,
        Self::MinorVersion,
        Self::GlobalFlagsClear,
        Self::GlobalFlagsSet,
        Self::CriticalSectionDefaultTimeout,
        Self::DeCommitFreeBlockThreshold,
        Self::DeCommitTotalFreeThreshold,
        Self::LockPrefixTable,
        Self::MaximumAllocationSize,
        Self::VirtualMemoryThreshold,
        Self::ProcessAffinityMask,
        Self::ProcessHeapFlags,
        Self::CsdVersion,
        Self::DependentLoadFlags,
        Self::EditList,
        Self::SecurityCookie,
        Self::SeHandlerTable,
        Self::SeHandlerCount,
        Self::GuardCfCheckFunctionPointer,
        Self::GuardCfDispatchFunctionPointer,
        Self::GuardCfFunctionTable,
        Self::GuardCfFunctionCount,
        Self::GuardFlags,
        Self::CodeIntegrityFlags,
        Self::CodeIntegrityCatalog,
        Self::CodeIntegrityCatalogOffset,
        Self::CodeIntegrityReserved,
        Self::GuardAddressTakenIatEntryTable,
        Self::GuardAddressTakenIatEntryCount,
        Self::GuardLongJumpTargetTable,
        Self::GuardLongJumpTargetCount,
        Self::DynamicValueRelocTable,
        Self::ChpeMetadataPointer,
        Self::GuardRfFailureRoutine,
        Self::GuardRfFailureRoutineFunctionPointer,
        Self::DynamicValueRelocTableOffset,
        Self::DynamicValueRelocTableSection,
        Self::Reserved2,
        Self::GuardRfVerifyStackPointerFunctionPointer,
        Self::HotPatchTableOffset,
        Self::Reserved3,
        Self::EnclaveConfigurationPointer,
        Self::VolatileMetadataPointer,
        Self::GuardEhContinuationTable,
        Self::GuardEhContinuationCount,
        Self::GuardXfgCheckFunctionPointer,
        Self::GuardXfgDispatchFunctionPointer,
        Self::GuardXfgTableDispatchFunctionPointer,
        Self::CastGuardOsDeterminedFailureMode,
        Self::GuardMemcpyFunctionPointer,
        Self::UmaFunctionPointers,
    ];

    /// Return the offset of the field in the structure.
    ///
    /// `is_64bit` selects the PE32+ layout.
    #[must_use]
    pub const fn offset(self, is_64bit: bool) -> usize {
        self.place(is_64bit).0
    }

    /// Return the width of the field in bytes.
    ///
    /// `is_64bit` selects the PE32+ layout.
    #[must_use]
    pub const fn size(self, is_64bit: bool) -> usize {
        self.place(is_64bit).1
    }

    /// Return the offset of the first byte after the field.
    ///
    /// `is_64bit` selects the PE32+ layout.
    #[must_use]
    pub const fn end(self, is_64bit: bool) -> usize {
        let (offset, size) = self.place(is_64bit);
        offset + size
    }

    /// Return `true` if the field holds a VA.
    #[must_use]
    pub const fn is_va(self) -> bool {
        matches!(
            self,
            Self::LockPrefixTable
                | Self::EditList
                | Self::SecurityCookie
                | Self::SeHandlerTable
                | Self::GuardCfCheckFunctionPointer
                | Self::GuardCfDispatchFunctionPointer
                | Self::GuardCfFunctionTable
                | Self::GuardAddressTakenIatEntryTable
                | Self::GuardLongJumpTargetTable
                | Self::DynamicValueRelocTable
                | Self::ChpeMetadataPointer
                | Self::GuardRfFailureRoutine
                | Self::GuardRfFailureRoutineFunctionPointer
                | Self::GuardRfVerifyStackPointerFunctionPointer
                | Self::EnclaveConfigurationPointer
                | Self::VolatileMetadataPointer
                | Self::GuardEhContinuationTable
                | Self::GuardXfgCheckFunctionPointer
                | Self::GuardXfgDispatchFunctionPointer
                | Self::GuardXfgTableDispatchFunctionPointer
                | Self::CastGuardOsDeterminedFailureMode
                | Self::GuardMemcpyFunctionPointer
                | Self::UmaFunctionPointers
        )
    }

    /// Return the offset and the width of the field.
    const fn place(self, is_64bit: bool) -> (usize, usize) {
        match self {
            Self::Size => place!(is_64bit, size),
            Self::TimeDateStamp => place!(is_64bit, time_date_stamp),
            Self::MajorVersion => place!(is_64bit, major_version),
            Self::MinorVersion => place!(is_64bit, minor_version),
            Self::GlobalFlagsClear => place!(is_64bit, global_flags_clear),
            Self::GlobalFlagsSet => place!(is_64bit, global_flags_set),
            Self::CriticalSectionDefaultTimeout => {
                place!(is_64bit, critical_section_default_timeout)
            }
            Self::DeCommitFreeBlockThreshold => place!(is_64bit, de_commit_free_block_threshold),
            Self::DeCommitTotalFreeThreshold => place!(is_64bit, de_commit_total_free_threshold),
            Self::LockPrefixTable => place!(is_64bit, lock_prefix_table),
            Self::MaximumAllocationSize => place!(is_64bit, maximum_allocation_size),
            Self::VirtualMemoryThreshold => place!(is_64bit, virtual_memory_threshold),
            Self::ProcessAffinityMask => place!(is_64bit, process_affinity_mask),
            Self::ProcessHeapFlags => place!(is_64bit, process_heap_flags),
            Self::CsdVersion => place!(is_64bit, csd_version),
            Self::DependentLoadFlags => place!(is_64bit, dependent_load_flags),
            Self::EditList => place!(is_64bit, edit_list),
            Self::SecurityCookie => place!(is_64bit, security_cookie),
            Self::SeHandlerTable => place!(is_64bit, se_handler_table),
            Self::SeHandlerCount => place!(is_64bit, se_handler_count),
            Self::GuardCfCheckFunctionPointer => place!(is_64bit, guard_cf_check_function_pointer),
            Self::GuardCfDispatchFunctionPointer => {
                place!(is_64bit, guard_cf_dispatch_function_pointer)
            }
            Self::GuardCfFunctionTable => place!(is_64bit, guard_cf_function_table),
            Self::GuardCfFunctionCount => place!(is_64bit, guard_cf_function_count),
            Self::GuardFlags => place!(is_64bit, guard_flags),
            Self::CodeIntegrityFlags => place!(is_64bit, code_integrity.flags),
            Self::CodeIntegrityCatalog => place!(is_64bit, code_integrity.catalog),
            Self::CodeIntegrityCatalogOffset => place!(is_64bit, code_integrity.catalog_offset),
            Self::CodeIntegrityReserved => place!(is_64bit, code_integrity.reserved),
            Self::GuardAddressTakenIatEntryTable => {
                place!(is_64bit, guard_address_taken_iat_entry_table)
            }
            Self::GuardAddressTakenIatEntryCount => {
                place!(is_64bit, guard_address_taken_iat_entry_count)
            }
            Self::GuardLongJumpTargetTable => place!(is_64bit, guard_long_jump_target_table),
            Self::GuardLongJumpTargetCount => place!(is_64bit, guard_long_jump_target_count),
            Self::DynamicValueRelocTable => place!(is_64bit, dynamic_value_reloc_table),
            Self::ChpeMetadataPointer => place!(is_64bit, chpe_metadata_pointer),
            Self::GuardRfFailureRoutine => place!(is_64bit, guard_rf_failure_routine),
            Self::GuardRfFailureRoutineFunctionPointer => {
                place!(is_64bit, guard_rf_failure_routine_function_pointer)
            }
            Self::DynamicValueRelocTableOffset => {
                place!(is_64bit, dynamic_value_reloc_table_offset)
            }
            Self::DynamicValueRelocTableSection => {
                place!(is_64bit, dynamic_value_reloc_table_section)
            }
            Self::Reserved2 => place!(is_64bit, reserved2),
            Self::GuardRfVerifyStackPointerFunctionPointer => {
                place!(is_64bit, guard_rf_verify_stack_pointer_function_pointer)
            }
            Self::HotPatchTableOffset => place!(is_64bit, hot_patch_table_offset),
            Self::Reserved3 => place!(is_64bit, reserved3),
            Self::EnclaveConfigurationPointer => place!(is_64bit, enclave_configuration_pointer),
            Self::VolatileMetadataPointer => place!(is_64bit, volatile_metadata_pointer),
            Self::GuardEhContinuationTable => place!(is_64bit, guard_eh_continuation_table),
            Self::GuardEhContinuationCount => place!(is_64bit, guard_eh_continuation_count),
            Self::GuardXfgCheckFunctionPointer => {
                place!(is_64bit, guard_xfg_check_function_pointer)
            }
            Self::GuardXfgDispatchFunctionPointer => {
                place!(is_64bit, guard_xfg_dispatch_function_pointer)
            }
            Self::GuardXfgTableDispatchFunctionPointer => {
                place!(is_64bit, guard_xfg_table_dispatch_function_pointer)
            }
            Self::CastGuardOsDeterminedFailureMode => {
                place!(is_64bit, cast_guard_os_determined_failure_mode)
            }
            Self::GuardMemcpyFunctionPointer => place!(is_64bit, guard_memcpy_function_pointer),
            Self::UmaFunctionPointers => place!(is_64bit, uma_function_pointers),
        }
    }
}

#[cfg(test)]
mod tests;
