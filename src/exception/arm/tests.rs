use super::*;

#[test]
fn huge_declared_size_does_not_reserve_memory() {
    // The largest multiple of 8 in a `u32`. Before the fix, `parse` reserved 4 GiB for
    // this size, and the reservation panicked on 32-bit targets.
    let size = u32::MAX - u32::MAX % 8;
    let result = PackedExceptionDirectory::parse(0x1000, size, |_, _| None);
    assert!(result.is_err());
}

/// Before the fix, `is_packed` was true for a `Flag` 3 record link.
#[test]
fn record_link_is_not_packed_and_has_a_parent() {
    let link = PackedRuntimeFunction {
        begin_address: 0x2000,
        unwind_data: 0x1000 | 3,
    };
    assert!(!link.is_packed());
    assert_eq!(link.parent_record_rva(), Some(0x1000));
    assert_eq!(link.exception_data_rva(), None);
    let packed = PackedRuntimeFunction {
        begin_address: 0x1000,
        unwind_data: 0x0020_0011,
    };
    assert!(packed.is_packed());
    assert_eq!(packed.parent_record_rva(), None);
}

/// Before the fix, the records were written in caller order without a check.
#[test]
fn serialization_requires_ascending_records() {
    let mut directory = PackedExceptionDirectory {
        functions: vec![
            PackedRuntimeFunction {
                begin_address: 0x2000,
                unwind_data: 1,
            },
            PackedRuntimeFunction {
                begin_address: 0x1000,
                unwind_data: 1,
            },
        ],
    };
    assert!(directory.try_to_bytes().is_err());
    directory.sort();
    assert_eq!(directory.try_to_bytes().unwrap().len(), 16);
    directory.functions[1].begin_address = 0x1000;
    assert!(directory.try_to_bytes().is_err());
}
