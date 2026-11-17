use super::*;

#[test]
fn borrowed_handler_payload_is_serialized_without_owned_replacement() {
    let info = UnwindInfo {
        version_flags: 1 | (UNW_FLAG_EHANDLER << 3),
        exception_handler: Some(0x3000),
        handler_data: vec![0xaa],
        ..UnwindInfo::default()
    };
    let bytes = info
        .try_to_bytes_with_handler_data(&[0x11, 0x22, 0x33])
        .expect("borrowed language metadata is valid");
    assert_eq!(&bytes[4..8], &0x3000_u32.to_le_bytes());
    assert_eq!(&bytes[8..], &[0x11, 0x22, 0x33]);
    assert_eq!(info.handler_data, [0xaa]);
    assert_eq!(
        &info.try_to_bytes().expect("owned metadata remains valid")[8..],
        &[0xaa]
    );
    let unhandled = UnwindInfo {
        version_flags: 1,
        ..UnwindInfo::default()
    };
    assert!(unhandled.try_to_bytes_with_handler_data(&[1]).is_err());
}

/// Before the fix, `count_of_codes` and `chained_info` were fields that serialization
/// ignored. A value with default fields did not survive a round trip.
#[test]
fn serialized_record_round_trips_without_redundant_fields() {
    let info = UnwindInfo {
        version_flags: 1 | (UNW_FLAG_CHAININFO << 3),
        size_of_prolog: 4,
        unwind_codes: vec![UnwindCode {
            code_offset: 4,
            op_and_info: 0x32,
        }],
        chained_function: Some(RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1100,
            unwind_info_address: 0x2000,
        }),
        ..UnwindInfo::default()
    };
    let bytes = info.try_to_bytes().unwrap();
    assert_eq!(bytes[2], 1);
    assert_eq!(UnwindInfo::parse(&bytes).unwrap(), info);
}
