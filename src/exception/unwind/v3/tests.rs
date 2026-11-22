use super::*;
use crate::exception::{UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER};

/// `KeBugCheck` of ntoskrnl.exe 10.0.28000.3365.
const KE_BUG_CHECK: [u8; 6] = [0x03, 0x04, 0x01, 0x01, 0x00, 0x48];

/// `KeBugCheckEx` of ntoskrnl.exe 10.0.28000.3365.
const KE_BUG_CHECK_EX: [u8; 8] = [0x03, 0x19, 0x02, 0x02, 0x15, 0x14, 0x58, 0x08];

/// `KeContextToKframes` of ntoskrnl.exe 10.0.28000.3365. The fragment has 0xEC bytes.
const KE_CONTEXT_TO_KFRAMES: [u8; 68] = [
    0x03, 0x52, 0x20, 0x2c, 0x49, 0x40, 0x37, 0x2e, 0x25, 0x1f, 0x19, 0x13, 0x0e, 0x09, 0x02, 0x00,
    0x60, 0xae, 0xff, 0x00, 0x00, 0x51, 0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x33, 0x39, 0x3f, 0x44,
    0x49, 0x50, 0xfa, 0x0c, 0x00, 0xea, 0x0b, 0x00, 0xda, 0x0a, 0x00, 0xca, 0x09, 0x00, 0xba, 0x08,
    0x00, 0xaa, 0x07, 0x00, 0x9a, 0x06, 0x00, 0x8a, 0x05, 0x00, 0x7a, 0x04, 0x00, 0x6a, 0x03, 0x00,
    0x02, 0x1a, 0x00, 0x1c,
];

/// The function at RVA 0x55E180 of ntoskrnl.exe 10.0.28000.3365. The fragment has 118 bytes.
/// The second epilog inherits the operations of the first epilog.
const INHERITED_EPILOG: [u8; 26] = [
    0x03, 0x09, 0x0b, 0x44, 0x05, 0x03, 0x02, 0x00, 0x20, 0xf3, 0xff, 0x00, 0x00, 0x08, 0x00, 0x04,
    0x06, 0x07, 0x00, 0xf3, 0xff, 0x38, 0x44, 0x0c, 0x14, 0x00,
];

/// Parse `bytes`, and check that the record serializes to the same bytes.
fn parse_round_trip(bytes: &[u8]) -> UnwindInfoV3 {
    let info = UnwindInfoV3::parse(bytes).expect("the record parses");
    assert_eq!(info.try_to_bytes().expect("the record serializes"), bytes);
    info
}

#[test]
fn ke_bug_check_allocates_0x28_bytes() {
    let info = parse_round_trip(&KE_BUG_CHECK);
    assert_eq!(info.size_of_prolog, 4);
    assert_eq!(
        info.prolog_ops().unwrap(),
        [(0, WindOp::AllocSmall { size: 4 })]
    );
    assert_eq!(info.epilogs, [] as [EpilogV3; 0]);
    assert!(info.epilog_fields(0).is_err());
    assert!(!info.has_exception_handler());
    assert!(!info.is_chained());

    let any = X64UnwindInfo::parse(&KE_BUG_CHECK).unwrap();
    assert_eq!(any.version(), 3);
    assert_eq!(any.flags(), 0);
    assert_eq!(any.size_of_prolog(), 4);
    assert!(any.has_operations());
    assert!(!any.has_exception_handler());
    assert_eq!(any.exception_handler(), None);
    assert_eq!(any.chained_function(), None);
    assert_eq!(any.handler_data(), [0_u8; 0]);
    assert_eq!(any.try_to_bytes().unwrap(), KE_BUG_CHECK);
    assert_eq!(any, X64UnwindInfo::V3(info));
}

#[test]
fn ke_bug_check_ex_has_two_small_allocations() {
    let info = parse_round_trip(&KE_BUG_CHECK_EX);
    assert_eq!(info.size_of_prolog, 0x19);
    assert_eq!(
        info.prolog_ops().unwrap(),
        [
            (0x15, WindOp::AllocSmall { size: 5 }),
            (0x14, WindOp::AllocSmall { size: 0 }),
        ]
    );
}

#[test]
fn ke_context_to_kframes_decodes_its_epilog() {
    let info = parse_round_trip(&KE_CONTEXT_TO_KFRAMES);
    assert_eq!(info.size_of_prolog, 0x52);
    let prolog_ips: [u16; 12] = [
        0x49, 0x40, 0x37, 0x2e, 0x25, 0x1f, 0x19, 0x13, 0x0e, 0x09, 0x02, 0x00,
    ];
    let mut wods: Vec<WindOp> = (0..10_u8)
        .map(|index| WindOp::SaveXmm128 {
            register: 15 - index,
            displacement: u16::from(0x0c - index),
        })
        .collect();
    wods.push(WindOp::AllocLarge { size: 0x1a });
    wods.push(WindOp::Push { register: 3 });
    let prolog: Vec<_> = prolog_ips.into_iter().zip(wods.iter().copied()).collect();
    assert_eq!(info.prolog_ops().unwrap(), prolog);

    let epilog_ips: Vec<u16> = vec![
        0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x33, 0x39, 0x3f, 0x44, 0x49, 0x50,
    ];
    assert_eq!(
        info.epilogs,
        [EpilogV3 {
            flags: 0,
            offset: -82,
            ops: Some(EpilogOpsV3 {
                first_op: 0,
                last_instruction: 0x51,
                ip_offsets: epilog_ips.clone(),
            }),
        }]
    );
    let expected_ops: Vec<_> = epilog_ips.into_iter().zip(wods).collect();
    assert_eq!(info.epilog_ops(0).unwrap(), expected_ops);
    assert_eq!(info.epilog_fields(0).unwrap().last_instruction, 0x51);
}

#[test]
fn every_wod_kind_decodes_and_encodes() {
    let cases: [(&[u8], WindOp); 12] = [
        (
            &[0x00, 0x35],
            WindOp::SetFrameRegister {
                register: 5,
                offset: 3,
            },
        ),
        (&[0x78], WindOp::AllocSmall { size: 7 }),
        (&[0x02, 0x34, 0x12], WindOp::AllocLarge { size: 0x1234 }),
        (
            &[0x01, 0x78, 0x56, 0x34, 0x12],
            WindOp::AllocHuge { size: 0x1234_5678 },
        ),
        (&[0x03, 0x02], WindOp::PushCanonicalFrame { kind: 2 }),
        (&[0xfc], WindOp::Push { register: 31 }),
        (
            &[0x60, 0xb4],
            WindOp::Push2 {
                first: 17,
                second: 22,
            },
        ),
        (&[0xf7], WindOp::PushConsecutive2 { register: 30 }),
        (
            &[0x66, 0x02, 0x01],
            WindOp::SaveNonvol {
                register: 12,
                displacement: 0x0102,
            },
        ),
        (
            &[0xa5, 0x00, 0x00, 0x01, 0x00],
            WindOp::SaveNonvolFar {
                register: 20,
                displacement: 0x0001_0000,
            },
        ),
        (
            &[0x9a, 0x03, 0x02],
            WindOp::SaveXmm128 {
                register: 9,
                displacement: 0x0203,
            },
        ),
        (
            &[0xe9, 0x00, 0x00, 0x02, 0x00],
            WindOp::SaveXmm128Far {
                register: 14,
                displacement: 0x0002_0000,
            },
        ),
    ];
    for (bytes, op) in cases {
        assert_eq!(WindOp::decode(bytes).unwrap(), (op, bytes.len()), "{op:?}");
        let mut longer = bytes.to_vec();
        longer.push(0x04);
        assert_eq!(
            WindOp::decode(&longer).unwrap(),
            (op, bytes.len()),
            "{op:?}"
        );
        assert!(WindOp::decode(&bytes[..bytes.len() - 1]).is_err(), "{op:?}");
        assert_eq!(op.encoded_len(), bytes.len(), "{op:?}");
        let mut encoded = Vec::new();
        op.encode(&mut encoded).expect("each field is in its range");
        assert_eq!(encoded, bytes, "{op:?}");
    }
}

#[test]
fn a_wod_field_out_of_range_is_an_error() {
    for op in [
        WindOp::SetFrameRegister {
            register: 16,
            offset: 0,
        },
        WindOp::SetFrameRegister {
            register: 5,
            offset: 16,
        },
        WindOp::AllocSmall { size: 16 },
        WindOp::Push { register: 32 },
        WindOp::Push2 {
            first: 32,
            second: 0,
        },
        WindOp::Push2 {
            first: 0,
            second: 32,
        },
        WindOp::PushConsecutive2 { register: 31 },
        WindOp::SaveNonvol {
            register: 32,
            displacement: 0,
        },
        WindOp::SaveNonvolFar {
            register: 32,
            displacement: 0,
        },
        WindOp::SaveXmm128 {
            register: 16,
            displacement: 0,
        },
        WindOp::SaveXmm128Far {
            register: 16,
            displacement: 0,
        },
    ] {
        let mut out = vec![0xaa];
        assert!(op.encode(&mut out).is_err(), "{op:?}");
        assert_eq!(out, [0xaa], "{op:?}");
    }
}

#[test]
fn an_invalid_wod_is_an_error() {
    assert!(WindOp::decode(&[]).is_err());
    // The low 4 bits 0xB are not an opcode.
    assert!(WindOp::decode(&[0x0b, 0x00, 0x00]).is_err());
    // The low 6 bits 0x10 are not an opcode, and 0x10 is not an 8-bit opcode.
    assert!(WindOp::decode(&[0x10, 0x00]).is_err());
    // WOD_PUSH_CONSECUTIVE_2 cannot name register 31.
    assert!(WindOp::decode(&[0xff]).is_err());
    // A record with an invalid opcode in its prolog WOD list.
    assert!(UnwindInfoV3::parse(&[0x03, 0x04, 0x01, 0x01, 0x00, 0x0b]).is_err());
}

#[test]
fn an_inherited_epilog_takes_the_operations_of_its_source() {
    let info = parse_round_trip(&INHERITED_EPILOG);
    assert_eq!(info.epilogs.len(), 2);
    assert_eq!(info.epilogs[1].ops, None);
    assert_eq!(info.epilogs[1].offset, -13);
    let prolog = info.prolog_ops().unwrap();
    assert_eq!(
        prolog,
        [
            (5, WindOp::AllocSmall { size: 3 }),
            (3, WindOp::Push { register: 8 }),
            (2, WindOp::Push { register: 1 }),
            (0, WindOp::Push { register: 2 }),
        ]
    );
    let ops: Vec<_> = [0_u16, 4, 6, 7]
        .into_iter()
        .zip(prolog.into_iter().map(|(_, op)| op))
        .collect();
    assert_eq!(info.epilog_ops(0).unwrap(), ops);
    assert_eq!(info.epilog_ops(1).unwrap(), ops);
    assert_eq!(
        info.epilog_fields(1).unwrap(),
        info.epilog_fields(0).unwrap()
    );
}

#[test]
fn a_large_record_round_trips() {
    let mut pool = Vec::new();
    WindOp::AllocLarge { size: 0x40 }
        .encode(&mut pool)
        .expect("the size fits");
    WindOp::Push { register: 5 }
        .encode(&mut pool)
        .expect("rbp is a register");
    let info = UnwindInfoV3 {
        flags: UNW_FLAG_LARGE,
        size_of_prolog: 0x0123,
        prolog_ip_offsets: vec![0x0110, 0x0004],
        epilogs: vec![EpilogV3 {
            flags: 0x02,
            offset: 0x0200,
            ops: Some(EpilogOpsV3 {
                first_op: 0,
                last_instruction: 0x0105,
                ip_offsets: vec![0x0100, 0x0000],
            }),
        }],
        pool,
        ..UnwindInfoV3::default()
    };
    let bytes = info.try_to_bytes().unwrap();
    assert_eq!(bytes[..5], [0x43, 0x23, 10, 0x22, 0x01]);
    assert_eq!(bytes[5..9], [0x10, 0x01, 0x04, 0x00]);
    assert_eq!(bytes.len(), 4 + 20);
    assert_eq!(UnwindInfoV3::parse(&bytes).unwrap(), info);
    assert_eq!(info.epilog_fields(0).unwrap().last_instruction, 0x0105);

    let small = UnwindInfoV3 {
        flags: 0,
        ..info.clone()
    };
    assert!(small.validate().is_err());
    let mut small_epilog = info;
    small_epilog.epilogs[0].flags = 0;
    assert!(small_epilog.validate().is_err());
}

#[test]
fn a_handler_record_round_trips() {
    let info = UnwindInfoV3 {
        flags: UNW_FLAG_EHANDLER,
        size_of_prolog: 4,
        prolog_ip_offsets: vec![0],
        pool: vec![0x48],
        exception_handler: Some(0x1234_5678),
        handler_data: vec![0xaa, 0xbb, 0xcc],
        ..UnwindInfoV3::default()
    };
    let bytes = info.try_to_bytes().unwrap();
    assert_eq!(bytes[..6], [0x0b, 0x04, 0x01, 0x01, 0x00, 0x48]);
    assert_eq!(bytes[6..8], [0, 0]);
    assert_eq!(bytes[8..12], 0x1234_5678_u32.to_le_bytes());
    assert_eq!(bytes[12..], [0xaa, 0xbb, 0xcc]);
    assert_eq!(parse_round_trip(&bytes), info);
    assert!(info.has_exception_handler());

    let borrowed = info.try_to_bytes_with_handler_data(&[1, 2]).unwrap();
    assert_eq!(borrowed[12..], [1, 2]);
    let any = X64UnwindInfo::parse(&bytes).unwrap();
    assert_eq!(any.exception_handler(), Some(0x1234_5678));
    assert_eq!(any.handler_data(), [0xaa, 0xbb, 0xcc]);

    let unhandled = UnwindInfoV3 {
        flags: 0,
        exception_handler: None,
        handler_data: Vec::new(),
        ..info
    };
    assert!(unhandled.try_to_bytes_with_handler_data(&[1]).is_err());
    assert!(UnwindInfoV3::parse(&bytes[..10]).is_err());
}

#[test]
fn a_chained_record_round_trips() {
    let chained = RuntimeFunction {
        begin_address: 0x1000,
        end_address: 0x1100,
        unwind_info_address: 0x2000,
    };
    let info = UnwindInfoV3 {
        flags: UNW_FLAG_CHAININFO,
        size_of_prolog: 1,
        prolog_ip_offsets: vec![0],
        pool: vec![0x1c],
        chained_function: Some(chained),
        ..UnwindInfoV3::default()
    };
    let bytes = info.try_to_bytes().unwrap();
    assert_eq!(bytes.len(), 8 + RuntimeFunction::SIZE);
    assert_eq!(bytes[8..], chained.to_bytes());
    assert_eq!(parse_round_trip(&bytes), info);
    assert!(info.is_chained());
    let any = X64UnwindInfo::parse(&bytes).unwrap();
    assert!(any.is_chained());
    assert_eq!(any.chained_function(), Some(chained));
    assert!(UnwindInfoV3::parse(&bytes[..19]).is_err());
}

#[test]
fn a_truncated_payload_is_an_error() {
    assert!(UnwindInfoV3::parse(&KE_BUG_CHECK[..5]).is_err());
    assert!(UnwindInfoV3::parse(&KE_BUG_CHECK[..3]).is_err());
    // PayloadWords is 1, but the descriptor of the one epilog needs 3 bytes.
    assert!(UnwindInfoV3::parse(&[0x03, 0x00, 0x01, 0x20, 0x00, 0x00]).is_err());
}

#[test]
fn a_wod_list_that_leaves_the_pool_is_an_error() {
    // WOD_ALLOC_LARGE needs 3 bytes, but the pool has 1 byte.
    assert!(UnwindInfoV3::parse(&[0x03, 0x04, 0x01, 0x01, 0x00, 0x02]).is_err());
    let mut info = UnwindInfoV3::parse(&INHERITED_EPILOG).unwrap();
    let ops = info.epilogs[0].ops.as_mut().unwrap();
    ops.first_op = 3;
    assert!(info.validate().is_err());
    let ops = info.epilogs[0].ops.as_mut().unwrap();
    ops.first_op = 6;
    assert!(info.validate().is_err());
}

#[test]
fn a_first_inherited_epilog_is_an_error() {
    assert!(UnwindInfoV3::parse(&[0x03, 0x00, 0x02, 0x20, 0x00, 0xf3, 0xff, 0x00]).is_err());
    let mut info = UnwindInfoV3::parse(&INHERITED_EPILOG).unwrap();
    info.epilogs.remove(0);
    assert!(info.validate().is_err());
    assert!(info.epilog_fields(0).is_err());
}

#[test]
fn inherited_flags_must_match_their_source() {
    let mut bytes = INHERITED_EPILOG;
    // Set EPILOG_INFO_PARENT_FRAGMENT_TRANSFER on the inherited epilog only.
    bytes[18] = 0x01;
    assert!(UnwindInfoV3::parse(&bytes).is_err());
    // Set it on both epilogs.
    bytes[8] = 0x21;
    let info = parse_round_trip(&bytes);
    assert_eq!(info.epilogs[1].flags, 0x01);
}

#[test]
fn a_sign_change_of_epilog_offsets_is_an_error() {
    let mut bytes = INHERITED_EPILOG;
    bytes[19..21].copy_from_slice(&5_i16.to_le_bytes());
    assert!(UnwindInfoV3::parse(&bytes).is_err());
    // An offset of zero has no sign.
    bytes[19..21].copy_from_slice(&0_i16.to_le_bytes());
    let info = parse_round_trip(&bytes);
    assert_eq!(info.epilogs[1].offset, 0);
}

#[test]
fn a_reserved_flag_bit_is_an_error() {
    let mut bytes = KE_BUG_CHECK;
    // Header flag bit 4.
    bytes[0] = 0x83;
    assert!(UnwindInfoV3::parse(&bytes).is_err());
    let mut bytes = INHERITED_EPILOG;
    // Epilog flag bit 2.
    bytes[8] = 0x24;
    assert!(UnwindInfoV3::parse(&bytes).is_err());
    // UNW_FLAG_CHAININFO with a handler flag.
    let mut bytes = KE_BUG_CHECK.to_vec();
    bytes[0] = 0x03 | ((UNW_FLAG_CHAININFO | UNW_FLAG_EHANDLER) << 3);
    bytes.resize(8 + RuntimeFunction::SIZE, 0);
    assert!(UnwindInfoV3::parse(&bytes).is_err());
}

#[test]
fn an_odd_payload_is_an_error() {
    let info = UnwindInfoV3 {
        prolog_ip_offsets: vec![0],
        pool: vec![0x48, 0x00],
        ..UnwindInfoV3::default()
    };
    assert!(info.validate().is_err());
    assert!(info.try_to_bytes().is_err());
}

#[test]
fn x64_unwind_info_dispatches_on_the_version() {
    let classic = [0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00];
    let any = X64UnwindInfo::parse(&classic).unwrap();
    assert_eq!(any.version(), 1);
    assert_eq!(any.size_of_prolog(), 4);
    assert!(any.has_operations());
    assert_eq!(
        any,
        X64UnwindInfo::Classic(UnwindInfo::parse(&classic).unwrap())
    );
    assert_eq!(any.try_to_bytes().unwrap(), classic);

    let error = X64UnwindInfo::parse(&[0x04, 0x00, 0x00, 0x00]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported x64 unwind version 4")
    );
    assert!(X64UnwindInfo::parse(&[0x00, 0x00, 0x00, 0x00]).is_err());
    assert!(X64UnwindInfo::parse(&[]).is_err());
    // `UnwindInfo` keeps to versions 1 and 2.
    assert!(UnwindInfo::parse(&KE_BUG_CHECK).is_err());
}
