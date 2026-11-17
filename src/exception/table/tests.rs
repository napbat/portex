use super::*;
use crate::exception::PackedRuntimeFunction;

fn parse_records(machine: MachineType, records: &[[u32; 2]]) -> Result<ExceptionTable> {
    let bytes: Vec<u8> = records
        .iter()
        .flat_map(|&[begin_address, unwind_data]| {
            PackedRuntimeFunction {
                begin_address,
                unwind_data,
            }
            .to_bytes()
        })
        .collect();
    let size = u32::try_from(bytes.len()).unwrap();
    ExceptionTable::parse(machine as u16, 0x7000, size, |rva, len| {
        let start = usize::try_from(rva.checked_sub(0x7000)?).ok()?;
        bytes
            .get(start..start.checked_add(len)?)
            .map(<[u8]>::to_vec)
    })
}

/// Before the fix, an odd `begin_address` (the Thumb bit) was rejected.
#[test]
fn arm_nt_accepts_the_thumb_bit() {
    let table = parse_records(MachineType::ArmNt, &[[0x1001, 0x0020_0001]]).unwrap();
    let ExceptionTable::Arm(directory) = table else {
        panic!("expected an ARM NT table");
    };
    assert_eq!(directory.functions[0].begin_address, 0x1001);
}

/// Before the fix, a `Flag` 3 record link was rejected as reserved.
#[test]
fn arm64_accepts_record_links() {
    let table = parse_records(MachineType::Arm64, &[[0x1000, 0x0020_0011], [0x2000, 3]]).unwrap();
    let ExceptionTable::Arm64(directory) = table else {
        panic!("expected an ARM64 table");
    };
    assert_eq!(directory.functions[1].parent_record_rva(), Some(0));
    assert!(parse_records(MachineType::Arm64, &[[0x1002, 1]]).is_err());
}

/// Before the fix, Windows CE ARM tables were decoded as Windows NT ARM records.
#[test]
fn windows_ce_arm_tables_are_raw() {
    for machine in [MachineType::Arm, MachineType::Thumb] {
        let table = parse_records(machine, &[[0x1000, 0x8000_0001]]).unwrap();
        assert!(
            matches!(table, ExceptionTable::Raw { machine: raw, ref data }
                if raw == machine as u16 && data.len() == 8)
        );
    }
}
