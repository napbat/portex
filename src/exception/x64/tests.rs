use super::*;

#[test]
fn test_runtime_function_size() {
    assert_eq!(RuntimeFunction::SIZE, 12);
}

#[test]
fn test_runtime_function_roundtrip() {
    let original = RuntimeFunction {
        begin_address: 0x1000,
        end_address: 0x1100,
        unwind_info_address: 0x2000,
    };

    let bytes = original.to_bytes();
    let parsed = RuntimeFunction::parse(&bytes).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn test_runtime_function_contains_rva() {
    let func = RuntimeFunction {
        begin_address: 0x1000,
        end_address: 0x1100,
        unwind_info_address: 0x2000,
    };

    assert!(func.contains_rva(0x1000));
    assert!(func.contains_rva(0x1050));
    assert!(!func.contains_rva(0x1100)); // End is exclusive
    assert!(!func.contains_rva(0x0FFF));
}

#[test]
fn test_exception_directory_roundtrip() {
    let mut dir = ExceptionDirectory::default();
    dir.add_function(0x1000, 0x1100, 0x2000);
    dir.add_function(0x1200, 0x1300, 0x2100);

    let bytes = dir.to_bytes();

    let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let offset = rva as usize;
        if offset >= bytes.len() {
            return None;
        }
        let available = (bytes.len() - offset).min(len);
        Some(bytes[offset..offset + available].to_vec())
    };

    let size = u32::try_from(bytes.len()).unwrap();
    let parsed = ExceptionDirectory::parse(0, size, read_fn).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed.functions[0].begin_address, 0x1000);
    assert_eq!(parsed.functions[1].begin_address, 0x1200);
}

#[test]
fn huge_declared_size_does_not_reserve_memory() {
    // The largest multiple of 12 in a `u32`. Before the fix, `parse` reserved 4 GiB for
    // this size, and the reservation panicked on 32-bit targets.
    let size = u32::MAX - u32::MAX % 12;
    let result = ExceptionDirectory::parse(0x1000, size, |_, _| None);
    assert!(result.is_err());
}

fn two_function_table() -> Vec<u8> {
    let mut dir = ExceptionDirectory::default();
    dir.add_function(0x1000, 0x1100, 0x2000);
    dir.add_function(0x1200, 0x1300, 0x2100);
    dir.to_bytes()
}

/// Parse the table with a callback that returns `len` bytes changed by `extra`.
fn parse_with_length_change(bytes: &[u8], extra: isize) -> Result<ExceptionDirectory> {
    let mut padded = bytes.to_vec();
    padded.resize(bytes.len() + 16, 0xcc);
    let size = u32::try_from(bytes.len()).unwrap();
    ExceptionDirectory::parse(0, size, |rva, len| {
        let start = usize::try_from(rva).ok()?;
        let end = start.checked_add(len.checked_add_signed(extra)?)?;
        padded.get(start..end).map(<[u8]>::to_vec)
    })
}

#[test]
fn a_longer_callback_result_is_truncated_to_the_table_size() {
    let bytes = two_function_table();
    let exact = parse_with_length_change(&bytes, 0).unwrap();
    let longer = parse_with_length_change(&bytes, 7).unwrap();
    assert_eq!(longer, exact);
    assert_eq!(longer.len(), 2);
}

#[test]
fn a_shorter_callback_result_is_an_error() {
    let bytes = two_function_table();
    assert!(parse_with_length_change(&bytes, -1).is_err());
}
