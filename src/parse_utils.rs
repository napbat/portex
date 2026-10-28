//! Shared bounded parsing helpers.

use crate::prelude::*;
use crate::{Error, Result};

/// Read exactly `len` bytes at an RVA through the `read_at_rva` callback.
pub(crate) fn read_exact_rva<F>(
    read_at_rva: &F,
    rva: u32,
    len: usize,
    context: &str,
) -> Result<Vec<u8>>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let data = read_at_rva(rva, len).ok_or_else(|| Error::invalid_rva(rva))?;
    if data.len() != len {
        return Err(Error::invalid_data_directory(format!(
            "{context} returned {} bytes, expected {len}",
            data.len()
        )));
    }
    Ok(data)
}

/// Read a table of records at an RVA in one read. Each record has `record_size` bytes.
///
/// `size` comes from the file and can be very large. A read of each record takes time that
/// grows with `size`. One read of the complete table takes time that grows only with the bytes
/// that `read_at_rva` can return, because the RVA reader limits the zero bytes of one read.
pub(crate) fn read_record_table<F>(
    read_at_rva: &F,
    rva: u32,
    size: u32,
    record_size: usize,
    context: &str,
) -> Result<Vec<u8>>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    if size == 0 {
        return Ok(Vec::new());
    }
    // The RVA of the last record must not overflow.
    u32::try_from(record_size)
        .ok()
        .and_then(|record_size| size.checked_sub(record_size))
        .and_then(|last| rva.checked_add(last))
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))?;
    read_exact_rva(read_at_rva, rva, size as usize, context)
}

/// Read a required null-terminated UTF-8 string at an RVA.
///
/// `max_len` is a limit only: the image does not have to contain `max_len` bytes after the
/// string.
pub(crate) fn read_c_string<F>(
    read_at_rva: &F,
    rva: u32,
    max_len: usize,
    context: &str,
) -> Result<String>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let mut bytes = Vec::new();
    for index in 0..max_len {
        let offset = u32::try_from(index)
            .ok()
            .and_then(|offset| rva.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))?;
        let byte = read_at_rva(offset, 1)
            .and_then(|data| data.first().copied())
            .ok_or_else(|| Error::invalid_rva(offset))?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| Error::invalid_utf8());
        }
        bytes.push(byte);
    }
    Err(Error::invalid_data_directory(format!(
        "{context} is not null-terminated within {max_len} bytes"
    )))
}

/// Read a C string at an RVA. The string bytes must stay inside the enclosing RVA range.
pub(crate) fn read_c_string_in_range<F>(
    read_at_rva: &F,
    rva: u32,
    enclosing_rva: u32,
    enclosing_size: u32,
    max_len: usize,
    context: &str,
) -> Result<String>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let enclosing_end = u64::from(enclosing_rva)
        .checked_add(u64::from(enclosing_size))
        .ok_or_else(|| Error::invalid_data_directory("data-directory RVA overflow"))?;
    if u64::from(rva) < u64::from(enclosing_rva) || u64::from(rva) >= enclosing_end {
        return Err(Error::invalid_data_directory(format!(
            "{context} RVA {rva:#x} is outside {enclosing_rva:#x}..{enclosing_end:#x}"
        )));
    }
    let available = usize::try_from(enclosing_end - u64::from(rva)).unwrap_or(usize::MAX);
    read_c_string(read_at_rva, rva, max_len.min(available), context)
}

/// Make sure that a table of fixed-size entries at an RVA fits in the enclosing RVA range.
pub(crate) fn bounded_table_range(
    table_rva: u32,
    count: u32,
    entry_size: usize,
    enclosing_rva: u32,
    enclosing_size: u32,
    context: &str,
) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    let byte_count = u64::from(count)
        .checked_mul(entry_size as u64)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))?;
    let table_end = u64::from(table_rva)
        .checked_add(byte_count)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))?;
    let enclosing_end = u64::from(enclosing_rva)
        .checked_add(u64::from(enclosing_size))
        .ok_or_else(|| Error::invalid_data_directory("data-directory RVA overflow"))?;
    if u64::from(table_rva) < u64::from(enclosing_rva) || table_end > enclosing_end {
        return Err(Error::invalid_data_directory(format!(
            "{context} range {table_rva:#x}..{table_end:#x} is outside {enclosing_rva:#x}..{enclosing_end:#x}"
        )));
    }
    Ok(())
}
