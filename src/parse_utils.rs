//! Shared bounded parsing helpers.

use nostdio::ReadLe;

use crate::prelude::*;
use crate::{Error, Result};

/// Return the `W` bytes at offset `O` of the fixed-size structure `raw`.
///
/// A compile-time assertion proves that the field is in `raw`, so the fallback never runs.
fn field<const N: usize, const O: usize, const W: usize>(raw: &[u8; N]) -> [u8; W] {
    const { assert!(O + W <= N) }
    raw.get(O..)
        .and_then(<[u8]>::first_chunk::<W>)
        .copied()
        .unwrap_or([0; W])
}

/// Write `bytes` at offset `O` of the fixed-size structure `raw`.
///
/// A compile-time assertion proves that the field is in `raw`, so the write always occurs.
fn put<const N: usize, const O: usize, const W: usize>(raw: &mut [u8; N], bytes: [u8; W]) {
    const { assert!(O + W <= N) }
    if let Some(field) = raw.get_mut(O..).and_then(<[u8]>::first_chunk_mut::<W>) {
        *field = bytes;
    }
}

/// Return the structure size `size` as a `u32`, for a `const` item.
///
/// A `const fn` cannot call `u32::try_from`, and an `as` cast can truncate. Thus the function
/// counts up. Call it only in a `const` item: there, a size that does not fit in `u32` stops the
/// build.
pub(crate) const fn size_u32(size: usize) -> u32 {
    let mut value: u32 = 0;
    let mut rest = size;
    while rest > 0 {
        value += 1;
        rest -= 1;
    }
    value
}

/// Copy the available prefix of a fixed-size structure into a zeroed array.
///
/// Return the array and the number of bytes that `data` holds, at most `N`. A field of the
/// structure is present if it ends at or before this number. Use this function where Portex
/// tolerates a structure that ends early. Where a short structure is an error, take
/// `data.first_chunk::<N>()` instead.
pub(crate) fn zero_extended<const N: usize>(data: &[u8]) -> ([u8; N], usize) {
    let mut raw = [0; N];
    let available = data.len().min(N);
    for (dst, src) in raw.iter_mut().zip(data) {
        *dst = *src;
    }
    (raw, available)
}

/// Return the byte at offset `O` of the fixed-size structure `raw`.
pub(crate) fn le_u8<const N: usize, const O: usize>(raw: &[u8; N]) -> u8 {
    u8::from_le_bytes(field::<N, O, 1>(raw))
}

/// Return the little-endian `u16` at offset `O` of the fixed-size structure `raw`.
pub(crate) fn le_u16<const N: usize, const O: usize>(raw: &[u8; N]) -> u16 {
    u16::from_le_bytes(field::<N, O, 2>(raw))
}

/// Return the little-endian `u32` at offset `O` of the fixed-size structure `raw`.
pub(crate) fn le_u32<const N: usize, const O: usize>(raw: &[u8; N]) -> u32 {
    u32::from_le_bytes(field::<N, O, 4>(raw))
}

/// Return the little-endian `u64` at offset `O` of the fixed-size structure `raw`.
pub(crate) fn le_u64<const N: usize, const O: usize>(raw: &[u8; N]) -> u64 {
    u64::from_le_bytes(field::<N, O, 8>(raw))
}

/// Write the byte `value` at offset `O` of the fixed-size structure `raw`.
pub(crate) fn put_u8<const N: usize, const O: usize>(raw: &mut [u8; N], value: u8) {
    put::<N, O, 1>(raw, value.to_le_bytes());
}

/// Write the little-endian `u16` `value` at offset `O` of the fixed-size structure `raw`.
pub(crate) fn put_u16<const N: usize, const O: usize>(raw: &mut [u8; N], value: u16) {
    put::<N, O, 2>(raw, value.to_le_bytes());
}

/// Write the little-endian `u32` `value` at offset `O` of the fixed-size structure `raw`.
pub(crate) fn put_u32<const N: usize, const O: usize>(raw: &mut [u8; N], value: u32) {
    put::<N, O, 4>(raw, value.to_le_bytes());
}

/// Write the little-endian `u64` `value` at offset `O` of the fixed-size structure `raw`.
pub(crate) fn put_u64<const N: usize, const O: usize>(raw: &mut [u8; N], value: u64) {
    put::<N, O, 8>(raw, value.to_le_bytes());
}

/// Read the little-endian `u16` at `offset` of `data` with `nostdio`.
///
/// Return `None` if `data` does not hold the complete value.
pub(crate) fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let mut rest = data.get(offset..)?;
    rest.read_u16_le().ok()
}

/// Read the little-endian `u32` at `offset` of `data` with `nostdio`.
///
/// Return `None` if `data` does not hold the complete value.
pub(crate) fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let mut rest = data.get(offset..)?;
    rest.read_u32_le().ok()
}

/// Read the little-endian `u64` at `offset` of `data` with `nostdio`.
///
/// Return `None` if `data` does not hold the complete value.
pub(crate) fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    let mut rest = data.get(offset..)?;
    rest.read_u64_le().ok()
}

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
/// The callback can return more than `size` bytes. Only the first `size` bytes are used. A
/// shorter result is an error.
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
    let len = usize::try_from(size)
        .map_err(|_| Error::invalid_data_directory(format!("{context} size overflow")))?;
    let mut data = read_at_rva(rva, len).ok_or_else(|| Error::invalid_rva(rva))?;
    if data.len() < len {
        return Err(Error::invalid_data_directory(format!(
            "{context} returned {} bytes, expected {len}",
            data.len()
        )));
    }
    data.truncate(len);
    Ok(data)
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
