//! PE checksum calculation.
//!
//! The PE checksum lets a tool verify the integrity of a PE file. Drivers and system files
//! usually have a checksum.

use core::mem::{offset_of, size_of};

use nostdio::ReadLe;

use crate::dos::{DosHeader, ImageDosHeader};
use crate::optional::{ImageNtHeaders32, ImageNtHeaders64};
use crate::parse_utils::{le_u32, zero_extended};

/// The offset of `CheckSum` from the start of the NT headers (the PE signature).
const CHECK_SUM_OFFSET: usize = offset_of!(ImageNtHeaders32, optional_header.check_sum);

/// The size of the `CheckSum` field (a `DWORD`), in bytes.
const CHECK_SUM_SIZE: usize = size_of::<u32>();

// PE32 and PE32+ put `CheckSum` at the same offset.
const _: () = assert!(CHECK_SUM_OFFSET == offset_of!(ImageNtHeaders64, optional_header.check_sum));

/// Calculate the PE checksum for a file.
///
/// `checksum_offset` is the file offset `o` of the `CheckSum` field. The algorithm gives the same
/// result as `CheckSumMappedFile` in Windows `imagehlp.dll`, also for an odd `o` and for an odd
/// file size:
///
/// 1. Add the 16-bit little-endian words of `data[..o & !1]`. Use 32-bit arithmetic with an
///    end-around carry.
/// 2. Skip the bytes from `o & !1` up to `o + 4`. For an even `o`, these are the 4 bytes of the
///    checksum field. For an odd `o`, these are the byte `o - 1` and the 4 field bytes.
/// 3. Add the 16-bit words of `data[o + 4..]`, with new pairs that start at `o + 4`. Skip a last
///    byte that has no pair.
/// 4. If the file size is odd, add the last byte of the file as a word with a zero high byte.
///    Add it also if step 3 added it, or if it is in the checksum field.
/// 5. Fold the result to 16 bits.
/// 6. Add the file size (modulo 2^32).
///
/// For an even `o`, the result is the sum of all words with the field bytes as zero.
///
/// If `o` is odd and the field ends at the end of a file with an odd size, the result includes
/// the last field byte (step 4). Then a write of the result to the field can change the result.
///
/// If the field ends after the end of `data`, step 3 and step 4 do not occur. Then the result is
/// the sum of the words of `data[..o & !1]` (or of all of `data`) plus the file size.
#[must_use]
pub fn calculate_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let start = checksum_offset & !1;
    let sum = if let Some(after) = data.get(checksum_offset.saturating_add(CHECK_SUM_SIZE)..) {
        // The field is in `data`, so `data[..start]` exists and has an even length.
        let before = data.get(..start).unwrap_or_default();
        add_odd_byte(add_words(add_words(0, before), after), data)
    } else {
        let before = data.get(..start).unwrap_or(data);
        add_odd_byte(add_words(0, before), before)
    };

    // Add the file size. The algorithm uses only the low 32 bits.
    // `usize` has 32 bits on some targets, so the mask works on a `u64`.
    let size_low = u64::try_from(data.len())
        .ok()
        .and_then(|len| u32::try_from(len & u64::from(u32::MAX)).ok())
        .unwrap_or_default();
    sum.wrapping_add(size_low)
}

/// Add the 16-bit little-endian words of `bytes` to `sum`, with an end-around carry.
///
/// Skip a last byte that has no pair.
fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    // Folding after every addition keeps `sum` within 16 bits, so adding a
    // 16-bit word never overflows a `u32`.
    let mut words = bytes;
    while let Ok(word) = words.read_u16_le() {
        sum = fold_carry(sum + u32::from(word));
    }
    sum
}

/// Add the last byte of `bytes` to `sum` if `bytes` has an odd length.
fn add_odd_byte(sum: u32, bytes: &[u8]) -> u32 {
    match bytes.as_chunks::<2>().1 {
        [byte] => fold_carry(sum + u32::from(*byte)),
        _ => sum,
    }
}

/// Fold the carry above bit 15 back into the low 16 bits (end-around carry).
const fn fold_carry(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum
}

/// Get the file offset of the `CheckSum` field in the optional header
/// (`IMAGE_OPTIONAL_HEADER32` or `IMAGE_OPTIONAL_HEADER64`).
///
/// Returns `None` if the PE is malformed or does not have an optional header.
#[must_use]
pub fn checksum_field_offset(data: &[u8]) -> Option<usize> {
    const E_LFANEW: usize = offset_of!(ImageDosHeader, e_lfanew);
    let (dos, available) = zero_extended::<{ DosHeader::SIZE }>(data);
    if available < E_LFANEW + size_of::<i32>() {
        return None;
    }
    let pe_offset = usize::try_from(le_u32::<{ DosHeader::SIZE }, E_LFANEW>(&dos)).ok()?;
    let checksum_offset = pe_offset.checked_add(CHECK_SUM_OFFSET)?;

    if checksum_offset.checked_add(CHECK_SUM_SIZE)? > data.len() {
        return None;
    }

    Some(checksum_offset)
}

/// Calculate and return the checksum for PE data.
///
/// Returns `None` if this function cannot find the file offset of the checksum field.
#[must_use]
pub fn compute_pe_checksum(data: &[u8]) -> Option<u32> {
    let offset = checksum_field_offset(data)?;
    Some(calculate_checksum(data, offset))
}

#[cfg(test)]
mod tests;
