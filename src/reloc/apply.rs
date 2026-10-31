use super::{Error, RelocationTable, RelocationType, Result};
use crate::prelude::*;

impl RelocationTable {
    /// Apply all supported base relocations to `buffer`.
    ///
    /// The function fails on a malformed range. It also fails on an architecture-specific
    /// relocation that it cannot interpret generically.
    ///
    /// The fixups are modular: each target field wraps around at its own width, as the Windows
    /// loader does.
    ///
    /// Returns the number of relocations applied.
    ///
    /// # Errors
    ///
    /// Returns an invalid-RVA error if a target field is not inside `buffer`.
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - A target RVA overflows.
    /// - A `HIGHADJ` entry does not have its adjustment word.
    /// - A `DIR64` entry occurs and `is_64bit` is false.
    /// - An entry has a machine-specific or unknown type.
    ///
    /// On error, `buffer` keeps the fixups that the function applied before the failed entry.
    pub fn try_apply(&self, buffer: &mut [u8], delta: i128, is_64bit: bool) -> Result<usize> {
        let mut applied = 0usize;
        for block in &self.blocks {
            let mut entries = block.entries.iter();
            while let Some(entry) = entries.next() {
                if entry.is_padding() {
                    continue;
                }

                let target_rva = block
                    .page_rva
                    .checked_add(u32::from(entry.offset))
                    .ok_or_else(|| {
                        Error::invalid_data_directory("base-relocation target RVA overflow")
                    })?;

                match entry.reloc_type {
                    RelocationType::HighLow => {
                        let field = target_field::<4>(buffer, target_rva)?;
                        let value = u32::from_le_bytes(*field);
                        write_wrapped(field, i128::from(value).wrapping_add(delta));
                    }
                    RelocationType::Dir64 if is_64bit => {
                        let field = target_field::<8>(buffer, target_rva)?;
                        let value = u64::from_le_bytes(*field);
                        write_wrapped(field, i128::from(value).wrapping_add(delta));
                    }
                    RelocationType::High => {
                        let field = target_field::<2>(buffer, target_rva)?;
                        let full = i128::from(u16::from_le_bytes(*field)) << 16;
                        write_wrapped(field, full.wrapping_add(delta) >> 16);
                    }
                    RelocationType::Low => {
                        let field = target_field::<2>(buffer, target_rva)?;
                        let value = u16::from_le_bytes(*field);
                        write_wrapped(field, i128::from(value).wrapping_add(delta));
                    }
                    RelocationType::HighAdj => {
                        let field = target_field::<2>(buffer, target_rva)?;
                        // The next entry holds the low half of the target, not a relocation.
                        let adjustment = entries.next().ok_or_else(|| {
                            Error::invalid_data_directory(
                                "HIGHADJ relocation is missing its adjustment word",
                            )
                        })?;
                        let low = i128::from(adjustment.to_u16().cast_signed());
                        let high = i128::from(u16::from_le_bytes(*field)) << 16;
                        let relocated = high
                            .wrapping_add(low)
                            .wrapping_add(delta)
                            .wrapping_add(0x8000);
                        write_wrapped(field, relocated >> 16);
                    }
                    RelocationType::Dir64 => {
                        return Err(Error::invalid_data_directory(
                            "DIR64 relocation appears in a PE32 image",
                        ));
                    }
                    unsupported => {
                        return Err(Error::invalid_data_directory(format!(
                            "relocation type {unsupported:?} requires machine-specific handling"
                        )));
                    }
                }
                // This cannot overflow: each entry adds one at most, and entries are in memory.
                applied += 1;
            }
        }
        Ok(applied)
    }
}

/// Return the `N`-byte target field at the RVA `rva` in `buffer`.
///
/// Returns an invalid-RVA error if the field is not fully inside `buffer`.
fn target_field<const N: usize>(buffer: &mut [u8], rva: u32) -> Result<&mut [u8; N]> {
    let start = rva as usize;
    let end = start
        .checked_add(N)
        .ok_or_else(|| Error::invalid_data_directory("relocation target range overflow"))?;
    buffer
        .get_mut(start..end)
        .and_then(|field| <&mut [u8; N]>::try_from(field).ok())
        .ok_or_else(|| Error::invalid_rva(rva))
}

/// Write the low `N` bytes of `value` in little-endian order.
///
/// This reduces `value` modulo 2^(8 * `N`), as relocation fixups require.
fn write_wrapped<const N: usize>(target: &mut [u8; N], value: i128) {
    for (byte, value_byte) in target.iter_mut().zip(value.to_le_bytes()) {
        *byte = value_byte;
    }
}
