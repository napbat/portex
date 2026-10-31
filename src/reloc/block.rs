use super::{Error, RelocationEntry, Result};
use crate::prelude::*;

/// A block of relocations for a single 4-KiB page.
///
/// On disk, a block is an `IMAGE_BASE_RELOCATION` header (8 bytes) followed by its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationBlock {
    /// RVA of the page (the base address for the relocations of this block).
    pub page_rva: u32,
    /// Total size of this block in bytes, including the header.
    pub block_size: u32,
    /// Relocation entries for this page.
    pub entries: Vec<RelocationEntry>,
}

impl RelocationBlock {
    /// Size of the `IMAGE_BASE_RELOCATION` header (`VirtualAddress` and
    /// `SizeOfBlock`) in bytes.
    pub const HEADER_SIZE: usize = Self::HEADER_SIZE_U32 as usize;
    /// [`Self::HEADER_SIZE`] as a `u32`, for arithmetic on directory sizes.
    pub(super) const HEADER_SIZE_U32: u32 = 8;

    /// Parse a relocation block from bytes.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::BufferTooSmall` if `data` is shorter than the header or the declared
    /// block size.
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - The block size is smaller than the header or is not a multiple of 4.
    /// - The page RVA is not aligned to 4 KiB.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some((&[p0, p1, p2, p3, s0, s1, s2, s3], body)) = data.split_first_chunk::<8>() else {
            return Err(Error::buffer_too_small(Self::HEADER_SIZE, data.len()));
        };

        let page_rva = u32::from_le_bytes([p0, p1, p2, p3]);
        let block_size_raw = u32::from_le_bytes([s0, s1, s2, s3]);

        let block_size = block_size_raw as usize;
        let Some(entries_size) = block_size
            .checked_sub(Self::HEADER_SIZE)
            .filter(|_| block_size.is_multiple_of(4))
        else {
            return Err(Error::invalid_data_directory(format!(
                "invalid base-relocation block size {block_size}"
            )));
        };
        if !page_rva.is_multiple_of(0x1000) {
            return Err(Error::invalid_data_directory(format!(
                "base-relocation page RVA {page_rva:#x} is not 4-KiB aligned"
            )));
        }

        let entry_bytes = body
            .get(..entries_size)
            .ok_or_else(|| Error::buffer_too_small(block_size, data.len()))?;
        // `entries_size` is even, so no bytes remain after the pairs.
        let (pairs, _) = entry_bytes.as_chunks::<2>();
        let entries = pairs
            .iter()
            .map(|pair| RelocationEntry::from_u16(u16::from_le_bytes(*pair)))
            .collect();

        Ok(Self {
            page_rva,
            block_size: block_size_raw,
            entries,
        })
    }

    /// Calculate the RVA of a specific entry. On overflow, the result saturates to
    /// `u32::MAX`.
    #[must_use]
    pub fn rva_for_entry(&self, entry: RelocationEntry) -> u32 {
        self.checked_rva_for_entry(entry).unwrap_or(u32::MAX)
    }

    /// Calculate the RVA of an entry. Returns `None` on overflow.
    #[must_use]
    pub fn checked_rva_for_entry(&self, entry: RelocationEntry) -> Option<u32> {
        self.page_rva.checked_add(u32::from(entry.offset))
    }

    /// Serialize the block to bytes.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("relocation block build failed: use try_to_bytes()")
    }

    /// Serialize the block to bytes, with a checked size and 12-bit offsets.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error in these conditions:
    ///
    /// - The page RVA is not aligned to 4 KiB.
    /// - An entry offset is wider than 12 bits.
    /// - An entry type is [`RelocationType::Unknown`](super::RelocationType::Unknown) with a
    ///   value that is wider than 4 bits or that is the code of a named type.
    /// - The target RVA of an entry overflows.
    /// - The block size is more than `u32::MAX`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        if !self.page_rva.is_multiple_of(0x1000) {
            return Err(Error::invalid_data_directory(format!(
                "base-relocation page RVA {:#x} is not 4-KiB aligned",
                self.page_rva
            )));
        }
        for entry in &self.entries {
            if entry.offset > 0x0fff {
                return Err(Error::invalid_data_directory(format!(
                    "relocation offset {:#x} exceeds 12 bits",
                    entry.offset
                )));
            }
            if !entry.reloc_type.is_canonical() {
                return Err(Error::invalid_data_directory(format!(
                    "relocation type {:?} is not a canonical four-bit code",
                    entry.reloc_type
                )));
            }
            self.page_rva
                .checked_add(u32::from(entry.offset))
                .ok_or_else(|| {
                    Error::invalid_data_directory("base-relocation target RVA overflow")
                })?;
        }
        // An odd entry count requires one IMAGE_REL_BASED_ABSOLUTE padding word.
        let needs_padding = !self.entries.len().is_multiple_of(2);
        let size = self
            .entries
            .len()
            .checked_add(usize::from(needs_padding))
            .and_then(|count| count.checked_mul(2))
            .and_then(|size| Self::HEADER_SIZE.checked_add(size))
            .ok_or_else(|| Error::invalid_data_directory("relocation block size overflow"))?;
        let size_u32 = u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("relocation block exceeds u32"))?;
        let mut buf = Vec::with_capacity(size);

        buf.extend_from_slice(&self.page_rva.to_le_bytes());
        buf.extend_from_slice(&size_u32.to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.to_u16().to_le_bytes());
        }
        if needs_padding {
            buf.extend_from_slice(&[0, 0]);
        }

        Ok(buf)
    }
}
