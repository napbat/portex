use super::{Error, RelocationBlock, RelocationEntry, RelocationType, Result};
use crate::prelude::*;

/// The complete relocation table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationTable {
    /// List of relocation blocks.
    pub blocks: Vec<RelocationBlock>,
}

impl RelocationTable {
    /// Parse the relocation table of a PE file.
    ///
    /// - `reloc_rva` is the RVA from the data directory.
    /// - `reloc_size` is the size from the data directory.
    /// - `read_at_rva` is a closure that reads bytes at an RVA.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    ///
    /// - The closure cannot read a block.
    /// - A block fails [`RelocationBlock::parse`].
    /// - A block extends past `reloc_size`.
    /// - Nonzero bytes follow a truncated tail or an all-zero padding block.
    /// - An RVA or offset calculation overflows.
    pub fn parse<F>(reloc_rva: u32, reloc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut blocks = Vec::new();
        let mut offset = 0u32;

        while offset < reloc_size {
            let entry_rva = reloc_rva.checked_add(offset).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table RVA overflow")
            })?;
            let remaining = reloc_size.checked_sub(offset).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table size underflow")
            })?;
            if remaining < RelocationBlock::HEADER_SIZE_U32 {
                let tail = crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    entry_rva,
                    remaining as usize,
                    "base-relocation tail",
                )?;
                if tail.iter().all(|byte| *byte == 0) {
                    break;
                }
                return Err(Error::invalid_data_directory(
                    "truncated base-relocation block header",
                ));
            }

            let header = crate::parse_utils::read_exact_rva(
                &read_at_rva,
                entry_rva,
                RelocationBlock::HEADER_SIZE,
                "base-relocation block header",
            )?;
            let [p0, p1, p2, p3, s0, s1, s2, s3] =
                <[u8; 8]>::try_from(header).map_err(|header| {
                    Error::buffer_too_small(RelocationBlock::HEADER_SIZE, header.len())
                })?;

            let page_rva = u32::from_le_bytes([p0, p1, p2, p3]);
            let block_size = u32::from_le_bytes([s0, s1, s2, s3]);

            // Some linkers fill the end of the declared directory with zeros.
            if page_rva == 0 && block_size == 0 {
                let tail = crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    entry_rva,
                    remaining as usize,
                    "base-relocation zero tail",
                )?;
                if tail.iter().all(|byte| *byte == 0) {
                    break;
                }
                return Err(Error::invalid_data_directory(
                    "zero base-relocation block is followed by nonzero data",
                ));
            }

            if block_size > remaining {
                return Err(Error::invalid_data_directory(format!(
                    "base-relocation block size {block_size} exceeds {remaining} remaining bytes"
                )));
            }
            let data = crate::parse_utils::read_exact_rva(
                &read_at_rva,
                entry_rva,
                block_size as usize,
                "base-relocation block",
            )?;

            let block = RelocationBlock::parse(&data)?;
            offset = offset.checked_add(block_size).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table size overflow")
            })?;
            if offset > reloc_size {
                return Err(Error::invalid_data_directory(format!(
                    "base-relocation block extends past directory size {reloc_size}"
                )));
            }
            blocks.push(block);
        }

        Ok(Self { blocks })
    }

    /// Check if the relocation table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Get the total number of relocations, without padding entries.
    #[must_use]
    pub fn relocation_count(&self) -> usize {
        self.blocks
            .iter()
            .flat_map(|b| &b.entries)
            .filter(|e| !e.is_padding())
            .count()
    }

    /// Serialize the table to bytes.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("relocation table build failed: use try_to_bytes()")
    }

    /// Serialize each block, with checked arithmetic on the table size.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`RelocationBlock::try_to_bytes`]. Returns an
    /// invalid-data-directory error if the table is larger than `u32::MAX`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for block in &self.blocks {
            let bytes = block.try_to_bytes()?;
            output
                .len()
                .checked_add(bytes.len())
                .and_then(|size| u32::try_from(size).ok())
                .ok_or_else(|| {
                    Error::invalid_data_directory("base-relocation table exceeds u32")
                })?;
            output.extend(bytes);
        }
        Ok(output)
    }

    /// Calculate the total size of the serialized table.
    ///
    /// The size saturates at `usize::MAX`. A table in memory cannot reach this limit: each
    /// block and each entry uses more memory than its serialized form.
    #[must_use]
    pub fn calculate_size(&self) -> usize {
        self.blocks.iter().fold(0usize, |total, block| {
            let entry_count = block.entries.len();
            // Pad to a 4-byte boundary.
            let padded_count =
                entry_count.saturating_add(usize::from(!entry_count.is_multiple_of(2)));
            let block_size =
                RelocationBlock::HEADER_SIZE.saturating_add(padded_count.saturating_mul(2));
            total.saturating_add(block_size)
        })
    }

    /// Add a relocation entry at a specific RVA.
    ///
    /// The function first tries the last block. If the last block is for a different page, the
    /// function searches all blocks. To add many relocations in no particular order, use
    /// [`RelocationBuilder`](super::RelocationBuilder). It finds the block of a page in a map.
    pub fn add_relocation(&mut self, rva: u32, reloc_type: RelocationType) {
        let (page_rva, entry) = split_rva(rva, reloc_type);
        let last = self
            .blocks
            .last()
            .filter(|b| b.page_rva == page_rva)
            .and_then(|_| self.blocks.len().checked_sub(1));
        let index = last.or_else(|| self.blocks.iter().position(|b| b.page_rva == page_rva));
        if let Some(block) = index.and_then(|index| self.blocks.get_mut(index)) {
            block.entries.push(entry);
        } else {
            self.blocks.push(new_block(page_rva, entry));
        }
    }

    /// Add a HIGHLOW (32-bit) relocation.
    pub fn add_highlow(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::HighLow);
    }

    /// Add a DIR64 (64-bit) relocation.
    pub fn add_dir64(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::Dir64);
    }

    /// Sort the blocks by page RVA, and pad each block to a 4-byte boundary.
    ///
    /// This function changes `self`.
    pub fn normalize(&mut self) {
        // Sort the blocks.
        self.blocks.sort_by_key(|b| b.page_rva);

        // Pad each block to a 4-byte boundary.
        for block in &mut self.blocks {
            if block.entries.len() % 2 == 1 {
                block.entries.push(RelocationEntry {
                    reloc_type: RelocationType::Absolute,
                    offset: 0,
                });
            }
            // Update block_size. If a block is too large for `u32`, the size saturates here.
            // `try_to_bytes` calculates the size again and rejects the block.
            block.block_size = block
                .entries
                .len()
                .checked_mul(2)
                .and_then(|size| size.checked_add(RelocationBlock::HEADER_SIZE))
                .and_then(|size| u32::try_from(size).ok())
                .unwrap_or(u32::MAX);
        }
    }

    /// Make a normalized copy. This function does not change `self`.
    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut copy = self.clone();
        copy.normalize();
        copy
    }

    /// Build the relocation table bytes from a normalized copy. This function does not change
    /// `self`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("relocation build failed: use try_build() for fallible serialization")
    }

    /// Build normalized relocation bytes, with checked block and table sizes.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_to_bytes`] for the normalized copy.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        self.normalized().try_to_bytes()
    }
}

/// Split `rva` into its 4-KiB page RVA and an entry with the low 12 bits as the offset.
pub(super) fn split_rva(rva: u32, reloc_type: RelocationType) -> (u32, RelocationEntry) {
    let page_rva = rva & !0xFFF;
    let [low, high, ..] = rva.to_le_bytes();
    let offset = u16::from_le_bytes([low, high]) & 0x0FFF;
    (page_rva, RelocationEntry { reloc_type, offset })
}

/// Make a block for the page `page_rva` with one entry. Serialization calculates the size.
pub(super) fn new_block(page_rva: u32, entry: RelocationEntry) -> RelocationBlock {
    RelocationBlock {
        page_rva,
        block_size: 0,
        entries: vec![entry],
    }
}
