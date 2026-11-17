//! Raw views of the base relocation table: blocks and entries.

use core::mem::{offset_of, size_of};

use super::{RawCursor, RawField, at, read_u16};
use crate::parse_utils::le_u32;
use crate::reloc::{ImageBaseRelocation, RelocationEntry, RelocationType};
use crate::{Error, Result};

/// A base relocation block header (`IMAGE_BASE_RELOCATION`) and the offsets of its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRelocationBlock {
    /// The offset of the block.
    pub offset: usize,
    /// `VirtualAddress`: the RVA of the page.
    pub virtual_address: RawField<u32>,
    /// `SizeOfBlock`: the size of the block with its header, in bytes.
    pub size_of_block: RawField<u32>,
}

impl RawRelocationBlock {
    /// The size of `IMAGE_BASE_RELOCATION` in bytes.
    pub const HEADER_SIZE: usize = size_of::<ImageBaseRelocation>();

    /// Read the block header at `offset`. The method does not check the values.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is not in `data`.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        const N: usize = RawRelocationBlock::HEADER_SIZE;
        const VIRTUAL_ADDRESS: usize = offset_of!(ImageBaseRelocation, virtual_address);
        const SIZE_OF_BLOCK: usize = offset_of!(ImageBaseRelocation, size_of_block);
        let Some(raw) = data.get(offset..).and_then(<[u8]>::first_chunk::<N>) else {
            return Err(Error::offset_out_of_bounds(offset, data.len()));
        };
        // The header is in `data`, so `offset + N` does not overflow.
        Ok(Self {
            offset,
            virtual_address: RawField {
                offset: offset + VIRTUAL_ADDRESS,
                value: le_u32::<N, VIRTUAL_ADDRESS>(raw),
            },
            size_of_block: RawField {
                offset: offset + SIZE_OF_BLOCK,
                value: le_u32::<N, SIZE_OF_BLOCK>(raw),
            },
        })
    }

    /// Return a cursor over the entries of the block.
    ///
    /// The cursor reads `(SizeOfBlock - 8) / 2` words after the header. It ignores an odd last
    /// byte.
    #[must_use]
    pub fn entries(&self) -> RawRelocations {
        let words = usize::try_from(self.size_of_block.value).map_or(usize::MAX, |size| {
            size.saturating_sub(Self::HEADER_SIZE) / RelocationEntry::SIZE
        });
        RawRelocations {
            // An offset that overflows gives no entries, because the read fails.
            offset: self.offset.saturating_add(Self::HEADER_SIZE),
            remaining: words,
        }
    }
}

/// A cursor over the blocks of a base relocation table.
///
/// The cursor reads at most `size` bytes. It ends at the first block whose `SizeOfBlock` is
/// less than 8 or larger than the bytes that remain. It does not check the page RVA or the
/// alignment of the blocks.
#[derive(Debug, Clone)]
pub struct RawRelocationBlocks {
    offset: usize,
    remaining: usize,
}

impl RawRelocationBlocks {
    /// Make a cursor for the blocks at `offset`, with at most `size` bytes.
    #[must_use]
    pub const fn new(offset: usize, size: usize) -> Self {
        Self {
            offset,
            remaining: size,
        }
    }
}

impl RawCursor for RawRelocationBlocks {
    type Item = RawRelocationBlock;

    fn read_next(&mut self, data: &[u8]) -> Result<Option<RawRelocationBlock>> {
        if self.remaining < RawRelocationBlock::HEADER_SIZE {
            return Ok(None);
        }
        let block = RawRelocationBlock::parse(data, self.offset)?;
        let size = usize::try_from(block.size_of_block.value).unwrap_or(usize::MAX);
        if size < RawRelocationBlock::HEADER_SIZE || size > self.remaining {
            self.remaining = 0;
            return Ok(None);
        }
        // The cursor returns the block also if its end overflows, because its header is in
        // `data`. A saturated offset gives no next block, because the read fails.
        self.offset = self.offset.saturating_add(size);
        self.remaining -= size;
        Ok(Some(block))
    }
}

/// One base relocation entry and its offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRelocation {
    /// The offset of the entry word.
    pub offset: usize,
    /// The decoded entry word.
    pub entry: RelocationEntry,
    /// The parameter word of a `HIGHADJ` entry, if the block has a word after the entry.
    pub parameter: Option<RawField<u16>>,
}

/// A cursor over the entries of one base relocation block.
///
/// The cursor returns each entry word, also `ABSOLUTE` padding entries. For a `HIGHADJ` entry,
/// it also reads the next word as the parameter.
#[derive(Debug, Clone)]
pub struct RawRelocations {
    offset: usize,
    remaining: usize,
}

impl RawCursor for RawRelocations {
    type Item = RawRelocation;

    fn read_next(&mut self, data: &[u8]) -> Result<Option<RawRelocation>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        // Entries are a variable-length stream (a `HIGHADJ` entry takes a second word), so
        // each word is read at its run-time offset.
        let word = read_u16(data, self.offset)?;
        let entry = RelocationEntry::from_u16(word.value);
        // Read the parameter word before the cursor moves. A failed read then keeps the
        // position of the entry, and the next call reads the entry again.
        let mut words = 1;
        let mut parameter = None;
        if entry.reloc_type == RelocationType::HighAdj && self.remaining > 1 {
            parameter = Some(read_u16(data, at(self.offset, RelocationEntry::SIZE)?)?);
            words = 2;
        }
        self.offset = at(self.offset, RelocationEntry::SIZE * words)?;
        self.remaining -= words;
        Ok(Some(RawRelocation {
            offset: word.offset,
            entry,
            parameter,
        }))
    }
}
