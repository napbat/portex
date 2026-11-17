//! The base relocation blocks of a dynamic relocation record.

use core::mem::{offset_of, size_of};

use nostdio::ReadLe;

use super::{invalid, rva_at};
use crate::Result;
use crate::parse_utils::u32_at;
use crate::reloc::ImageBaseRelocation;

/// The name of the block header in errors.
const BLOCK: &str = "IMAGE_BASE_RELOCATION";

/// An iterator over the base relocation blocks (`IMAGE_BASE_RELOCATION`) of a dynamic relocation
/// record.
///
/// Each block has a page RVA and entries of 16 or 32 bits. The iterator reads one block at a
/// time. It stops after the first error.
#[derive(Debug, Clone)]
pub struct DynamicRelocationBlocks<'a> {
    /// The blocks.
    data: &'a [u8],
    /// The RVA of the first block.
    rva: u32,
    /// The size of one entry in bytes: 2 or 4.
    entry_size: usize,
    /// The offset of the next block in `data`.
    position: usize,
    /// `true` after an error.
    done: bool,
}

impl<'a> DynamicRelocationBlocks<'a> {
    /// The size of `IMAGE_BASE_RELOCATION` in bytes.
    pub const HEADER_SIZE: usize = size_of::<ImageBaseRelocation>();

    /// Make an iterator over the blocks in `data`, which starts at `rva`.
    pub(super) fn new(data: &'a [u8], rva: u32, entry_size: usize) -> Self {
        Self {
            data,
            rva,
            entry_size,
            position: 0,
            done: false,
        }
    }

    /// Return the RVA of the first block.
    #[must_use]
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Return the size of one entry in bytes: 2 or 4.
    #[must_use]
    pub fn entry_size(&self) -> usize {
        self.entry_size
    }

    /// Read the block at the current position.
    fn read_block(&mut self) -> Result<DynamicRelocationBlock<'a>> {
        let rva = rva_at(self.rva, self.position);
        let fail = || invalid(rva, BLOCK);
        let rest = self.data.get(self.position..).ok_or_else(fail)?;
        let page_rva =
            u32_at(rest, offset_of!(ImageBaseRelocation, virtual_address)).ok_or_else(fail)?;
        let block_size =
            u32_at(rest, offset_of!(ImageBaseRelocation, size_of_block)).ok_or_else(fail)?;
        let size = usize::try_from(block_size)
            .ok()
            .filter(|&size| size >= Self::HEADER_SIZE)
            .ok_or_else(fail)?;
        let entries = rest
            .get(Self::HEADER_SIZE..size)
            .filter(|entries| entries.len().is_multiple_of(self.entry_size))
            .ok_or_else(fail)?;
        self.position = self.position.checked_add(size).ok_or_else(fail)?;
        Ok(DynamicRelocationBlock {
            rva,
            page_rva,
            entries,
            entry_size: self.entry_size,
        })
    }
}

impl<'a> Iterator for DynamicRelocationBlocks<'a> {
    type Item = Result<DynamicRelocationBlock<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.position >= self.data.len() {
            return None;
        }
        let block = self.read_block();
        self.done = block.is_err();
        Some(block)
    }
}

/// One base relocation block (`IMAGE_BASE_RELOCATION`) of a dynamic relocation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicRelocationBlock<'a> {
    /// The RVA of the block header.
    rva: u32,
    /// `VirtualAddress`.
    page_rva: u32,
    /// The entries after the header.
    entries: &'a [u8],
    /// The size of one entry in bytes: 2 or 4.
    entry_size: usize,
}

impl<'a> DynamicRelocationBlock<'a> {
    /// Return the RVA of the block header.
    #[must_use]
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Return `VirtualAddress`: the RVA of the page of the entries.
    #[must_use]
    pub fn page_rva(&self) -> u32 {
        self.page_rva
    }

    /// Return the size of one entry in bytes: 2 or 4.
    #[must_use]
    pub fn entry_size(&self) -> usize {
        self.entry_size
    }

    /// Return an iterator over the raw values of the entries.
    ///
    /// A zero 16-bit entry at the end of the block is padding, because blocks of 16-bit entries
    /// align to 4 bytes. The iterator does not return it.
    #[must_use]
    pub fn entries(&self) -> DynamicRelocationEntries<'a> {
        let entries = match self.entries {
            [rest @ .., 0, 0] if self.entry_size == 2 => rest,
            entries => entries,
        };
        DynamicRelocationEntries {
            data: entries,
            entry_size: self.entry_size,
        }
    }
}

/// An iterator over the raw entry values of one block.
#[derive(Debug, Clone)]
pub struct DynamicRelocationEntries<'a> {
    /// The entries that remain.
    data: &'a [u8],
    /// The size of one entry in bytes: 2 or 4.
    entry_size: usize,
}

impl Iterator for DynamicRelocationEntries<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let entry = if self.entry_size == 2 {
            self.data.read_u16_le().map(u32::from)
        } else {
            self.data.read_u32_le()
        };
        entry.ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.data.len() / self.entry_size;
        (count, Some(count))
    }
}

impl ExactSizeIterator for DynamicRelocationEntries<'_> {}
