//! The body of a function override record (`IMAGE_FUNCTION_OVERRIDE_HEADER`).

use core::mem::{offset_of, size_of};

use nostdio::ReadLe;

use super::{DynamicRelocationBlocks, invalid, rva_at};
use crate::Result;
use crate::parse_utils::le_u32;

/// The layout of `IMAGE_FUNCTION_OVERRIDE_HEADER`.
#[repr(C)]
struct ImageFunctionOverrideHeader {
    func_override_size: u32,
}

/// The layout of the fixed fields of `IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION`.
#[repr(C)]
struct ImageFunctionOverrideDynamicRelocation {
    original_rva: u32,
    bdd_offset: u32,
    rva_size: u32,
    base_reloc_size: u32,
}

const _: () = {
    assert!(size_of::<ImageFunctionOverrideHeader>() == 4);
    assert!(size_of::<ImageFunctionOverrideDynamicRelocation>() == 16);
};

/// The body of a [`FUNCTION_OVERRIDE`](super::symbols::FUNCTION_OVERRIDE) record:
/// `IMAGE_FUNCTION_OVERRIDE_HEADER`, the override records and the BDD bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionOverrideHeader<'a> {
    /// The RVA of the header.
    rva: u32,
    /// The `FuncOverrideSize` bytes of override records.
    overrides: &'a [u8],
    /// The bytes after the override records.
    bdd: &'a [u8],
}

impl<'a> FunctionOverrideHeader<'a> {
    /// The size of `IMAGE_FUNCTION_OVERRIDE_HEADER` in bytes.
    pub const HEADER_SIZE: usize = size_of::<ImageFunctionOverrideHeader>();

    /// Parse the body `data` of a record. The body starts at `rva`.
    pub(super) fn parse(data: &'a [u8], rva: u32) -> Result<Self> {
        const N: usize = size_of::<ImageFunctionOverrideHeader>();
        let fail = || invalid(rva, "IMAGE_FUNCTION_OVERRIDE_HEADER");
        let header = data.first_chunk::<N>().ok_or_else(fail)?;
        let size =
            le_u32::<N, { offset_of!(ImageFunctionOverrideHeader, func_override_size) }>(header);
        let end = usize::try_from(size)
            .ok()
            .and_then(|size| Self::HEADER_SIZE.checked_add(size))
            .ok_or_else(fail)?;
        let overrides = data.get(Self::HEADER_SIZE..end).ok_or_else(fail)?;
        let bdd = data.get(end..).ok_or_else(fail)?;
        Ok(Self {
            rva,
            overrides,
            bdd,
        })
    }

    /// Return the RVA of the header.
    #[must_use]
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Return an iterator over the override records
    /// (`IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION`).
    #[must_use]
    pub fn overrides(&self) -> FunctionOverrides<'a> {
        FunctionOverrides {
            data: self.overrides,
            rva: rva_at(self.rva, Self::HEADER_SIZE),
            position: 0,
            done: false,
        }
    }

    /// Return the bytes after the override records: the binary decision diagram
    /// (`IMAGE_BDD_INFO` and its nodes).
    #[must_use]
    pub fn bdd(&self) -> &'a [u8] {
        self.bdd
    }

    /// Return the RVA of the BDD bytes.
    #[must_use]
    pub fn bdd_rva(&self) -> u32 {
        rva_at(
            self.rva,
            Self::HEADER_SIZE.saturating_add(self.overrides.len()),
        )
    }
}

/// An iterator over the override records of a function override record.
///
/// The iterator reads one record at a time. It stops after the first error.
#[derive(Debug, Clone)]
pub struct FunctionOverrides<'a> {
    /// The override records.
    data: &'a [u8],
    /// The RVA of the first override record.
    rva: u32,
    /// The offset of the next override record in `data`.
    position: usize,
    /// `true` after an error.
    done: bool,
}

impl<'a> FunctionOverrides<'a> {
    /// Read the override record at the current position.
    fn read_override(&mut self) -> Result<FunctionOverride<'a>> {
        const N: usize = size_of::<ImageFunctionOverrideDynamicRelocation>();
        let rva = rva_at(self.rva, self.position);
        let fail = || invalid(rva, "IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION");
        let rest = self.data.get(self.position..).ok_or_else(fail)?;
        let header = rest.first_chunk::<N>().ok_or_else(fail)?;
        let original_rva = le_u32::<
            N,
            { offset_of!(ImageFunctionOverrideDynamicRelocation, original_rva) },
        >(header);
        let bdd_offset =
            le_u32::<N, { offset_of!(ImageFunctionOverrideDynamicRelocation, bdd_offset) }>(header);
        let rva_size = usize::try_from(le_u32::<
            N,
            { offset_of!(ImageFunctionOverrideDynamicRelocation, rva_size) },
        >(header))
        .map_err(|_| fail())?;
        let reloc_size = usize::try_from(le_u32::<
            N,
            { offset_of!(ImageFunctionOverrideDynamicRelocation, base_reloc_size) },
        >(header))
        .map_err(|_| fail())?;
        if !rva_size.is_multiple_of(4) {
            return Err(fail());
        }
        let blocks_start = FunctionOverride::HEADER_SIZE
            .checked_add(rva_size)
            .ok_or_else(fail)?;
        let end = blocks_start.checked_add(reloc_size).ok_or_else(fail)?;
        let rvas = rest
            .get(FunctionOverride::HEADER_SIZE..blocks_start)
            .ok_or_else(fail)?;
        let blocks = rest.get(blocks_start..end).ok_or_else(fail)?;
        let blocks_rva = rva_at(rva, blocks_start);
        self.position = self.position.checked_add(end).ok_or_else(fail)?;
        Ok(FunctionOverride {
            rva,
            original_rva,
            bdd_offset,
            rvas,
            blocks: DynamicRelocationBlocks::new(blocks, blocks_rva, 2),
        })
    }
}

impl<'a> Iterator for FunctionOverrides<'a> {
    type Item = Result<FunctionOverride<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.position >= self.data.len() {
            return None;
        }
        let record = self.read_override();
        self.done = record.is_err();
        Some(record)
    }
}

/// One override record (`IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION`).
#[derive(Debug, Clone)]
pub struct FunctionOverride<'a> {
    /// The RVA of the record.
    rva: u32,
    /// `OriginalRva`.
    original_rva: u32,
    /// `BDDOffset`.
    bdd_offset: u32,
    /// The `RvaSize` bytes of RVAs.
    rvas: &'a [u8],
    /// The `BaseRelocSize` bytes of base relocation blocks.
    blocks: DynamicRelocationBlocks<'a>,
}

impl<'a> FunctionOverride<'a> {
    /// The size of the fixed fields of `IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION` in bytes.
    pub const HEADER_SIZE: usize = size_of::<ImageFunctionOverrideDynamicRelocation>();

    /// Return the RVA of the record.
    #[must_use]
    pub fn rva(&self) -> u32 {
        self.rva
    }

    /// Return `OriginalRva`: the RVA of the original function.
    #[must_use]
    pub fn original_rva(&self) -> u32 {
        self.original_rva
    }

    /// Return `BDDOffset`: the offset of the BDD of this record in the BDD bytes.
    #[must_use]
    pub fn bdd_offset(&self) -> u32 {
        self.bdd_offset
    }

    /// Return an iterator over the RVAs of the override functions.
    pub fn rvas(&self) -> impl Iterator<Item = u32> + 'a {
        let mut rvas = self.rvas;
        core::iter::from_fn(move || rvas.read_u32_le().ok())
    }

    /// Return an iterator over the base relocation blocks of 16-bit entries.
    #[must_use]
    pub fn blocks(&self) -> DynamicRelocationBlocks<'a> {
        self.blocks.clone()
    }
}
