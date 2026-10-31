//! Base relocation table parsing and building.
//!
//! This module has types that read and write PE base relocation tables. The loader uses these
//! tables when it loads the image at an address that is not its preferred base.
//!
//! # Examples
//!
//! ## Listing relocations from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let relocs = pe.relocations()?;
//! for block in &relocs.blocks {
//!     println!("Block at page RVA {:#x}", block.page_rva);
//!     for entry in &block.entries {
//!         println!("  Type: {:?}, Offset: {:#x}",
//!             entry.reloc_type, entry.offset);
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Adding relocations to a PE file
//!
//! ```no_run
//! use portex::{PeImage, RelocationBlock, RelocationEntry, RelocationTable, RelocationType};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Make the relocation table from blocks.
//! let table = RelocationTable {
//!     blocks: vec![
//!         RelocationBlock {
//!             page_rva: 0x1000,
//!             block_size: 12, // 8-byte header + 2 entries * 2 bytes
//!             entries: vec![
//!                 RelocationEntry { reloc_type: RelocationType::Dir64, offset: 0x100 },
//!                 RelocationEntry { reloc_type: RelocationType::Dir64, offset: 0x200 },
//!             ],
//!         },
//!     ],
//! };
//!
//! // Write the relocations into the PE.
//! pe.update_relocations(&table, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::{Error, Result};

/// Base relocation types (`IMAGE_REL_BASED_*`): the high 4 bits of a relocation entry.
///
/// A later version of the crate can add a named variant for a code that is now
/// [`Self::Unknown`]. Thus a `match` must have a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelocationType {
    /// No relocation (padding).
    Absolute,
    /// High 16 bits of a 32-bit address.
    High,
    /// Low 16 bits of a 32-bit address.
    Low,
    /// Full 32-bit address (HIGHLOW).
    HighLow,
    /// High 16 bits of a 32-bit address, adjusted for sign extension of the low half.
    HighAdj,
    /// Machine-specific (type 5): MIPS JMPADDR, ARM MOV32, RISC-V HIGH20.
    MachineSpecific5,
    /// Section index (reserved).
    Section,
    /// Machine-specific (type 7): REL32, THUMB MOV32, RISC-V LOW12I.
    MachineSpecific7,
    /// RISC-V low 12 bits, S-type format.
    RiscvLow12S,
    /// MIPS 16-bit jump address.
    MipsJmpAddr16,
    /// 64-bit address (DIR64).
    Dir64,
    /// A 4-bit code (11 to 15) that has no name in this version of the crate.
    ///
    /// [`Self::from_u8`] makes this variant only for these codes. The serializer rejects an
    /// `Unknown` value that is wider than 4 bits or that is the code of a named variant.
    Unknown(u8),
}

impl RelocationType {
    /// Parse the type from the low 4 bits of `value`. The function ignores the high 4 bits.
    ///
    /// To parse a relocation entry, give the high 4 bits of the entry as the low 4 bits of
    /// `value`.
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0f {
            0 => Self::Absolute,
            1 => Self::High,
            2 => Self::Low,
            3 => Self::HighLow,
            4 => Self::HighAdj,
            5 => Self::MachineSpecific5,
            6 => Self::Section,
            7 => Self::MachineSpecific7,
            8 => Self::RiscvLow12S,
            9 => Self::MipsJmpAddr16,
            10 => Self::Dir64,
            other => Self::Unknown(other),
        }
    }

    /// Return the four-bit on-disk relocation code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Absolute => 0,
            Self::High => 1,
            Self::Low => 2,
            Self::HighLow => 3,
            Self::HighAdj => 4,
            Self::MachineSpecific5 => 5,
            Self::Section => 6,
            Self::MachineSpecific7 => 7,
            Self::RiscvLow12S => 8,
            Self::MipsJmpAddr16 => 9,
            Self::Dir64 => 10,
            Self::Unknown(value) => value & 0x0f,
        }
    }

    /// Return `true` if [`Self::from_u8`] gives this value for its code. Only an `Unknown`
    /// value that is wider than 4 bits or that is the code of a named variant is not
    /// canonical.
    pub(crate) fn is_canonical(self) -> bool {
        Self::from_u8(self.as_u8()) == self
    }
}

/// A single relocation entry in a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationEntry {
    /// Relocation type.
    pub reloc_type: RelocationType,
    /// Offset of the target from the page RVA of the block (12 bits).
    pub offset: u16,
}

impl RelocationEntry {
    /// Parse an entry from its 16-bit value.
    #[must_use]
    pub fn from_u16(value: u16) -> Self {
        // The type is the high four bits of the high byte.
        let [high, _] = value.to_be_bytes();
        Self {
            reloc_type: RelocationType::from_u8(high >> 4),
            offset: value & 0x0FFF,
        }
    }

    /// Convert the entry to its 16-bit value.
    #[must_use]
    pub fn to_u16(self) -> u16 {
        (u16::from(self.reloc_type.as_u8()) << 12) | (self.offset & 0x0FFF)
    }

    /// Check if this is a padding entry (`Absolute` type).
    #[must_use]
    pub fn is_padding(self) -> bool {
        matches!(self.reloc_type, RelocationType::Absolute)
    }
}

mod apply;
mod block;
mod builder;
mod table;

pub use block::RelocationBlock;
pub use builder::RelocationBuilder;
pub use table::RelocationTable;

#[cfg(test)]
mod tests;
