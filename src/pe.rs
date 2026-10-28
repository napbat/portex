//! The main PE image types and their parsers.
//!
//! This module supplies the [`PeImage`] and [`PeHeaders`] types. Use them to read, change, and
//! write Windows PE (Portable Executable) files.
//!
//! # Examples
//!
//! ## Load and inspect a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! // Check the architecture.
//! println!("64-bit: {}", pe.is_64bit());
//! println!("Entry point: {:#x}", pe.entry_point());
//! println!("Image base: {:#x}", pe.image_base());
//!
//! // List the sections.
//! for section in &pe.sections {
//!     println!("Section: {} (RVA: {:#x}, size: {})",
//!         section.name(),
//!         section.header.virtual_address,
//!         section.data.len());
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Load only the headers (faster for large files)
//!
//! ```no_run
//! use portex::PeHeaders;
//!
//! # let file_bytes: &[u8] = &[];
//! // Read only the headers. Do not read the section data.
//! let headers = PeHeaders::from_slice(file_bytes)?;
//! println!("Entry point: {:#x}", headers.entry_point());
//! println!("Number of sections: {}", headers.section_headers.len());
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Change and write a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Change the entry point RVA through the inner header.
//! match &mut pe.optional_header {
//!     portex::optional::OptionalHeader::Pe32(h) => h.address_of_entry_point = 0x1000,
//!     portex::optional::OptionalHeader::Pe32Plus(h) => h.address_of_entry_point = 0x1000,
//! }
//!
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::coff::CoffHeader;
use crate::dos::DosHeader;
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::section::{Section, SectionHeader};

/// The layout of the PE bytes in their source.
///
/// A raw PE file stores each section payload at the file offset
/// [`SectionHeader::pointer_to_raw_data`]. An image that a loader mapped stores each payload at
/// its RVA ([`SectionHeader::virtual_address`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SourceLayout {
    /// Raw file layout, as on disk or in a byte-for-byte copy of the file.
    #[default]
    File,
    /// Loader-mapped image layout. Each RVA is an offset from the start of the image.
    Mapped,
}

/// The policy for section bytes that the parser cannot read from the source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MissingSectionData {
    /// Reject section ranges that are truncated or that the parser cannot read.
    #[default]
    Error,
    /// Keep the section header, and give the section empty data for the missing bytes.
    ///
    /// Use this for remote mapped images. In such images, the pages of discardable sections
    /// can be decommitted.
    Empty,
}

/// Options to parse a PE image from any byte source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// How each RVA maps to an offset in the source.
    pub layout: SourceLayout,
    /// What to do with section ranges that the parser cannot read.
    pub missing_section_data: MissingSectionData,
    /// The actual load address (a VA) of a relocated mapped image.
    pub runtime_image_base: Option<u64>,
}

impl ParseOptions {
    /// Return options for strict parsing of a raw file.
    #[must_use]
    pub const fn file() -> Self {
        Self {
            layout: SourceLayout::File,
            missing_section_data: MissingSectionData::Error,
            runtime_image_base: None,
        }
    }

    /// Return options for strict parsing of a loader-mapped image.
    #[must_use]
    pub const fn mapped() -> Self {
        Self {
            layout: SourceLayout::Mapped,
            missing_section_data: MissingSectionData::Error,
            runtime_image_base: None,
        }
    }

    /// Accept section ranges that are not in the source.
    #[must_use]
    pub const fn allow_missing_section_data(mut self) -> Self {
        self.missing_section_data = MissingSectionData::Empty;
        self
    }

    /// Set the actual base address (a VA) of a relocated mapped image.
    #[must_use]
    pub const fn runtime_image_base(mut self, image_base: u64) -> Self {
        self.runtime_image_base = Some(image_base);
        self
    }
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self::file()
    }
}

/// The maximum number of sections that the Windows image loader accepts.
///
/// Windows Vista and later accept up to 65535 sections, the range of `NumberOfSections`. The
/// loader of Windows XP accepts only 96.
pub const MAX_NUMBER_OF_SECTIONS: usize = 65535;

/// A parsed PE file that owns its section data.
///
/// This is the main type to read, change, and write PE files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    /// The DOS header (`IMAGE_DOS_HEADER`).
    pub dos_header: DosHeader,
    /// The DOS stub: the bytes between the DOS header and the PE signature.
    pub dos_stub: Vec<u8>,
    /// The COFF file header (`IMAGE_FILE_HEADER`).
    pub coff_header: CoffHeader,
    /// The optional header (`IMAGE_OPTIONAL_HEADER32` or `IMAGE_OPTIONAL_HEADER64`).
    pub optional_header: OptionalHeader,
    /// The sections, each with its own data.
    pub sections: Vec<Section>,
    pub(crate) source_layout: SourceLayout,
    pub(crate) runtime_image_base: Option<u64>,
    /// The raw bytes after the section table.
    ///
    /// Linkers can put data there, for example the bound import table.
    pub(crate) header_tail: HeaderBytes,
    /// The raw bytes after the optional header and before the section table, if
    /// `SizeOfOptionalHeader` is larger than the optional header.
    ///
    /// A file can put other data there, for example the raw data of a section.
    pub(crate) optional_padding: HeaderBytes,
}

/// Raw header bytes that no header structure describes.
///
/// The bytes keep their offset, because data directories and section headers can refer to them.
/// In the headers, a file offset and an RVA have the same value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HeaderBytes {
    /// The offset of the first byte from the start of the image.
    pub(crate) offset: usize,
    /// The bytes, without trailing zeros.
    pub(crate) bytes: Vec<u8>,
}

impl HeaderBytes {
    /// Return the offset after the last byte, or `None` on overflow.
    pub(crate) fn end(&self) -> Option<usize> {
        self.offset.checked_add(self.bytes.len())
    }

    /// Return `true` if the RVA `rva` is in the tail bytes.
    pub(crate) fn contains_rva(&self, rva: u32) -> bool {
        usize::try_from(rva)
            .ok()
            .and_then(|rva| rva.checked_sub(self.offset))
            .is_some_and(|index| index < self.bytes.len())
    }

    /// Set the tail bytes in an RVA range to zero.
    ///
    /// The part of the range outside the tail has no effect.
    pub(crate) fn clear_rva_range(&mut self, rva: u32, size: u32) {
        let Some(start) = usize::try_from(rva)
            .ok()
            .and_then(|rva| rva.checked_sub(self.offset))
            .filter(|start| *start < self.bytes.len())
        else {
            return;
        };
        let end = usize::try_from(size)
            .ok()
            .and_then(|size| start.checked_add(size))
            .map_or(self.bytes.len(), |end| end.min(self.bytes.len()));
        self.bytes[start..end].fill(0);
        self.trim_trailing_zeros();
    }

    /// Remove the zero bytes at the end. The build writes zeros there without the tail.
    pub(crate) fn trim_trailing_zeros(&mut self) {
        let used = self
            .bytes
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |last| last + 1);
        self.bytes.truncate(used);
    }
}

/// The PE headers without the section data.
///
/// Use this type for a remote process, or when you need only the header data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeaders {
    /// The DOS header (`IMAGE_DOS_HEADER`).
    pub dos_header: DosHeader,
    /// The COFF file header (`IMAGE_FILE_HEADER`).
    pub coff_header: CoffHeader,
    /// The optional header (`IMAGE_OPTIONAL_HEADER32` or `IMAGE_OPTIONAL_HEADER64`).
    pub optional_header: OptionalHeader,
    /// The section headers (`IMAGE_SECTION_HEADER`), without the section data.
    pub section_headers: Vec<SectionHeader>,
    /// The source offset of the PE signature.
    pub pe_offset: u64,
}

mod build;
mod directories_data;
mod directories_runtime;
mod edit;
mod headers;
mod inspect;
mod parse;
mod utilities;
mod validate;
