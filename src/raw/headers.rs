//! The offsets of the header fields that a tool rewrites in place.

use crate::coff::CoffHeader;
use crate::data_dir::DataDirectory;
use crate::section::SectionHeader;

/// The offset of `ImageBase` in `IMAGE_OPTIONAL_HEADER32`.
const IMAGE_BASE_32: usize = 28;
/// The offset of `ImageBase` in `IMAGE_OPTIONAL_HEADER64`.
const IMAGE_BASE_64: usize = 24;
/// The offset of `SizeOfImage` in both optional header layouts.
const SIZE_OF_IMAGE: usize = 56;
/// The offset of `SizeOfHeaders` in both optional header layouts.
const SIZE_OF_HEADERS: usize = 60;
/// The offset of `CheckSum` in both optional header layouts.
const CHECK_SUM: usize = 64;
/// The offset of the data directory array in `IMAGE_OPTIONAL_HEADER32`.
const DATA_DIRECTORIES_32: usize = 96;
/// The offset of the data directory array in `IMAGE_OPTIONAL_HEADER64`.
const DATA_DIRECTORIES_64: usize = 112;
/// The offset of `TimeDateStamp` in `IMAGE_FILE_HEADER`.
const TIME_DATE_STAMP: usize = 4;

/// The source offsets of the header fields that a tool rewrites in place.
///
/// [`PeHeaders::header_offsets`](crate::PeHeaders::header_offsets) makes this value. Each
/// offset has the same base as [`PeHeaders::pe_offset`](crate::PeHeaders::pe_offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderOffsets {
    /// The offset of the NT headers (`IMAGE_NT_HEADERS`): the PE signature.
    pub nt_headers: usize,
    /// The offset of `IMAGE_FILE_HEADER`.
    pub coff_header: usize,
    /// The offset of `TimeDateStamp` in `IMAGE_FILE_HEADER`.
    pub time_date_stamp: usize,
    /// The offset of the optional header.
    pub optional_header: usize,
    /// The offset of `ImageBase` (a VA). The field has 32 bits in a PE32 image and 64 bits in a
    /// PE32+ image.
    pub image_base: usize,
    /// The offset of `SizeOfImage`.
    pub size_of_image: usize,
    /// The offset of `SizeOfHeaders`.
    pub size_of_headers: usize,
    /// The offset of `CheckSum`.
    pub check_sum: usize,
    /// The offset of the data directory array (`IMAGE_DATA_DIRECTORY`).
    pub data_directories: usize,
    /// The offset of the section table: the optional header offset plus
    /// `SizeOfOptionalHeader`.
    pub section_table: usize,
}

impl HeaderOffsets {
    /// Calculate the offsets for NT headers at `nt_headers`. Return `None` on overflow.
    pub(crate) fn new(
        nt_headers: usize,
        size_of_optional_header: u16,
        is_64bit: bool,
    ) -> Option<Self> {
        let coff_header = nt_headers.checked_add(4)?;
        let optional_header = coff_header.checked_add(CoffHeader::SIZE)?;
        let (image_base, data_directories) = if is_64bit {
            (IMAGE_BASE_64, DATA_DIRECTORIES_64)
        } else {
            (IMAGE_BASE_32, DATA_DIRECTORIES_32)
        };
        let field = |delta: usize| optional_header.checked_add(delta);
        Some(Self {
            nt_headers,
            coff_header,
            time_date_stamp: coff_header.checked_add(TIME_DATE_STAMP)?,
            optional_header,
            image_base: field(image_base)?,
            size_of_image: field(SIZE_OF_IMAGE)?,
            size_of_headers: field(SIZE_OF_HEADERS)?,
            check_sum: field(CHECK_SUM)?,
            data_directories: field(data_directories)?,
            section_table: field(usize::from(size_of_optional_header))?,
        })
    }

    /// Return the offset of the data directory entry at `index`, or `None` on overflow.
    ///
    /// The method does not compare `index` with `NumberOfRvaAndSizes`.
    #[must_use]
    pub fn data_directory(&self, index: usize) -> Option<usize> {
        index
            .checked_mul(DataDirectory::SIZE)
            .and_then(|delta| self.data_directories.checked_add(delta))
    }

    /// Return the offset of the section header at `index`, or `None` on overflow.
    ///
    /// The method does not compare `index` with `NumberOfSections`.
    #[must_use]
    pub fn section_header(&self, index: usize) -> Option<usize> {
        index
            .checked_mul(SectionHeader::SIZE)
            .and_then(|delta| self.section_table.checked_add(delta))
    }
}
