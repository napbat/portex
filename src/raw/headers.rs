//! The offsets of the header fields that a tool rewrites in place.

use core::mem::offset_of;

use crate::data_dir::DataDirectory;
use crate::optional::{ImageNtHeaders32, ImageNtHeaders64};
use crate::section::SectionHeader;

// PE32 and PE32+ share the offsets of the file header, the optional header and the fields
// below in the NT headers.
const _: () = {
    assert!(offset_of!(ImageNtHeaders32, file_header) == offset_of!(ImageNtHeaders64, file_header));
    assert!(
        offset_of!(ImageNtHeaders32, optional_header)
            == offset_of!(ImageNtHeaders64, optional_header)
    );
    assert!(
        offset_of!(ImageNtHeaders32, optional_header.size_of_image)
            == offset_of!(ImageNtHeaders64, optional_header.size_of_image)
    );
    assert!(
        offset_of!(ImageNtHeaders32, optional_header.size_of_headers)
            == offset_of!(ImageNtHeaders64, optional_header.size_of_headers)
    );
    assert!(
        offset_of!(ImageNtHeaders32, optional_header.check_sum)
            == offset_of!(ImageNtHeaders64, optional_header.check_sum)
    );
};

/// The source offsets of the header fields that a tool rewrites in place.
///
/// [`PeHeaders::header_offsets`](crate::PeHeaders::header_offsets) makes this value. Each
/// offset has the same base as [`PeHeaders::pe_offset`](crate::PeHeaders::pe_offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
        let at = |delta: usize| nt_headers.checked_add(delta);
        let (image_base, data_directories) = if is_64bit {
            (
                offset_of!(ImageNtHeaders64, optional_header.image_base),
                offset_of!(ImageNtHeaders64, optional_header.data_directory),
            )
        } else {
            (
                offset_of!(ImageNtHeaders32, optional_header.image_base),
                offset_of!(ImageNtHeaders32, optional_header.data_directory),
            )
        };
        let optional_header = at(offset_of!(ImageNtHeaders32, optional_header))?;
        Some(Self {
            nt_headers,
            coff_header: at(offset_of!(ImageNtHeaders32, file_header))?,
            time_date_stamp: at(offset_of!(ImageNtHeaders32, file_header.time_date_stamp))?,
            optional_header,
            image_base: at(image_base)?,
            size_of_image: at(offset_of!(ImageNtHeaders32, optional_header.size_of_image))?,
            size_of_headers: at(offset_of!(
                ImageNtHeaders32,
                optional_header.size_of_headers
            ))?,
            check_sum: at(offset_of!(ImageNtHeaders32, optional_header.check_sum))?,
            data_directories: at(data_directories)?,
            section_table: optional_header.checked_add(usize::from(size_of_optional_header))?,
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
