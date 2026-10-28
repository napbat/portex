//! PE layout calculations for the file alignment and the section alignment.

use crate::coff::CoffHeader;
use crate::dos::DosHeader;
use crate::optional::OptionalHeader;
use crate::prelude::format;
use crate::section::{Section, SectionHeader};
use crate::{Error, Result};

/// Align a value up to the given alignment. Return `None` if the result overflows `u32`.
#[inline]
#[must_use]
pub fn checked_align_up(value: u32, alignment: u32) -> Option<u32> {
    if alignment == 0 {
        return Some(value);
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

/// Align a value up to the given alignment.
#[inline]
#[must_use]
pub fn align_up(value: u32, alignment: u32) -> u32 {
    checked_align_up(value, alignment).unwrap_or(u32::MAX - (u32::MAX % alignment.max(1)))
}

/// Align a value down to the given alignment.
#[inline]
#[must_use]
pub fn align_down(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    value - value % alignment
}

/// Layout configuration for the PE builder.
#[derive(Debug, Clone)]
pub struct LayoutConfig {
    /// File alignment (typically 0x200).
    pub file_alignment: u32,
    /// Section alignment (typically 0x1000).
    pub section_alignment: u32,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }
}

impl LayoutConfig {
    /// Create a configuration from the alignment values of an optional header.
    #[must_use]
    pub fn from_optional_header(opt: &OptionalHeader) -> Self {
        Self {
            file_alignment: opt.file_alignment(),
            section_alignment: opt.section_alignment(),
        }
    }

    /// Align a value up to the file alignment.
    #[must_use]
    pub fn align_file(&self, value: u32) -> u32 {
        align_up(value, self.file_alignment)
    }

    /// Align a value up to the section alignment.
    #[must_use]
    pub fn align_section(&self, value: u32) -> u32 {
        align_up(value, self.section_alignment)
    }
}

/// Calculate the size of all headers.
///
/// The headers are the DOS header, the PE signature, the COFF header, the optional header and
/// the section table.
///
/// Return `None` if the size overflows `usize`.
#[must_use]
pub fn headers_size(num_sections: usize, optional_header_size: usize) -> Option<usize> {
    headers_size_at(DosHeader::SIZE, num_sections, optional_header_size)
}

/// Calculate the end of the PE headers for a PE signature at the file offset `pe_offset`.
///
/// Unlike [`headers_size`], this function includes the DOS stub and any padding before the
/// PE signature. The `e_lfanew` value of the DOS header gives this offset.
#[must_use]
pub fn headers_size_at(
    pe_offset: usize,
    num_sections: usize,
    optional_header_size: usize,
) -> Option<usize> {
    let section_table_size = num_sections.checked_mul(SectionHeader::SIZE)?;
    pe_offset
        .checked_add(4 + CoffHeader::SIZE)
        .and_then(|size| size.checked_add(optional_header_size))
        .and_then(|size| size.checked_add(section_table_size))
}

/// Calculate the end of the NT headers for a PE signature at the file offset `pe_offset`.
///
/// `declared_optional_size` is `SizeOfOptionalHeader`: the distance from the start of the
/// optional header to the section table. `optional_size` is the size of the optional header with
/// its data directories. If `optional_size` is larger, the optional header overlaps the section
/// table. The NT headers end after the section table or after the optional header, whichever is
/// later.
pub(crate) fn nt_headers_end(
    pe_offset: usize,
    num_sections: usize,
    declared_optional_size: usize,
    optional_size: usize,
) -> Option<usize> {
    let table_end = headers_size_at(pe_offset, num_sections, declared_optional_size)?;
    let optional_end = headers_size_at(pe_offset, 0, optional_size)?;
    Some(table_end.max(optional_end))
}

/// The unit to which the loader rounds down `PointerToRawData`.
const LOADER_RAW_UNIT: u32 = 0x200;

/// Return the file offset where the loader reads the raw data of a section.
///
/// If `FileAlignment` is 0x200 or more, the loader rounds `PointerToRawData` down to a multiple of
/// 0x200. With a smaller (low) `FileAlignment`, the loader uses the value as it is.
pub(crate) fn loader_raw_offset(pointer_to_raw_data: u32, file_alignment: u32) -> u32 {
    if file_alignment >= LOADER_RAW_UNIT {
        pointer_to_raw_data & !(LOADER_RAW_UNIT - 1)
    } else {
        pointer_to_raw_data
    }
}

/// Convert an RVA in a section to the file offset where the loader reads the byte.
///
/// The result is `None` if the RVA is not in the raw data of the section.
pub(crate) fn section_rva_to_file_offset(
    header: &SectionHeader,
    rva: u32,
    file_alignment: u32,
) -> Option<u32> {
    let rounding =
        header.pointer_to_raw_data - loader_raw_offset(header.pointer_to_raw_data, file_alignment);
    header.rva_to_offset(rva)?.checked_sub(rounding)
}

/// Calculate the section layout again (RVAs and file offsets).
///
/// Returns the total file size.
///
/// # Panics
///
/// Panics if a section RVA, file offset or aligned size overflows `u32`. For a fallible
/// layout, use [`try_layout_sections`].
pub fn layout_sections(sections: &mut [Section], config: &LayoutConfig, headers_size: u32) -> u32 {
    try_layout_sections(sections, config, headers_size)
        .expect("PE layout overflow: use try_layout_sections() for fallible layout")
}

/// Calculate the section layout again, with checked size and address arithmetic.
///
/// # Errors
///
/// Returns an `InvalidSection` error in these conditions:
/// - The section data is larger than `u32`.
/// - An RVA, file offset or aligned size overflows `u32`.
pub fn try_layout_sections(
    sections: &mut [Section],
    config: &LayoutConfig,
    headers_size: u32,
) -> Result<u32> {
    // The first section starts after the headers, aligned to the section alignment.
    let mut current_rva = checked_align_up(headers_size, config.section_alignment)
        .ok_or_else(|| Error::invalid_section("first section RVA exceeds u32"))?;
    let mut current_file_offset = checked_align_up(headers_size, config.file_alignment)
        .ok_or_else(|| Error::invalid_section("first section file offset exceeds u32"))?;

    for section in sections.iter_mut() {
        let data_size = u32::try_from(section.data.len()).map_err(|_| {
            Error::invalid_section(format!("section '{}' data exceeds u32", section.name()))
        })?;
        let old_raw_size = section.header.size_of_raw_data;
        let preserved_raw_size = section.preserved_raw_size();
        let initialized_size = preserved_raw_size.unwrap_or(data_size);

        // Keep valid gaps in parsed images. A new section (address zero) gets the next slot.
        // A section that moves because an earlier section grew also gets the next slot.
        let existing_rva = section.header.virtual_address;
        section.header.virtual_address = if existing_rva >= current_rva
            && (config.section_alignment == 0
                || existing_rva.is_multiple_of(config.section_alignment))
        {
            existing_rva
        } else {
            current_rva
        };

        // Set the file offset.
        let existing_file_offset = section.header.pointer_to_raw_data;
        section.header.pointer_to_raw_data = if initialized_size == 0 {
            0
        } else if existing_file_offset >= current_file_offset
            && existing_file_offset != 0
            && (config.file_alignment == 0
                || existing_file_offset.is_multiple_of(config.file_alignment))
        {
            existing_file_offset
        } else {
            current_file_offset
        };

        // `VirtualSize` does not include raw file padding. Keep the parsed value, unless the
        // data grew past the old raw extent. This also keeps BSS sections (`VirtualSize` > 0,
        // no raw bytes) intact. A `VirtualSize` of 0 makes the old `SizeOfRawData` the virtual
        // extent, so keep that extent also if the data is shorter, for example after the end of
        // the file.
        let virtual_size = if section.header.virtual_size == 0 {
            data_size.max(old_raw_size)
        } else if data_size > old_raw_size {
            section.header.virtual_size.max(data_size)
        } else {
            section.header.virtual_size
        };
        section.header.virtual_size = virtual_size;
        section.header.size_of_raw_data = match preserved_raw_size {
            Some(size) => size,
            None => checked_align_up(initialized_size, config.file_alignment).ok_or_else(|| {
                Error::invalid_section(format!(
                    "section '{}' raw size exceeds u32 after alignment",
                    section.name()
                ))
            })?,
        };

        // Advance the RVA (aligned to the section alignment).
        let mapped_size = virtual_size.max(section.header.size_of_raw_data).max(1);
        let section_end = section
            .header
            .virtual_address
            .checked_add(mapped_size)
            .ok_or_else(|| {
                Error::invalid_section(format!(
                    "section '{}' virtual range overflows",
                    section.name()
                ))
            })?;
        current_rva = checked_align_up(section_end, config.section_alignment).ok_or_else(|| {
            Error::invalid_section(format!(
                "section '{}' virtual end exceeds u32 after alignment",
                section.name()
            ))
        })?;

        // Advance the file offset (aligned to the file alignment).
        if initialized_size != 0 {
            current_file_offset = section
                .header
                .pointer_to_raw_data
                .checked_add(section.header.size_of_raw_data)
                .ok_or_else(|| {
                    Error::invalid_section(format!(
                        "section '{}' raw-file range overflows",
                        section.name()
                    ))
                })?;
        }
    }

    Ok(current_file_offset)
}

/// Calculate `SizeOfImage`: the total virtual size, aligned to the section alignment.
///
/// # Panics
///
/// Panics if the aligned virtual end of a section overflows `u32`. For a fallible
/// calculation, use [`try_calculate_size_of_image`].
#[must_use]
pub fn calculate_size_of_image(sections: &[Section], config: &LayoutConfig) -> u32 {
    try_calculate_size_of_image(sections, config)
        .expect("PE image-size overflow: use try_calculate_size_of_image()")
}

/// Calculate `SizeOfImage` with checked address arithmetic.
///
/// # Errors
///
/// Returns an `InvalidSection` error if the aligned virtual end of a section overflows
/// `u32`.
pub fn try_calculate_size_of_image(sections: &[Section], config: &LayoutConfig) -> Result<u32> {
    if sections.is_empty() {
        return checked_align_up(0x1000, config.section_alignment)
            .ok_or_else(|| Error::invalid_section("minimum image size exceeds u32"));
    }

    sections
        .iter()
        .map(|section| {
            let mapped_size = section
                .header
                .virtual_size
                .max(section.header.size_of_raw_data)
                .max(1);
            let end = section
                .header
                .virtual_address
                .checked_add(mapped_size)
                .ok_or_else(|| {
                    Error::invalid_section(format!(
                        "section '{}' virtual range overflows",
                        section.name()
                    ))
                })?;
            checked_align_up(end, config.section_alignment).ok_or_else(|| {
                Error::invalid_section(format!(
                    "section '{}' virtual end exceeds u32 after alignment",
                    section.name()
                ))
            })
        })
        .try_fold(0u32, |maximum, size| size.map(|size| maximum.max(size)))
}

/// Calculate `SizeOfImage` for sections that follow headers of `size_of_headers` bytes.
///
/// The image always maps the complete headers, also if no section follows them.
pub(crate) fn try_calculate_size_of_image_with_headers(
    sections: &[Section],
    config: &LayoutConfig,
    size_of_headers: u32,
) -> Result<u32> {
    let headers_end = checked_align_up(size_of_headers, config.section_alignment)
        .ok_or_else(|| Error::invalid_section("SizeOfHeaders exceeds u32 after alignment"))?;
    Ok(try_calculate_size_of_image(sections, config)?.max(headers_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x200), 0);
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0, 0x200), 0);
        assert_eq!(align_down(0x1FF, 0x200), 0);
        assert_eq!(align_down(0x200, 0x200), 0x200);
        assert_eq!(align_down(0x3FF, 0x200), 0x200);
    }

    #[test]
    fn headers_size_reports_overflow() {
        assert_eq!(
            headers_size(1, 0xE0),
            Some(DosHeader::SIZE + 4 + CoffHeader::SIZE + 0xE0 + SectionHeader::SIZE)
        );
        assert_eq!(headers_size(usize::MAX, 0), None);
        assert_eq!(headers_size(0, usize::MAX), None);
    }
}
