//! The raw-file layout helpers of `PeFile`: the image end, the certificate range and the raw gaps.

use core::ops::Range;

use crate::data_dir::DataDirectoryType;
use crate::prelude::*;
use crate::security::SecurityDirectory;
use crate::{Error, PeImage, Result};

/// The raw layout fields of an image. The build keeps the raw gaps of the source only if these
/// fields do not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawLayoutFingerprint {
    pe_offset: usize,
    optional_header_size: usize,
    size_of_headers: usize,
    sections: Vec<(u32, u32)>,
}

/// Source bytes that the image does not hold, and their file range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PreservedRegion {
    range: Range<usize>,
    data: Vec<u8>,
}

/// Return the file offset after the headers and the raw data of the sections.
///
/// The result can be past the end of the file. The raw data starts where the loader reads it.
pub(super) fn raw_image_end(pe: &PeImage) -> Result<usize> {
    let file_alignment = pe.optional_header.file_alignment();
    let mut image_end = u64::from(pe.optional_header.size_of_headers());
    for section in &pe.sections {
        let header = &section.header;
        if header.pointer_to_raw_data == 0 || header.size_of_raw_data == 0 {
            continue;
        }
        let start = crate::layout::loader_raw_offset(header.pointer_to_raw_data, file_alignment);
        image_end = image_end.max(u64::from(start) + u64::from(header.size_of_raw_data));
    }
    Ok(usize::try_from(image_end)
        .unwrap_or(usize::MAX)
        .max(nt_headers_end(pe)?))
}

/// Return the range of the certificate table, as offsets from the start of the overlay.
///
/// The result is `None` if the Security directory is absent, or if it does not give a valid
/// certificate table in the overlay: inside the file, after `image_end`, aligned to 8 bytes, and
/// with entries that parse.
pub(super) fn certificate_range(
    pe: &PeImage,
    data: &[u8],
    image_end: usize,
) -> Option<Range<usize>> {
    let directory = pe
        .data_directory(DataDirectoryType::Security)
        .filter(|directory| directory.is_present())?;
    let start = directory.virtual_address as usize;
    let end = start.checked_add(directory.size as usize)?;
    let valid = directory.virtual_address != 0
        && directory.size != 0
        && start >= image_end
        && start.is_multiple_of(8)
        && data
            .get(start..end)
            .is_some_and(|table| SecurityDirectory::parse(table).is_ok());
    valid.then(|| (start - image_end)..(end - image_end))
}

/// Return the file offset of the end of the NT headers.
///
/// The loader reads the complete section table and optional header, also if they end after
/// `SizeOfHeaders`.
pub(super) fn nt_headers_end(image: &PeImage) -> Result<usize> {
    image
        .nt_headers_end()
        .ok_or_else(|| Error::invalid_section("NT header offset overflow"))
}

impl RawLayoutFingerprint {
    pub(super) fn from_image(image: &PeImage) -> Result<Self> {
        let pe_offset = usize::try_from(image.dos_header.e_lfanew)
            .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
        Ok(Self {
            pe_offset,
            optional_header_size: usize::from(image.coff_header.size_of_optional_header),
            size_of_headers: image.optional_header.size_of_headers() as usize,
            sections: image
                .sections
                .iter()
                .map(|section| {
                    (
                        section.header.pointer_to_raw_data,
                        section.header.size_of_raw_data,
                    )
                })
                .collect(),
        })
    }
}

pub(super) fn collect_preserved_regions(
    data: &[u8],
    image: &PeImage,
    image_end: usize,
) -> Result<Vec<PreservedRegion>> {
    // The image keeps the header bytes after the section table and the padding before it, so
    // the gaps start after them.
    let headers_end = nt_headers_end(image)?;
    let header_data_end = image.header_data_end(headers_end).unwrap_or(headers_end);

    let mut regions = Vec::new();

    let file_alignment = image.optional_header.file_alignment();
    let mut occupied: Vec<Range<usize>> = image
        .sections
        .iter()
        .filter(|section| {
            section.header.pointer_to_raw_data != 0 && section.header.size_of_raw_data != 0
        })
        .map(|section| {
            // The section data starts where the loader reads it.
            let start = crate::layout::loader_raw_offset(
                section.header.pointer_to_raw_data,
                file_alignment,
            ) as usize;
            start..start.saturating_add(section.header.size_of_raw_data as usize)
        })
        .collect();
    occupied.sort_by_key(|range| range.start);

    let mut cursor = header_data_end.min(image_end);
    for range in occupied {
        if range.end <= cursor {
            continue;
        }
        if range.start > cursor {
            push_preserved_region(&mut regions, data, cursor..range.start.min(image_end))?;
        }
        cursor = cursor.max(range.end.min(image_end));
        if cursor >= image_end {
            break;
        }
    }
    if cursor < image_end {
        push_preserved_region(&mut regions, data, cursor..image_end)?;
    }
    Ok(regions)
}

fn push_preserved_region(
    regions: &mut Vec<PreservedRegion>,
    source: &[u8],
    range: Range<usize>,
) -> Result<()> {
    if range.start >= range.end {
        return Ok(());
    }
    let bytes = source
        .get(range.clone())
        .ok_or_else(|| Error::buffer_too_small(range.end, source.len()))?;
    regions.push(PreservedRegion {
        range,
        data: bytes.to_vec(),
    });
    Ok(())
}

pub(super) fn restore_preserved_regions(
    output: &mut [u8],
    regions: &[PreservedRegion],
) -> Result<()> {
    for region in regions {
        let target = output.get_mut(region.range.clone()).ok_or_else(|| {
            Error::invalid_section("preserved raw-file region exceeds rebuilt image")
        })?;
        if target.len() != region.data.len() {
            return Err(Error::invalid_section(
                "preserved raw-file region changed size",
            ));
        }
        target.copy_from_slice(&region.data);
    }
    Ok(())
}

pub(super) fn align_up_usize(value: usize, alignment: usize) -> Option<usize> {
    let padding = padding_for(value, alignment);
    value.checked_add(padding)
}

pub(super) fn padding_for(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return 0;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        0
    } else {
        alignment - remainder
    }
}
