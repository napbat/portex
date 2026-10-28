//! The loader view of a raw file: the bytes that the Windows loader maps into memory.
//!
//! [`PeFile::normalize`](crate::PeFile::normalize) compares the loader view of each candidate
//! with the loader view of the original file. It accepts a candidate only if the loader maps
//! the same bytes.

use super::{NormalizeKept, PAGE_SIZE, loader_virtual_size};
use crate::data_dir::DataDirectoryType;
use crate::debug::DebugDirectory;
use crate::pe::PeImage;
use crate::prelude::*;
use crate::section::Section;
use crate::section::characteristics::{CODE, EXECUTE};
use core::ops::Range;

/// The offset of the `PointerToRawData` field in a debug directory entry.
const DEBUG_POINTER_OFFSET: usize = 24;

/// The size of the `PointerToRawData` field in a debug directory entry.
const DEBUG_POINTER_SIZE: usize = 4;

/// The loader view of a raw file that [`PeFile::try_build`](crate::PeFile::try_build) made.
pub(crate) struct LoaderView<'a> {
    /// The raw file.
    bytes: &'a [u8],
    /// The parsed file.
    image: PeImage,
    /// The number of file bytes that the loader maps at RVA 0. The header bytes after this
    /// length are zero.
    header_len: usize,
}

impl<'a> LoaderView<'a> {
    /// Parse a raw file that [`PeFile::try_build`](crate::PeFile::try_build) made.
    ///
    /// # Errors
    ///
    /// Return an error if [`PeImage::parse`] fails.
    pub(crate) fn parse(bytes: &'a [u8]) -> crate::Result<Self> {
        let image = PeImage::parse(bytes)?;
        let header_len = if is_low_alignment(&image) {
            // The loader maps the file as it is.
            bytes.len()
        } else {
            // The loader maps `SizeOfHeaders` bytes. The rest of the header page is zero.
            (image.optional_header.size_of_headers() as usize).min(bytes.len())
        };
        Ok(Self {
            bytes,
            image,
            header_len,
        })
    }

    /// Check that `new` keeps the loader view of `self`.
    ///
    /// Return `Ok(true)` if the debug `PointerToRawData` fields changed, because this is the
    /// only accepted difference. Return `Ok(false)` if there is no difference.
    ///
    /// # Errors
    ///
    /// Return the reason if `new` changes the loader view:
    ///
    /// - [`NormalizeKept::SectionAddresses`] if a section RVA, virtual size or set of
    ///   characteristics changes.
    /// - [`NormalizeKept::SectionData`] if section data changes. With a low alignment, a
    ///   change of the raw layout of a section is also a data change.
    /// - [`NormalizeKept::HeaderBytesInUse`] if header bytes that the entry point or a data
    ///   directory refers to change.
    pub(crate) fn check(&self, new: &LoaderView<'_>) -> Result<bool, NormalizeKept> {
        let (old_sections, new_sections) = (&self.image.sections, &new.image.sections);
        if old_sections.len() != new_sections.len() {
            return Err(NormalizeKept::SectionAddresses);
        }
        let same_addresses = old_sections.iter().zip(new_sections).all(|(old, new)| {
            old.header.virtual_address == new.header.virtual_address
                && old.header.characteristics == new.header.characteristics
                && loader_virtual_size(&old.header) == loader_virtual_size(&new.header)
        });
        if !same_addresses {
            return Err(NormalizeKept::SectionAddresses);
        }
        if is_low_alignment(&self.image) {
            let same_raw_layout = old_sections.iter().zip(new_sections).all(|(old, new)| {
                old.header.pointer_to_raw_data == new.header.pointer_to_raw_data
                    && old.header.size_of_raw_data == new.header.size_of_raw_data
            });
            if !same_raw_layout {
                return Err(NormalizeKept::SectionData);
            }
        }
        let mut debug_changed = false;
        for (old, new) in old_sections.iter().zip(new_sections) {
            debug_changed |= self.check_section_data(old, new)?;
        }
        self.check_header_bytes(new)?;
        Ok(debug_changed)
    }

    /// Check that `new` has the data of the section `old`. A shorter slice counts as
    /// zero-extended.
    ///
    /// Return `Ok(true)` if only bytes of debug `PointerToRawData` fields changed in a section
    /// that is not code. Return `Err(SectionData)` for any other difference.
    fn check_section_data(&self, old: &Section, new: &Section) -> Result<bool, NormalizeKept> {
        let (old_data, new_data) = (old.data.as_slice(), new.data.as_slice());
        if zero_extended_eq(old_data, new_data) {
            return Ok(false);
        }
        if old.header.characteristics & (CODE | EXECUTE) != 0 {
            return Err(NormalizeKept::SectionData);
        }
        let debug = self.debug_entries();
        let base = old.header.virtual_address as usize;
        let len = old_data.len().max(new_data.len());
        for offset in 0..len {
            let old_byte = old_data.get(offset).copied().unwrap_or(0);
            let new_byte = new_data.get(offset).copied().unwrap_or(0);
            if old_byte == new_byte {
                continue;
            }
            let in_pointer = base
                .checked_add(offset)
                .is_some_and(|rva| is_debug_pointer(rva, debug));
            if !in_pointer {
                return Err(NormalizeKept::SectionData);
            }
        }
        Ok(true)
    }

    /// Return the RVA and the number of entries of the debug directory of this image.
    fn debug_entries(&self) -> Option<(usize, usize)> {
        self.image
            .data_directory(DataDirectoryType::Debug)
            .map(|directory| {
                (
                    directory.virtual_address as usize,
                    directory.size as usize / DebugDirectory::SIZE,
                )
            })
    }

    /// Check that `new` has the header bytes that the entry point and the data directories of
    /// this image refer to.
    fn check_header_bytes(&self, new: &LoaderView<'_>) -> Result<(), NormalizeKept> {
        let clears_bound_imports = self
            .image
            .data_directory(DataDirectoryType::BoundImport)
            .is_some_and(|directory| directory.is_present())
            && !new
                .image
                .data_directory(DataDirectoryType::BoundImport)
                .is_some_and(|directory| directory.is_present());
        let (old_header, new_header) = (self.header_bytes(), new.header_bytes());
        // Both views are zero after the longer header.
        let view_end = old_header.len().max(new_header.len());
        for range in self.header_references(clears_bound_imports) {
            let end = range.end.min(view_end);
            if range.start >= end {
                continue;
            }
            let old_part = part(old_header, range.start, end);
            let new_part = part(new_header, range.start, end);
            if !zero_extended_eq(old_part, new_part) {
                return Err(NormalizeKept::HeaderBytesInUse);
            }
        }
        Ok(())
    }

    /// Return the file bytes that the loader maps at RVA 0. The header bytes after them are
    /// zero.
    fn header_bytes(&self) -> &'a [u8] {
        self.bytes.get(..self.header_len).unwrap_or(self.bytes)
    }

    /// Return the RVA where the header bytes end: the RVA of the first section that the
    /// loader maps, or `usize::MAX` if there is no such section.
    fn header_end(&self) -> usize {
        self.image
            .sections
            .iter()
            .filter(|section| loader_virtual_size(&section.header) != 0)
            .map(|section| section.header.virtual_address as usize)
            .min()
            .unwrap_or(usize::MAX)
    }

    /// Return the ranges of header bytes that the loader view uses: the code at the entry
    /// point, and the data that the data directories refer to.
    ///
    /// The method skips the entries that the loader does not read: `Security` (a file offset),
    /// the reserved entries, and entries with an RVA of 0. It also skips `BoundImport` if
    /// `skip_bound_imports` is `true`. A directory with a size of 0 uses the rest of the
    /// headers, because the loader ignores the size of some directories.
    fn header_references(&self, skip_bound_imports: bool) -> Vec<Range<usize>> {
        let header_end = self.header_end();
        let header = &self.image.optional_header;
        let mut ranges = Vec::new();
        let entry_point = header.address_of_entry_point() as usize;
        // A DLL has no entry point if the value is 0. An executable starts at RVA 0 then.
        if entry_point < header_end && (entry_point != 0 || !self.image.coff_header.is_dll()) {
            ranges.push(entry_point..header_end);
        }
        for (index, directory) in header.data_directories().iter().enumerate() {
            let skipped = match DataDirectoryType::from_index(index) {
                Some(
                    DataDirectoryType::Security
                    | DataDirectoryType::Architecture
                    | DataDirectoryType::GlobalPtr
                    | DataDirectoryType::Reserved,
                )
                | None => true,
                Some(DataDirectoryType::BoundImport) => skip_bound_imports,
                Some(_) => false,
            };
            let start = directory.virtual_address as usize;
            if skipped || directory.virtual_address == 0 || start >= header_end {
                continue;
            }
            let end = if directory.size == 0 {
                header_end
            } else {
                start
                    .saturating_add(directory.size as usize)
                    .min(header_end)
            };
            ranges.push(start..end);
        }
        ranges
    }
}

/// Return `true` if `SectionAlignment` is smaller than a page. The loader then maps the file
/// as it is.
fn is_low_alignment(image: &PeImage) -> bool {
    let alignment = image.optional_header.section_alignment();
    alignment.is_power_of_two() && alignment < PAGE_SIZE
}

/// Return `true` if `rva` is inside a `PointerToRawData` field of a debug directory entry.
/// `debug` holds the RVA and the number of entries of the debug directory.
fn is_debug_pointer(rva: usize, debug: Option<(usize, usize)>) -> bool {
    let Some((start, count)) = debug else {
        return false;
    };
    let Some(offset) = rva.checked_sub(start) else {
        return false;
    };
    let field = offset % DebugDirectory::SIZE;
    offset / DebugDirectory::SIZE < count
        && (DEBUG_POINTER_OFFSET..DEBUG_POINTER_OFFSET + DEBUG_POINTER_SIZE).contains(&field)
}

/// Return the bytes of `bytes` in `start..end`. The result is shorter if `bytes` ends before
/// `end`, and empty if `bytes` ends before `start`.
fn part(bytes: &[u8], start: usize, end: usize) -> &[u8] {
    bytes.get(start..end.min(bytes.len())).unwrap_or_default()
}

/// Return `true` if `old` and `new` have the same bytes. Bytes after the end of the shorter
/// slice are zero.
fn zero_extended_eq(old: &[u8], new: &[u8]) -> bool {
    let common = old.len().min(new.len());
    let (old_head, old_tail) = old.split_at(common);
    let (new_head, new_tail) = new.split_at(common);
    old_head == new_head
        && old_tail.iter().all(|byte| *byte == 0)
        && new_tail.iter().all(|byte| *byte == 0)
}
