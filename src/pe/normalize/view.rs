//! The loader view of a raw file: the bytes that the Windows loader maps into memory.
//!
//! [`PeFile::normalize`](crate::PeFile::normalize) compares the loader view of each candidate
//! with the loader view of the built original. It accepts a candidate only if the loader maps
//! the same bytes.

use super::{NormalizeKept, PAGE_SIZE, loader_virtual_size};
use crate::data_dir::{DataDirectory, DataDirectoryType};
use crate::debug::DebugDirectory;
use crate::delay_import::{DelayImportDirectory, DelayImportThunk, DelayLoadDescriptor};
use crate::import::{ImportDescriptor, ImportTable, ImportThunk};
use crate::layout::{checked_align_up, loader_raw_offset};
use crate::optional::OptionalHeader;
use crate::pe::PeImage;
use crate::prelude::*;
use crate::section::SectionHeader;
use crate::section::characteristics::{CODE, EXECUTE};
use core::ops::Range;

/// The offset of the `PointerToRawData` field in an `IMAGE_DEBUG_DIRECTORY` entry. This field
/// is a file offset.
const DEBUG_POINTER_OFFSET: usize = 24;

/// The size of the `PointerToRawData` field in an `IMAGE_DEBUG_DIRECTORY` entry.
const DEBUG_POINTER_SIZE: usize = 4;

/// The loader view of a raw file that [`PeFile::try_build`](crate::PeFile::try_build) made.
pub(crate) struct LoaderView<'a> {
    /// The raw file.
    bytes: &'a [u8],
    /// The optional header of the file.
    optional_header: OptionalHeader,
    /// `true` if the file is a DLL.
    is_dll: bool,
    /// The section headers of the file.
    sections: Vec<SectionHeader>,
    /// The file offset where the section table ends (the end of the NT headers).
    table_end: usize,
    /// The number of file bytes that the loader maps at RVA 0. The header bytes after this
    /// length are zero.
    header_len: usize,
    /// The RVA ranges of the structures that the loader follows from the `Import`,
    /// `DelayImport` and `Tls` directories, sorted and merged. See [`followed_ranges`].
    followed: Vec<Range<usize>>,
}

impl<'a> LoaderView<'a> {
    /// Parse a raw file that [`PeFile::try_build`](crate::PeFile::try_build) made.
    ///
    /// # Errors
    ///
    /// Return an error if [`PeImage::parse`] fails.
    pub(crate) fn parse(bytes: &'a [u8]) -> crate::Result<Self> {
        let image = PeImage::parse(bytes)?;
        let followed = followed_ranges(&image);
        // Without a known table end, protect all header bytes.
        let table_end = image.nt_headers_end().unwrap_or(0);
        let is_dll = image.coff_header.is_dll();
        let optional_header = image.optional_header;
        let sections = image
            .sections
            .into_iter()
            .map(|section| section.header)
            .collect();
        let header_len = if is_low_alignment(&optional_header) {
            // The loader maps the file as it is.
            bytes.len()
        } else {
            // The loader maps `SizeOfHeaders` bytes. The rest of the header page is zero.
            (optional_header.size_of_headers() as usize).min(bytes.len())
        };
        Ok(Self {
            bytes,
            optional_header,
            is_dll,
            sections,
            table_end,
            header_len,
            followed,
        })
    }

    /// Check that `new` keeps the loader view of `self`.
    ///
    /// Return `Ok(true)` if the `PointerToRawData` fields of `IMAGE_DEBUG_DIRECTORY` entries
    /// changed, because this is the only accepted difference. Return `Ok(false)` if there is
    /// no difference.
    ///
    /// # Errors
    ///
    /// Return the reason if `new` changes the loader view:
    ///
    /// - [`NormalizeKept::SectionAddresses`] if the section count, a section RVA, virtual
    ///   size or set of characteristics changes. If the old `SectionAlignment` is a power of
    ///   two and not smaller than a page, a change of `SizeOfHeaders` aligned up to
    ///   `SectionAlignment` is also an address change.
    /// - [`NormalizeKept::SectionData`] if the mapped file bytes of a section change. With a
    ///   low alignment, a change of the raw layout of a section is also a data change.
    /// - [`NormalizeKept::HeaderBytesInUse`] if header bytes change that the entry point, a
    ///   data directory or a followed range refers to, or if nonzero header bytes after the
    ///   section table change.
    ///
    /// The check covers the indirect references in the followed ranges of
    /// [`followed_ranges`] only. Other indirect references can point to header bytes before
    /// the end of the section table, and the check does not find them.
    pub(crate) fn check(&self, new: &LoaderView<'_>) -> Result<bool, NormalizeKept> {
        let (old_sections, new_sections) = (&self.sections, &new.sections);
        if old_sections.len() != new_sections.len() {
            return Err(NormalizeKept::SectionAddresses);
        }
        let same_addresses = old_sections.iter().zip(new_sections).all(|(old, new)| {
            old.virtual_address == new.virtual_address
                && old.characteristics == new.characteristics
                && loader_virtual_size(old) == loader_virtual_size(new)
        });
        if !same_addresses {
            return Err(NormalizeKept::SectionAddresses);
        }
        if is_low_alignment(&self.optional_header) {
            let same_raw_layout = old_sections.iter().zip(new_sections).all(|(old, new)| {
                old.pointer_to_raw_data == new.pointer_to_raw_data
                    && old.size_of_raw_data == new.size_of_raw_data
            });
            if !same_raw_layout {
                return Err(NormalizeKept::SectionData);
            }
        } else if self.optional_header.section_alignment().is_power_of_two()
            && let Some(old_aligned) = self.aligned_headers()
        {
            // The loader needs the aligned header end at the first section RVA. The candidate
            // keeps a valid old value.
            if new.aligned_headers() != Some(old_aligned) {
                return Err(NormalizeKept::SectionAddresses);
            }
        }
        let debug = self.debug_entries();
        let protected = self.protected_ranges();
        let mut debug_changed = false;
        for (old, new_header) in old_sections.iter().zip(new_sections) {
            let old_data = self.section_bytes(old);
            let new_data = new.section_bytes(new_header);
            debug_changed |= check_section_data(old, old_data, new_data, debug, &protected)?;
        }
        self.check_header_bytes(new)?;
        Ok(debug_changed)
    }

    /// Return `true` if the file bytes of each section equal the data of the same section in
    /// `image`.
    ///
    /// The method reads `data.len()` bytes at the loader raw offset of this view. A shorter
    /// side counts as zero-extended. Return `false` if the section counts differ.
    pub(crate) fn keeps_section_data(&self, image: &PeImage) -> bool {
        if self.sections.len() != image.sections.len() {
            return false;
        }
        let file_alignment = self.optional_header.file_alignment();
        self.sections
            .iter()
            .zip(&image.sections)
            .all(|(header, section)| {
                let file_bytes: &[u8] =
                    if header.pointer_to_raw_data == 0 || header.size_of_raw_data == 0 {
                        &[]
                    } else {
                        let start =
                            loader_raw_offset(header.pointer_to_raw_data, file_alignment) as usize;
                        part(self.bytes, start, start.saturating_add(section.data.len()))
                    };
                zero_extended_eq(file_bytes, &section.data)
            })
    }

    /// Return `SizeOfHeaders` aligned up to `SectionAlignment`, or `None` on overflow.
    fn aligned_headers(&self) -> Option<u32> {
        checked_align_up(
            self.optional_header.size_of_headers(),
            self.optional_header.section_alignment(),
        )
    }

    /// Return the data directory entry of the given type.
    fn data_directory(&self, kind: DataDirectoryType) -> Option<&DataDirectory> {
        self.optional_header.data_directories().get(kind.as_index())
    }

    /// Return the file bytes that the loader maps for the section `header`.
    ///
    /// The bytes start at the loader raw offset. They end at the aligned raw end or at the
    /// aligned virtual end, whichever is first. The result is clipped to the file length.
    fn section_bytes(&self, header: &SectionHeader) -> &'a [u8] {
        if header.pointer_to_raw_data == 0 || header.size_of_raw_data == 0 {
            return &[];
        }
        let file_alignment = self.optional_header.file_alignment();
        let start = loader_raw_offset(header.pointer_to_raw_data, file_alignment) as usize;
        let raw_end = header
            .pointer_to_raw_data
            .checked_add(header.size_of_raw_data)
            .and_then(|end| {
                if file_alignment.is_power_of_two() {
                    checked_align_up(end, file_alignment)
                } else {
                    Some(end)
                }
            })
            .map_or(usize::MAX, |end| end as usize);
        let virtual_len = checked_align_up(
            loader_virtual_size(header),
            self.optional_header.section_alignment(),
        )
        .map_or(usize::MAX, |len| len as usize);
        let mapped_end = raw_end.min(start.saturating_add(virtual_len));
        part(self.bytes, start, mapped_end)
    }

    /// Return the RVA and the number of `IMAGE_DEBUG_DIRECTORY` entries of this view.
    fn debug_entries(&self) -> Option<(usize, usize)> {
        self.data_directory(DataDirectoryType::Debug)
            .map(|directory| {
                (
                    directory.virtual_address as usize,
                    directory.size as usize / DebugDirectory::SIZE,
                )
            })
    }

    /// Return the RVA ranges that the debug exception must not touch, sorted and merged: the
    /// data directories and the followed ranges.
    ///
    /// The method skips the `Debug`, `Security`, `Architecture`, `GlobalPtr`, `Reserved` and
    /// unknown data directory entries. A size of 0 gives a range to the end of the address
    /// space.
    fn protected_ranges(&self) -> Vec<Range<usize>> {
        let mut ranges = self.followed.clone();
        for (index, directory) in self.optional_header.data_directories().iter().enumerate() {
            let skipped = matches!(
                DataDirectoryType::from_index(index),
                Some(
                    DataDirectoryType::Debug
                        | DataDirectoryType::Security
                        | DataDirectoryType::Architecture
                        | DataDirectoryType::GlobalPtr
                        | DataDirectoryType::Reserved,
                ) | None
            );
            if skipped || !directory.is_present() {
                continue;
            }
            let start = directory.virtual_address as usize;
            let end = if directory.size == 0 {
                usize::MAX
            } else {
                start.saturating_add(directory.size as usize)
            };
            ranges.push(start..end);
        }
        merge_ranges(ranges)
    }

    /// Check that `new` has the header bytes that the entry point, the data directories and
    /// the followed ranges of this view refer to.
    ///
    /// For the bytes after the section table, check only the nonzero old bytes. A zero old
    /// byte can change, because the new section table can grow into zero padding.
    fn check_header_bytes(&self, new: &LoaderView<'_>) -> Result<(), NormalizeKept> {
        let bound_imports = |view: &LoaderView<'_>| {
            view.data_directory(DataDirectoryType::BoundImport)
                .copied()
                .filter(|directory| directory.is_present())
        };
        let cleared_bound_imports = bound_imports(self).filter(|_| bound_imports(new).is_none());
        let (old_header, new_header) = (self.header_bytes(), new.header_bytes());
        // Both views are zero after the longer header.
        let view_end = old_header.len().max(new_header.len());
        for range in self.header_references(cleared_bound_imports) {
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
        for range in self.table_end_references(cleared_bound_imports) {
            let old_part = part(old_header, range.start, range.end);
            let new_part = part(new_header, range.start, range.end);
            if !keeps_nonzero_bytes(old_part, new_part) {
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
    /// loader maps from the file, or `usize::MAX` if there is no such section. A section
    /// without raw bytes (`PointerToRawData` or `SizeOfRawData` is 0) does not end the header
    /// bytes.
    fn header_end(&self) -> usize {
        self.sections
            .iter()
            .filter(|header| header.pointer_to_raw_data != 0 && header.size_of_raw_data != 0)
            .map(|header| header.virtual_address as usize)
            .min()
            .unwrap_or(usize::MAX)
    }

    /// Return the ranges of header bytes that the entry point, the data directories and the
    /// followed ranges refer to.
    ///
    /// The method skips the entries that the loader does not read: `Security` (a file offset),
    /// the reserved entries, and entries with an RVA of 0. It skips `BoundImport` if
    /// `cleared_bound_imports` holds it. A directory uses the rest of the headers, because the
    /// loader ignores the size of some directories. A followed range that starts in the
    /// headers uses its own length.
    fn header_references(&self, cleared_bound_imports: Option<DataDirectory>) -> Vec<Range<usize>> {
        let header_end = self.header_end();
        let mut ranges = Vec::new();
        let entry_point = self.optional_header.address_of_entry_point() as usize;
        // A DLL has no entry point if the value is 0. An executable starts at RVA 0 then.
        if entry_point < header_end && (entry_point != 0 || !self.is_dll) {
            ranges.push(entry_point..header_end);
        }
        for (index, directory) in self.optional_header.data_directories().iter().enumerate() {
            let skipped = match DataDirectoryType::from_index(index) {
                Some(
                    DataDirectoryType::Security
                    | DataDirectoryType::Architecture
                    | DataDirectoryType::GlobalPtr
                    | DataDirectoryType::Reserved,
                )
                | None => true,
                Some(DataDirectoryType::BoundImport) => cleared_bound_imports.is_some(),
                Some(_) => false,
            };
            let start = directory.virtual_address as usize;
            if !skipped && directory.virtual_address != 0 && start < header_end {
                ranges.push(start..header_end);
            }
        }
        for range in &self.followed {
            if range.start < header_end {
                ranges.push(range.start..range.end.min(header_end));
            }
        }
        ranges
    }

    /// Return the ranges of header bytes after the section table. An indirect RVA that the
    /// followed ranges do not cover can point there. The ranges exclude the cleared
    /// `BoundImport` data in `cleared_bound_imports`.
    fn table_end_references(
        &self,
        cleared_bound_imports: Option<DataDirectory>,
    ) -> [Range<usize>; 2] {
        let header_end = self.header_end();
        match cleared_bound_imports {
            Some(bound) => {
                let start = bound.virtual_address as usize;
                let end = if bound.size == 0 {
                    header_end
                } else {
                    start.saturating_add(bound.size as usize)
                };
                [
                    self.table_end..start.min(header_end),
                    end.max(self.table_end)..header_end,
                ]
            }
            None => [self.table_end..header_end, 0..0],
        }
    }
}

/// Check that `new_data` has the mapped bytes `old_data` of the section `old`. A shorter
/// slice counts as zero-extended.
///
/// Return `Ok(true)` if only bytes of `PointerToRawData` fields of `IMAGE_DEBUG_DIRECTORY`
/// entries changed. The exception applies only to a section without `IMAGE_SCN_CNT_CODE` or
/// `IMAGE_SCN_MEM_EXECUTE`, and only outside the `protected` RVA ranges. These ranges must be
/// sorted and merged. Return `Err(SectionData)` for any other difference.
fn check_section_data(
    old: &SectionHeader,
    old_data: &[u8],
    new_data: &[u8],
    debug: Option<(usize, usize)>,
    protected: &[Range<usize>],
) -> Result<bool, NormalizeKept> {
    if zero_extended_eq(old_data, new_data) {
        return Ok(false);
    }
    if old.characteristics & (CODE | EXECUTE) != 0 {
        return Err(NormalizeKept::SectionData);
    }
    let base = old.virtual_address as usize;
    let len = old_data.len().max(new_data.len());
    for offset in 0..len {
        let old_byte = old_data.get(offset).copied().unwrap_or(0);
        let new_byte = new_data.get(offset).copied().unwrap_or(0);
        if old_byte == new_byte {
            continue;
        }
        let allowed = base
            .checked_add(offset)
            .is_some_and(|rva| is_debug_pointer(rva, debug) && !ranges_contain(protected, rva));
        if !allowed {
            return Err(NormalizeKept::SectionData);
        }
    }
    Ok(true)
}

/// Return `true` if `SectionAlignment` is smaller than a page. The loader then maps the file
/// as it is.
fn is_low_alignment(header: &OptionalHeader) -> bool {
    let alignment = header.section_alignment();
    alignment.is_power_of_two() && alignment < PAGE_SIZE
}

/// Return `true` if `rva` is inside a `PointerToRawData` field of an `IMAGE_DEBUG_DIRECTORY`
/// entry. `debug` holds the RVA and the number of entries of the debug directory.
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

/// Return `true` if each nonzero byte of `old` has the same value in `new`. Bytes after the
/// end of `new` are zero.
fn keeps_nonzero_bytes(old: &[u8], new: &[u8]) -> bool {
    old.iter()
        .enumerate()
        .all(|(index, byte)| *byte == 0 || new.get(index) == Some(byte))
}

/// Return `true` if one of the sorted and merged `ranges` contains `rva`.
fn ranges_contain(ranges: &[Range<usize>], rva: usize) -> bool {
    let after = ranges.partition_point(|range| range.start <= rva);
    after
        .checked_sub(1)
        .and_then(|index| ranges.get(index))
        .is_some_and(|range| rva < range.end)
}

/// Sort `ranges` and merge the ranges that overlap or touch. Remove empty ranges.
fn merge_ranges(mut ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    ranges.retain(|range| range.start < range.end);
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

/// Return the range of `len` bytes at `rva`. The range ends at `usize::MAX` on overflow.
fn range_at(rva: u32, len: usize) -> Range<usize> {
    let start = rva as usize;
    start..start.saturating_add(len)
}

/// Return the RVA ranges of the structures that the loader follows, sorted and merged.
///
/// The ranges are:
///
/// - the `Import` descriptor array, up to and including the null descriptor;
/// - for each import descriptor, the DLL name with its NUL, and the `OriginalFirstThunk` and
///   `FirstThunk` arrays up to and including the null thunk;
/// - each hint/name entry: the 2-byte hint, the name and its NUL;
/// - the same items for `DelayImport`;
/// - the TLS callback array, up to and including the null entry.
///
/// The walk ignores the directory sizes, because the loader reads up to the null entries. The
/// parsers of the crate give the limits of the walk: 65,536 descriptors, 1,048,576 thunks per
/// array, and 65,536 TLS callbacks. If the `Import` or `DelayImport` parse fails, the range
/// from the directory RVA to the end of the address space is followed. A failed TLS parse gives
/// no range.
fn followed_ranges(image: &PeImage) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let is_64bit = image.is_64bit();
    let thunk_size = if is_64bit { 8 } else { 4 };
    let reader = image.rva_reader();
    let read = |rva: u32, len: usize| reader.read(rva, len);
    let directory_rva = |kind| {
        image
            .data_directory(kind)
            .map(|directory: &DataDirectory| directory.virtual_address)
            .filter(|rva| *rva != 0)
    };
    if let Some(rva) = directory_rva(DataDirectoryType::Import) {
        let walked = ImportTable::parse(rva, is_64bit, read)
            .ok()
            .and_then(|table| push_import_ranges(&mut ranges, &read, rva, &table, thunk_size));
        if walked.is_none() {
            ranges.push(rva as usize..usize::MAX);
        }
    }
    if let Some(rva) = directory_rva(DataDirectoryType::DelayImport) {
        let image_base = image.runtime_image_base();
        let walked = DelayImportDirectory::parse_with_image_base(rva, image_base, is_64bit, read)
            .ok()
            .and_then(|table| {
                push_delay_import_ranges(&mut ranges, &read, rva, &table, thunk_size)
            });
        if walked.is_none() {
            ranges.push(rva as usize..usize::MAX);
        }
    }
    if let Ok(Some(tls)) = image.tls()
        && let Some(directory) = tls.directory.as_ref().filter(|tls| tls.has_callbacks())
        && let Some(array) = directory
            .callbacks_va()
            .checked_sub(tls.image_base)
            .and_then(|rva| u32::try_from(rva).ok())
    {
        let len = tls
            .callback_rvas
            .len()
            .saturating_add(1)
            .saturating_mul(thunk_size);
        ranges.push(range_at(array, len));
    }
    merge_ranges(ranges)
}

/// Add the followed ranges of the import table `table` at `rva` to `ranges`. Return `None`
/// if a thunk array cannot be read again.
fn push_import_ranges(
    ranges: &mut Vec<Range<usize>>,
    read: &impl Fn(u32, usize) -> Option<Vec<u8>>,
    rva: u32,
    table: &ImportTable,
    thunk_size: usize,
) -> Option<()> {
    let count = table.dlls.len().checked_add(1)?;
    ranges.push(range_at(rva, count.checked_mul(ImportDescriptor::SIZE)?));
    for dll in &table.dlls {
        let descriptor = &dll.descriptor;
        ranges.push(range_at(
            descriptor.name_rva,
            dll.name.len().checked_add(1)?,
        ));
        // The parser reads the names from `OriginalFirstThunk`, or from `FirstThunk` if
        // `OriginalFirstThunk` is 0.
        let name_table = if descriptor.original_first_thunk == 0 {
            descriptor.first_thunk
        } else {
            descriptor.original_first_thunk
        };
        let names = dll.imports.iter().map(|thunk| match thunk {
            ImportThunk::Name { name, .. } => Some(name.len()),
            ImportThunk::Ordinal(_) => None,
        });
        push_thunk_ranges(
            ranges,
            read,
            [name_table, descriptor.first_thunk],
            thunk_size,
            names,
        )?;
    }
    Some(())
}

/// Add the followed ranges of the delay-load import table `table` at `rva` to `ranges`.
/// Return `None` if a thunk array cannot be read again.
fn push_delay_import_ranges(
    ranges: &mut Vec<Range<usize>>,
    read: &impl Fn(u32, usize) -> Option<Vec<u8>>,
    rva: u32,
    table: &DelayImportDirectory,
    thunk_size: usize,
) -> Option<()> {
    let count = table.dlls.len().checked_add(1)?;
    ranges.push(range_at(rva, count.checked_mul(DelayLoadDescriptor::SIZE)?));
    for dll in &table.dlls {
        // The parser converts the VAs of a legacy descriptor to RVAs.
        let descriptor = &dll.descriptor;
        ranges.push(range_at(
            descriptor.dll_name_rva,
            dll.name.len().checked_add(1)?,
        ));
        let names = dll.imports.iter().map(|thunk| match thunk {
            DelayImportThunk::Name { name, .. } => Some(name.len()),
            DelayImportThunk::Ordinal(_) => None,
        });
        push_thunk_ranges(
            ranges,
            read,
            [
                descriptor.import_name_table_rva,
                descriptor.import_address_table_rva,
            ],
            thunk_size,
            names,
        )?;
    }
    Some(())
}

/// Add the ranges of the thunk arrays `tables` and of their hint/name entries to `ranges`.
///
/// `tables` holds the RVA of the name table, from which the parser read `names`, and the RVA
/// of the address table. Each array has one thunk of `thunk_size` bytes for each item of
/// `names`, and the null thunk. An RVA of 0 has no array. `names` holds the name length of
/// each import by name, and `None` for each import by ordinal. Return `None` if the name table
/// cannot be read again.
fn push_thunk_ranges(
    ranges: &mut Vec<Range<usize>>,
    read: &impl Fn(u32, usize) -> Option<Vec<u8>>,
    tables: [u32; 2],
    thunk_size: usize,
    names: impl ExactSizeIterator<Item = Option<usize>>,
) -> Option<()> {
    let count = names.len();
    let array_len = count.checked_add(1)?.checked_mul(thunk_size)?;
    for table in tables.into_iter().filter(|table| *table != 0) {
        ranges.push(range_at(table, array_len));
    }
    if count == 0 {
        return Some(());
    }
    let values = read(tables[0], count.checked_mul(thunk_size)?)?;
    for (value, name_len) in values.chunks_exact(thunk_size).zip(names) {
        let Some(name_len) = name_len else {
            continue;
        };
        // The thunk of an import by name holds the RVA of the entry. The parser checks that
        // the value fits 31 bits (PE32) or 32 bits (PE32+), so the low 4 bytes hold it.
        let hint_rva = u32::from_le_bytes(*value.first_chunk::<4>()?);
        ranges.push(range_at(hint_rva, name_len.checked_add(3)?));
    }
    Some(())
}
