use super::{MAX_NUMBER_OF_SECTIONS, PeImage, SourceLayout};
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::section::Section;
use crate::{Error, Result};
use alloc::collections::BinaryHeap;
use core::cell::OnceCell;
use core::cmp::Reverse;

/// The number of zero bytes that one [`PeImage::read_rva`] call can always add.
///
/// A file that ends early can hold fewer bytes than a directory that it declares. This floor
/// lets such a read succeed, and it still limits the memory use of one read.
const MIN_ZERO_FILL: usize = 1 << 20;

impl PeImage {
    /// Return `true` if this is a 64-bit (PE32+) image.
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_pe32plus()
    }

    /// Return `true` if this image is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Return the section with the given name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    /// Return the section with the given name, as a mutable reference.
    pub fn section_by_name_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name() == name)
    }

    /// Find the section that contains an RVA.
    ///
    /// A section holds the RVAs of the size that the loader maps (see
    /// [`SectionHeader::mapped_size`](crate::SectionHeader::mapped_size)). If sections overlap,
    /// the result is the first one in table order.
    #[must_use]
    pub fn section_by_rva(&self, rva: u32) -> Option<&Section> {
        let alignment = self.optional_header.section_alignment();
        self.sections
            .iter()
            .find(|section| section_contains_rva(section, rva, alignment))
    }

    /// Find the section that contains an RVA, as a mutable reference.
    #[must_use]
    pub fn section_by_rva_mut(&mut self, rva: u32) -> Option<&mut Section> {
        let alignment = self.optional_header.section_alignment();
        self.sections
            .iter_mut()
            .find(|section| section_contains_rva(section, rva, alignment))
    }

    /// Read `len` bytes at an RVA from one section.
    ///
    /// The result is `None` if the range is not in the data of the section that
    /// [`Self::section_by_rva`] finds, or if it goes past the size that the loader maps.
    #[must_use]
    pub fn read_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let section = self.section_by_rva(rva)?;
        self.range_in_section(section, rva, len)
            .then(|| section.data_at_rva(rva, len))?
    }

    /// Read `len` bytes at an RVA into a new buffer.
    ///
    /// The range can be in the PE headers. It can also cross the boundary between contiguous
    /// sections. As in the loader view, these bytes read as zero:
    ///
    /// - The header bytes after the header data and before `SizeOfHeaders`.
    /// - The bytes of a section after its complete raw data and before its virtual end.
    ///
    /// The result is `None` if the range is not in the image. It is also `None` if the read adds
    /// more zero bytes than the image holds in its header data and section data, or than 1 MiB
    /// if that is more. This limit keeps the memory use of a read in proportion to the input, also
    /// if `SizeOfHeaders` or `VirtualSize` is very large. A range in the headers also gives `None`
    /// if the header fields cannot be serialized, for example if the DOS stub ends after
    /// `e_lfanew`.
    #[must_use]
    pub fn read_rva(&self, rva: u32, len: usize) -> Option<Vec<u8>> {
        RvaReader::new(self, SectionLookup::Table).read(rva, len)
    }

    /// Return a reader of RVA ranges for a directory parser.
    ///
    /// The reader reads as [`Self::read_rva`] does. It sorts the sections once, so that a parse
    /// that makes many reads stays fast also in an image with many sections.
    pub(super) fn rva_reader(&self) -> RvaReader<'_> {
        RvaReader::new(
            self,
            SectionLookup::sorted(&self.sections, self.optional_header.section_alignment()),
        )
    }

    /// Return the number of bytes that the image holds: the header data and the section data.
    ///
    /// The header data ends at the end of the NT headers or at the header tail after them.
    fn held_len(&self) -> usize {
        let headers = self
            .nt_headers_end()
            .and_then(|end| self.header_data_end(end))
            .unwrap_or(0);
        self.sections.iter().fold(headers, |total, section| {
            total.saturating_add(section.data.len())
        })
    }

    /// Check if an RVA range is in the headers or in the sections, without allocating or copying
    /// it.
    ///
    /// The check uses the extents of [`Self::read_rva`]. Thus the zero bytes after the raw data
    /// of a section are in the range, but [`Self::read_at_rva`] cannot borrow them.
    /// [`Self::read_rva`] can also reject a range that this method accepts, if the read adds too
    /// many zero bytes, or if it cannot serialize the headers.
    #[must_use]
    pub fn contains_rva_range(&self, rva: u32, len: usize) -> bool {
        if len == 0 {
            return rva <= self.optional_header.size_of_image();
        }
        self.visit_rva_range(&SectionLookup::Table, rva, len, |_| Some(()))
            .is_some()
    }

    /// Call `visit` for each part of the RVA range `rva..rva + len`, in RVA order.
    ///
    /// The first part can be in the headers. Each other part is in one section, up to the
    /// extent of [`mapped_extent`]. The result is `None` if a part of the range is not in the
    /// image, or if `visit` returns `None`.
    ///
    /// Each section part is in the first section in table order that contains its RVA, as
    /// [`Self::section_by_rva`] finds it. `lookup` gives the method to find that section. With
    /// [`SectionLookup::Table`], the method sorts the sections by RVA once if the range crosses
    /// into more sections. Thus a walk over many sections takes O(n log n) time, also if the
    /// section table is not in RVA order or the sections overlap.
    fn visit_rva_range<'a>(
        &'a self,
        lookup: &SectionLookup,
        rva: u32,
        len: usize,
        mut visit: impl FnMut(RvaPart<'a>) -> Option<()>,
    ) -> Option<()> {
        let end = u64::from(rva).checked_add(u64::try_from(len).ok()?)?;
        if end > u64::from(self.optional_header.size_of_image()) {
            return None;
        }

        let mut current = rva;
        let mut remaining = len;
        let section_alignment = self.optional_header.section_alignment();
        let size_of_headers = self.optional_header.size_of_headers();
        if current < size_of_headers {
            let count = ((size_of_headers - current) as usize).min(remaining);
            visit(RvaPart::Headers {
                start: current as usize,
                count,
            })?;
            current = current.checked_add(u32::try_from(count).ok()?)?;
            remaining -= count;
        }
        if remaining == 0 {
            return Some(());
        }

        if let SectionLookup::Sorted(order) = lookup {
            // The sections do not overlap. Thus the section that contains `current` is the last
            // section that starts at or before it, and the next part is in the next section.
            let mut position = order
                .partition_point(|&index| self.sections[index].header.virtual_address <= current)
                .checked_sub(1)?;
            while remaining != 0 {
                let section = &self.sections[*order.get(position)?];
                if !section_contains_rva(section, current, section_alignment) {
                    return None;
                }
                let count =
                    visit_section_part(section, section_alignment, current, remaining, &mut visit)?;
                current = current.checked_add(u32::try_from(count).ok()?)?;
                remaining -= count;
                position += 1;
            }
            return Some(());
        }

        let first = self.section_by_rva(current)?;
        let count = visit_section_part(first, section_alignment, current, remaining, &mut visit)?;
        current = current.checked_add(u32::try_from(count).ok()?)?;
        remaining -= count;
        if remaining == 0 {
            return Some(());
        }

        // Walk the other sections in RVA order. The heap holds the sections that start at or
        // before `current`, by table index. Its first unexpired entry is the first section in
        // table order that contains `current`.
        let mut later: Vec<(usize, &Section)> = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, section)| {
                u64::from(section.header.virtual_address) < end
                    && section_end(section, section_alignment) > u64::from(current)
            })
            .collect();
        later.sort_by_key(|(_, section)| section.header.virtual_address);
        let mut started = BinaryHeap::new();
        let mut next = 0;
        while remaining != 0 {
            while let Some(&(index, section)) = later.get(next)
                && section.header.virtual_address <= current
            {
                started.push(Reverse(index));
                next += 1;
            }
            while let Some(&Reverse(index)) = started.peek()
                && section_end(&self.sections[index], section_alignment) <= u64::from(current)
            {
                started.pop();
            }
            let &Reverse(index) = started.peek()?;
            let count = visit_section_part(
                &self.sections[index],
                section_alignment,
                current,
                remaining,
                &mut visit,
            )?;
            current = current.checked_add(u32::try_from(count).ok()?)?;
            remaining -= count;
        }
        Some(())
    }

    /// Write data at an RVA in one section.
    ///
    /// The result is `None` if the range is not in the data of the section that
    /// [`Self::section_by_rva`] finds, or if it goes past the size that the loader maps.
    #[must_use]
    pub fn write_at_rva(&mut self, rva: u32, data: &[u8]) -> Option<()> {
        let index = self.section_index_by_rva(rva)?;
        if !self.range_in_section(&self.sections[index], rva, data.len()) {
            return None;
        }
        let slice = self.sections[index].data_at_rva_mut(rva, data.len())?;
        slice.copy_from_slice(data);
        Some(())
    }

    /// Return the index of the section that [`Self::section_by_rva`] finds.
    fn section_index_by_rva(&self, rva: u32) -> Option<usize> {
        let alignment = self.optional_header.section_alignment();
        self.sections
            .iter()
            .position(|section| section_contains_rva(section, rva, alignment))
    }

    /// Return `true` if the range `rva..rva + len` ends inside the RVA extent of `section`.
    fn range_in_section(&self, section: &Section, rva: u32, len: usize) -> bool {
        let alignment = self.optional_header.section_alignment();
        let end = u64::from(rva).checked_add(u64::try_from(len).unwrap_or(u64::MAX));
        end.is_some_and(|end| end <= section_end(section, alignment))
    }

    /// Convert an RVA to a source offset for the given layout.
    ///
    /// The offset is relative to the start of the image. If you use [`Self::read_from`] with a
    /// nonzero `base_offset`, add that base to the offset before you read from the original
    /// source. In the file layout, the offset is where the loader reads the byte: the loader
    /// rounds `PointerToRawData` down to a multiple of 0x200 if `FileAlignment` is 0x200 or more.
    #[must_use]
    pub fn rva_to_source_offset(&self, rva: u32, layout: SourceLayout) -> Option<u32> {
        if rva >= self.optional_header.size_of_image() {
            return None;
        }

        match layout {
            SourceLayout::Mapped => Some(rva),
            SourceLayout::File => {
                if rva < self.optional_header.size_of_headers() {
                    return Some(rva);
                }
                let file_alignment = self.optional_header.file_alignment();
                let section_alignment = self.optional_header.section_alignment();
                self.sections.iter().find_map(|section| {
                    crate::layout::section_rva_to_file_offset(
                        &section.header,
                        rva,
                        file_alignment,
                        section_alignment,
                    )
                })
            }
        }
    }

    /// Convert an RVA to a file offset in the raw file.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.rva_to_source_offset(rva, SourceLayout::File)
    }

    /// Add a new section.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_add_section`] returns an error.
    pub fn add_section(&mut self, section: Section) {
        self.try_add_section(section)
            .expect("invalid PE section: use try_add_section() for fallible updates");
    }

    /// Add a section, and apply the section limit for executable images.
    ///
    /// The next layout update places the section after the last section. The section table
    /// grows by one entry. If the larger table needs the RVA of an existing section, the method
    /// returns an error, because an edit must not move a section. This can occur in an image
    /// with a low `SectionAlignment`.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions. Then the image does not change.
    ///
    /// - The image already has [`MAX_NUMBER_OF_SECTIONS`] sections.
    /// - The section data is larger than `u32::MAX` bytes.
    /// - The larger section table needs the RVA of an existing section.
    pub fn try_add_section(&mut self, section: Section) -> Result<()> {
        if self.sections.len() >= MAX_NUMBER_OF_SECTIONS {
            return Err(Error::invalid_section(format!(
                "section count would exceed the PE image limit of {MAX_NUMBER_OF_SECTIONS}"
            )));
        }
        u32::try_from(section.data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?;
        let count = u16::try_from(self.sections.len() + 1)
            .map_err(|_| Error::invalid_section("section count exceeds u16"))?;
        if let (Some(old_start), Some(new_start)) = (
            self.first_section_rva(self.sections.len()),
            self.first_section_rva(self.sections.len() + 1),
        ) && self
            .sections
            .iter()
            .any(|existing| (old_start..new_start).contains(&existing.header.virtual_address))
        {
            return Err(Error::invalid_section(format!(
                "the section table grows to {new_start:#x} and moves the first section; \
                 an edit must not move a section"
            )));
        }
        self.sections.push(section);
        self.coff_header.number_of_sections = count;
        Ok(())
    }

    /// Return the RVA of the entry point.
    #[must_use]
    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point()
    }

    /// Return the preferred image base (a VA) from the optional header.
    #[must_use]
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base()
    }

    /// Return the layout of the source that this image was parsed from.
    #[must_use]
    pub const fn source_layout(&self) -> SourceLayout {
        self.source_layout
    }

    /// Return the actual mapped base (a VA). If it is not set, return the preferred image base.
    #[must_use]
    pub fn runtime_image_base(&self) -> u64 {
        self.runtime_image_base.unwrap_or_else(|| self.image_base())
    }

    /// Set the actual mapped base (a VA). Directories that contain VAs use this base.
    pub fn set_runtime_image_base(&mut self, runtime_image_base: u64) {
        self.runtime_image_base = Some(runtime_image_base);
    }

    /// Convert an RVA to a VA with the actual mapped base, if it is known.
    #[must_use]
    pub fn rva_to_runtime_va(&self, rva: u32) -> Option<u64> {
        self.rva_to_va_at(rva, self.runtime_image_base())
    }

    /// Convert a runtime VA to an RVA with the actual mapped base, if it is known.
    #[must_use]
    pub fn runtime_va_to_rva(&self, va: u64) -> Option<u32> {
        self.va_to_rva_at(va, self.runtime_image_base())
    }

    /// Convert an RVA to a VA with the preferred image base.
    #[must_use]
    pub fn rva_to_va(&self, rva: u32) -> Option<u64> {
        self.rva_to_va_at(rva, self.image_base())
    }

    /// Convert an RVA to a VA with the given runtime image base (a VA).
    #[must_use]
    pub fn rva_to_va_at(&self, rva: u32, runtime_image_base: u64) -> Option<u64> {
        (rva < self.optional_header.size_of_image())
            .then(|| runtime_image_base.checked_add(u64::from(rva)))?
    }

    /// Convert a VA that uses the preferred image base to an RVA.
    #[must_use]
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        self.va_to_rva_at(va, self.image_base())
    }

    /// Convert a VA to an RVA with the given runtime image base (a VA).
    #[must_use]
    pub fn va_to_rva_at(&self, va: u64, runtime_image_base: u64) -> Option<u32> {
        let relative = va.checked_sub(runtime_image_base)?;
        let rva = u32::try_from(relative).ok()?;
        (rva < self.optional_header.size_of_image()).then_some(rva)
    }

    /// Return the raw bytes of a standard data directory whose address is an RVA.
    ///
    /// Use this as the lossless fallback for versioned or architecture-specific directory
    /// formats. This function rejects the Security directory, because its address is a file
    /// offset. For a full raw-file view, use [`crate::PeFile::directory_data`].
    ///
    /// # Errors
    ///
    /// Returns an error if `dir_type` is the Security directory. Also returns an error if the
    /// entry has only one of its RVA and size set, or if the image cannot supply the RVA range
    /// of the directory.
    pub fn directory_data(
        &self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Result<Option<Vec<u8>>> {
        use crate::data_dir::DataDirectoryType;

        let Some(directory) = self.data_directory(dir_type).filter(|dir| dir.is_present()) else {
            return Ok(None);
        };
        if dir_type == DataDirectoryType::Security {
            return Err(Error::invalid_data_directory(
                "the Security directory uses a file offset; parse the image with PeFile",
            ));
        }
        if directory.virtual_address == 0 || directory.size == 0 {
            return Err(Error::invalid_data_directory(format!(
                "{} directory has only one of address/size set",
                dir_type.name()
            )));
        }

        self.read_rva(directory.virtual_address, directory.size as usize)
            .map(Some)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "{} directory range {:#x}..+{:#x} is not readable",
                    dir_type.name(),
                    directory.virtual_address,
                    directory.size
                ))
            })
    }

    /// Return the data directory entry (`IMAGE_DATA_DIRECTORY`) of the given type.
    #[must_use]
    pub fn data_directory(
        &self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Option<&crate::data_dir::DataDirectory> {
        self.optional_header
            .data_directories()
            .get(dir_type.as_index())
    }

    /// Return the data directory entry (`IMAGE_DATA_DIRECTORY`) at an index (advanced use).
    #[must_use]
    pub fn data_directory_by_index(&self, index: usize) -> Option<&crate::data_dir::DataDirectory> {
        self.optional_header.data_directories().get(index)
    }

    /// Parse the import table.
    ///
    /// Returns an empty table if the import directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the import descriptors (`IMAGE_IMPORT_DESCRIPTOR`), thunks, or names
    /// cannot be read or are malformed.
    #[must_use = "parsing returns an import table that should be used"]
    pub fn imports(&self) -> Result<crate::import::ImportTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Import)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                crate::import::ImportTable::parse_sized(
                    d.virtual_address,
                    d.size,
                    self.is_64bit(),
                    read_fn,
                )
            }
            None => Ok(crate::import::ImportTable::default()),
        }
    }

    /// Parse the export table.
    ///
    /// Returns an empty table if the export directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the `IMAGE_EXPORT_DIRECTORY` or its address, name, or ordinal tables
    /// cannot be read or are malformed.
    #[must_use = "parsing returns an export table that should be used"]
    pub fn exports(&self) -> Result<crate::export::ExportTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Export)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                crate::export::ExportTable::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::export::ExportTable::default()),
        }
    }

    /// Parse the base relocation table.
    ///
    /// Returns an empty table if the base relocation directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if a base relocation block (`IMAGE_BASE_RELOCATION`) cannot be read or
    /// is malformed. Returns an [`ErrorKind::InvalidDataDirectory`](crate::ErrorKind) error if
    /// the directory is larger than the data that the image holds.
    #[must_use = "parsing returns a relocation table that should be used"]
    pub fn relocations(&self) -> Result<crate::reloc::RelocationTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::BaseReloc)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                if reader.exceeds_zero_fill(d.size) {
                    return Err(Error::invalid_data_directory(
                        "base relocation table is larger than the data that the image holds",
                    ));
                }
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                crate::reloc::RelocationTable::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::reloc::RelocationTable::default()),
        }
    }

    /// Set the RVA and size of the data directory entry of the given type.
    pub fn set_data_directory(
        &mut self,
        dir_type: crate::data_dir::DataDirectoryType,
        rva: u32,
        size: u32,
    ) {
        self.store_data_directory(dir_type.as_index(), rva, size);
    }

    /// Set the RVA and size of the data directory entry at an index (advanced use).
    ///
    /// # Errors
    ///
    /// Returns an error if `index` is [`NUMBER_OF_DIRECTORY_ENTRIES`] or more. The loader reads
    /// at most that number of entries.
    ///
    /// [`NUMBER_OF_DIRECTORY_ENTRIES`]: crate::data_dir::NUMBER_OF_DIRECTORY_ENTRIES
    pub fn set_data_directory_by_index(&mut self, index: usize, rva: u32, size: u32) -> Result<()> {
        if index >= crate::data_dir::NUMBER_OF_DIRECTORY_ENTRIES {
            return Err(Error::invalid_data_directory(format!(
                "directory index {index} is past the {} entries that the loader reads",
                crate::data_dir::NUMBER_OF_DIRECTORY_ENTRIES
            )));
        }
        self.store_data_directory(index, rva, size);
        Ok(())
    }

    /// Store a data-directory entry. If necessary, grow the array and update
    /// `NumberOfRvaAndSizes`. The caller must validate `index` first.
    ///
    /// A `NumberOfRvaAndSizes` larger than the array stays as it is, so that a round trip keeps
    /// it.
    fn store_data_directory(&mut self, index: usize, rva: u32, size: u32) {
        let dirs = self.optional_header.data_directories_mut();
        if dirs.len() <= index {
            dirs.resize(index + 1, crate::data_dir::DataDirectory::default());
        }
        dirs[index].virtual_address = rva;
        dirs[index].size = size;

        let length = u32::try_from(dirs.len()).unwrap_or(u32::MAX);
        let count = match &mut self.optional_header {
            OptionalHeader::Pe32(header) => &mut header.number_of_rva_and_sizes,
            OptionalHeader::Pe32Plus(header) => &mut header.number_of_rva_and_sizes,
        };
        *count = (*count).max(length);
    }

    pub(super) fn ensure_data_directory_slot(
        &mut self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Result<()> {
        let index = dir_type.as_index();
        if self.optional_header.data_directories().len() <= index {
            self.set_data_directory_by_index(index, 0, 0)?;
        }
        Ok(())
    }

    /// Clear the data directory entry of the given type.
    ///
    /// If the data-directory array has no entry of this type, the function does nothing. It does
    /// not grow the array or change `NumberOfRvaAndSizes`.
    ///
    /// The bound import table can be in the header bytes after the section table. If you clear
    /// the `BoundImport` entry, the function also removes the table from these bytes. Then the
    /// build writes zeros in its place.
    pub fn clear_data_directory(&mut self, dir_type: crate::data_dir::DataDirectoryType) {
        let Some(entry) = self
            .optional_header
            .data_directories_mut()
            .get_mut(dir_type.as_index())
        else {
            return;
        };
        let old = core::mem::take(entry);
        if dir_type == crate::data_dir::DataDirectoryType::BoundImport {
            self.header_tail
                .clear_rva_range(old.virtual_address, old.size);
        }
    }

    /// Append data to the section with the index `section_index` in [`Self::sections`], and
    /// return the RVA of the data.
    ///
    /// Returns `None` if [`Self::try_append_to_section`] returns an error.
    pub fn append_to_section(&mut self, section_index: usize, data: &[u8]) -> Option<u32> {
        self.try_append_to_section(section_index, data).ok()
    }

    /// Append data to the section with the index `section_index` in [`Self::sections`], with
    /// checked layout and address calculation.
    ///
    /// The data goes after `VirtualSize` and after the last nonzero byte of the section data,
    /// at the next multiple of 8 bytes. Thus it does not overwrite the uninitialized data (BSS)
    /// of the section, and it can reuse zero raw padding. The method fills the space before
    /// the data with zeros. The append never moves a section.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions. Then the image does not change.
    ///
    /// - `section_index` is not the index of a section.
    /// - The layout calculation fails.
    /// - The appended data overflows the size or the RVA range of the section.
    /// - The data does not fit before the next section, or it needs more than 16 MiB of zero
    ///   fill.
    pub fn try_append_to_section(&mut self, section_index: usize, data: &[u8]) -> Result<u32> {
        self.append_to_section_at(section_index, data)
    }
}

/// Return the number of bytes at the start of a section that an RVA read can address.
///
/// The loader fills a section with zeros after its raw data, up to the size that it maps (see
/// [`rva_extent`]). An RVA read uses the same zeros, but only after complete raw data:
///
/// - If the raw data goes past the end of the source file, the loader also maps zeros for the
///   bytes after that end. If `PointerToRawData` is 0, the loader maps only zeros. In both
///   cases the data is complete.
/// - Otherwise, if the data is shorter than `SizeOfRawData`, the parser could not read some raw
///   bytes (see [`MissingSectionData::Empty`](super::MissingSectionData::Empty)). These bytes
///   are not known to be zero, so the read stops at the end of the data.
/// - The data of a section from a loader-mapped image covers the mapped range. Missing bytes
///   there are also not known to be zero.
fn mapped_extent(section: &Section, section_alignment: u32) -> usize {
    let extent = usize::try_from(rva_extent(section, section_alignment)).unwrap_or(usize::MAX);
    let data_len = section.data.len();
    let incomplete =
        data_len < section.header.size_of_raw_data as usize && !section.raw_tail_is_zero;
    if section.mapped_raw_size.is_some() || incomplete {
        return data_len.min(extent);
    }
    extent
}

/// Return the number of bytes from the start of a section that its RVAs cover.
///
/// This is the size that the loader maps (see
/// [`SectionHeader::mapped_size`](crate::SectionHeader::mapped_size)). Raw data after that size
/// belongs to no RVA. Section data that grows past `SizeOfRawData` after an edit stays in the
/// section, until the next layout update sets the header fields.
fn rva_extent(section: &Section, section_alignment: u32) -> u64 {
    let mapped = section.header.mapped_size(section_alignment);
    let data_len = section.data.len() as u64;
    if data_len > u64::from(section.header.size_of_raw_data) {
        mapped.max(data_len)
    } else {
        mapped
    }
}

/// Return `true` if the RVA `rva` is in the RVA extent of `section` (see [`rva_extent`]).
fn section_contains_rva(section: &Section, rva: u32, section_alignment: u32) -> bool {
    rva.checked_sub(section.header.virtual_address)
        .is_some_and(|offset| u64::from(offset) < rva_extent(section, section_alignment))
}

/// The method that finds the section that contains an RVA.
enum SectionLookup {
    /// Search the section table in table order. This needs no setup, so a single read uses it.
    Table,
    /// The indices of the sections that are not empty, sorted by RVA. These sections do not
    /// overlap, so a binary search finds the one section that contains an RVA.
    Sorted(Vec<usize>),
}

impl SectionLookup {
    /// Sort the sections by RVA. If two sections overlap, use the table order.
    fn sorted(sections: &[Section], section_alignment: u32) -> Self {
        let start = |index: usize| u64::from(sections[index].header.virtual_address);
        let end = |index: usize| section_end(&sections[index], section_alignment);
        let mut order: Vec<usize> = (0..sections.len())
            .filter(|&index| end(index) > start(index))
            .collect();
        order.sort_by_key(|&index| start(index));
        if order.windows(2).all(|pair| end(pair[0]) <= start(pair[1])) {
            Self::Sorted(order)
        } else {
            Self::Table
        }
    }
}

/// A reader of RVA ranges, from [`PeImage::rva_reader`].
pub(super) struct RvaReader<'a> {
    image: &'a PeImage,
    lookup: SectionLookup,
    /// The value of [`PeImage::held_len`], which the reader calculates at most once.
    held: OnceCell<usize>,
}

impl<'a> RvaReader<'a> {
    fn new(image: &'a PeImage, lookup: SectionLookup) -> Self {
        Self {
            image,
            lookup,
            held: OnceCell::new(),
        }
    }

    /// Return true if [`Self::read`] refuses a read of `len` bytes because of the zero-fill
    /// budget: the read is larger than the held bytes plus the zero-fill budget.
    pub(super) fn exceeds_zero_fill(&self, len: u32) -> bool {
        let Ok(len) = usize::try_from(len) else {
            return true;
        };
        if len <= MIN_ZERO_FILL {
            return false;
        }
        let held = *self.held.get_or_init(|| self.image.held_len());
        len > held.saturating_add(held.max(MIN_ZERO_FILL))
    }

    /// Read `len` bytes at an RVA into a new buffer, as [`PeImage::read_rva`] does.
    pub(super) fn read(&self, rva: u32, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }

        // Each output byte is a copy of a held byte or a zero byte. The held bytes matter only
        // for a read that is larger than the minimum budget, and their count visits each section.
        let mut zero_budget = if len <= MIN_ZERO_FILL {
            MIN_ZERO_FILL
        } else {
            let held = *self.held.get_or_init(|| self.image.held_len());
            let budget = held.max(MIN_ZERO_FILL);
            if len > held.saturating_add(budget) {
                return None;
            }
            budget
        };
        let image = self.image;
        image.visit_rva_range(&self.lookup, rva, len, |_| Some(()))?;
        let mut header_bytes = None;
        let mut output = Vec::new();
        output.try_reserve_exact(len).ok()?;
        image.visit_rva_range(&self.lookup, rva, len, |part| {
            let (bytes, offset, count) = match part {
                // The header part comes first, so this builds the requested header bytes once.
                RvaPart::Headers { start, count } => {
                    if header_bytes.is_none() {
                        header_bytes = Some(image.header_bytes(start, start + count).ok()?);
                    }
                    (header_bytes.as_deref()?, 0, count)
                }
                RvaPart::Section {
                    section,
                    offset,
                    count,
                } => (section.data.as_slice(), offset, count),
            };
            let initialized = bytes.get(offset..).unwrap_or_default();
            let initialized = &initialized[..initialized.len().min(count)];
            zero_budget = zero_budget.checked_sub(count - initialized.len())?;
            output.extend_from_slice(initialized);
            output.resize(output.len() + count - initialized.len(), 0);
            Some(())
        })?;
        Some(output)
    }
}

/// One part of an RVA range: bytes in the headers or bytes in one section.
enum RvaPart<'a> {
    /// `count` bytes of the headers, from the file offset `start`.
    Headers { start: usize, count: usize },
    /// `count` bytes of `section`, from `offset` bytes after its start.
    Section {
        section: &'a Section,
        offset: usize,
        count: usize,
    },
}

/// Visit the part of `section` that starts at `rva` and has at most `remaining` bytes.
///
/// Return the number of bytes in the part, or `None` if the section has no bytes at `rva`.
fn visit_section_part<'a>(
    section: &'a Section,
    section_alignment: u32,
    rva: u32,
    remaining: usize,
    visit: &mut impl FnMut(RvaPart<'a>) -> Option<()>,
) -> Option<usize> {
    let offset = rva.checked_sub(section.header.virtual_address)? as usize;
    let count = mapped_extent(section, section_alignment)
        .checked_sub(offset)?
        .min(remaining);
    if count == 0 {
        return None;
    }
    visit(RvaPart::Section {
        section,
        offset,
        count,
    })?;
    Some(count)
}

/// Return the RVA after the end of a section: the end of its RVA extent (see [`rva_extent`]).
pub(super) fn section_end(section: &Section, section_alignment: u32) -> u64 {
    u64::from(section.header.virtual_address) + rva_extent(section, section_alignment)
}
