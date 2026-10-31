use super::{MAX_NUMBER_OF_SECTIONS, PeImage};
use crate::dos::DosHeader;
use crate::layout::{self, LayoutConfig};
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::section::{Section, SectionHeader};
use crate::{Error, Result};

impl PeImage {
    /// Update the layout, and return the RVA where an append to a section puts its data.
    ///
    /// The RVA is after the section data and after `VirtualSize`, so that the data does not
    /// overwrite the uninitialized data (BSS) of the section. It is aligned to
    /// [`APPEND_ALIGNMENT`], so that each structure in the data is aligned.
    pub(super) fn prepare_section_append(&mut self, section_index: usize) -> Result<u32> {
        self.try_update_layout()?;
        let section = self
            .sections
            .get(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?;
        let offset = u32::try_from(section.data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?
            .max(section.header.virtual_size);
        layout::checked_align_up(offset, APPEND_ALIGNMENT)
            .and_then(|offset| section.header.virtual_address.checked_add(offset))
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))
    }

    /// Append `data` at the RVA that [`Self::prepare_section_append`] returned.
    ///
    /// The method fills the space before `expected_rva` with zeros.
    ///
    /// # Errors
    ///
    /// Returns an error if the append moves a section, for example if the data does not fit
    /// before the next section. Then the image does not change.
    pub(super) fn commit_section_append(
        &mut self,
        section_index: usize,
        expected_rva: u32,
        data: &[u8],
    ) -> Result<()> {
        if self.try_commit_section_append(section_index, expected_rva, data)? {
            Ok(())
        } else {
            Err(self.moved_section_error(section_index))
        }
    }

    /// Append `data` at `expected_rva`, as [`Self::commit_section_append`] does.
    ///
    /// Return `Ok(false)` and do not change the image if the append moves a section.
    fn try_commit_section_append(
        &mut self,
        section_index: usize,
        expected_rva: u32,
        data: &[u8],
    ) -> Result<bool> {
        let mut candidate = self.clone();
        let section = candidate
            .sections
            .get_mut(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?;
        let start = expected_rva
            .checked_sub(section.header.virtual_address)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| *offset >= section.data.len())
            .ok_or_else(|| {
                Error::invalid_section("the append RVA is not after the section data")
            })?;
        section
            .data
            .try_reserve(start - section.data.len())
            .map_err(|_| Error::invalid_section("section data is too large to allocate"))?;
        section.data.resize(start, 0);
        let offset = section.try_append_data(data)?;
        candidate.try_update_layout()?;
        if !candidate.has_section_rvas_of(self) {
            return Ok(false);
        }
        let actual_rva = candidate.sections[section_index]
            .header
            .virtual_address
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))?;
        if actual_rva != expected_rva {
            return Err(Error::invalid_section(
                "target section moved while appending address-bearing data",
            ));
        }
        *self = candidate;
        Ok(true)
    }

    /// Return the error for an append to a section that moves another section.
    fn moved_section_error(&self, section_index: usize) -> Error {
        let name = self
            .sections
            .get(section_index)
            .map(Section::name)
            .unwrap_or_default();
        Error::invalid_section(format!(
            "the data does not fit in section '{name}' before the next section; \
             an append must not move a section"
        ))
    }

    /// Build data for an RVA in a section, and append it there.
    ///
    /// `build` gets the RVA of the data and returns the bytes and a value for the caller. If the
    /// data does not fit before the next section, the result depends on `explicit_target`:
    ///
    /// - If the caller named the section (`true`), the method returns an error.
    /// - Otherwise, the method appends the data to the last section. If the last section is not
    ///   readable or has uninitialized data, the method adds a new section for the data. Then
    ///   it calls `build` again with the new RVA.
    ///
    /// The method never moves a section. Returns the RVA of the data and the value of `build`.
    pub(super) fn append_section_data<T>(
        &mut self,
        section_index: usize,
        explicit_target: bool,
        mut build: impl FnMut(u32) -> Result<(Vec<u8>, T)>,
    ) -> Result<(u32, T)> {
        let rva = self.prepare_section_append(section_index)?;
        let (data, value) = build(rva)?;
        if self.try_commit_section_append(section_index, rva, &data)? {
            return Ok((rva, value));
        }
        if explicit_target {
            return Err(self.moved_section_error(section_index));
        }

        let fallback = self.append_fallback_section()?;
        let rva = self.prepare_section_append(fallback)?;
        let (data, value) = build(rva)?;
        self.commit_section_append(fallback, rva, &data)?;
        Ok((rva, value))
    }

    /// Return the index of the section that gets appended data that does not fit in its target
    /// section.
    ///
    /// This is the last section in RVA order, if it is readable and has no uninitialized data
    /// after its data. Otherwise the method adds a new section after it.
    fn append_fallback_section(&mut self) -> Result<usize> {
        use crate::section::characteristics;

        let last = self
            .sections
            .iter()
            .enumerate()
            .max_by_key(|(_, section)| section.header.virtual_address);
        if let Some((index, section)) = last
            && section.header.is_readable()
            && section.header.virtual_size as usize <= section.data.len()
        {
            return Ok(index);
        }
        self.try_add_section_with_data(
            APPEND_SECTION_NAME,
            Vec::new(),
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )?;
        Ok(self.sections.len() - 1)
    }

    /// Update the imports.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the target section. If `target_section` is `None`, the function
    /// uses one of these sections, in this order:
    /// 1. The section that contains the existing imports.
    /// 2. `.rdata`.
    /// 3. The last section.
    ///
    /// The function keeps the import address table (IAT) of each DLL whose function list is
    /// unchanged: the descriptor keeps its `FirstThunk`. Only the import lookup table, the
    /// names and the descriptors move. Code that calls through the existing IAT slots thus
    /// continues to work. A DLL is unchanged if [`Self::imports`] has a DLL with the same
    /// `descriptor.first_thunk` and the same `imports`. Start from [`Self::imports`] to keep
    /// the IATs. See [`crate::ImportTableBuilder`].
    ///
    /// A new DLL, or a DLL whose function list changed, gets a new IAT in the written data.
    /// Code that uses the old IAT of a changed DLL must be patched by the caller.
    ///
    /// The IAT data directory gets the range from the first IAT to the end of the last IAT. If
    /// this range is not in one section, the function clears the IAT data directory. A range
    /// over more than one section can include pages with other protections.
    ///
    /// Returns the RVA of the import directory. Returns 0 if `imports` is empty; then the
    /// function clears the import and IAT data directories.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no IAT slot and cannot be extended.
    /// - The import table cannot be serialized, or its descriptor table does not fit in `u32`.
    /// - The target section does not exist.
    /// - The layout update fails, or the data does not fit in the target section that you
    ///   named. See [Directory updates](crate::PeImage#directory-updates).
    pub fn update_imports(
        &mut self,
        imports: &crate::import::ImportTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::import::ImportTableBuilder;

        if imports.is_empty() {
            self.clear_data_directory(DataDirectoryType::Import);
            self.clear_data_directory(DataDirectoryType::Iat);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::Iat)?;

        // Keep the IATs of the unchanged DLLs. If the current table is malformed, no DLL is
        // unchanged, and each DLL gets a new IAT.
        let current = self.imports().unwrap_or_default();
        let is_64bit = self.is_64bit();
        let builder_at =
            |base_rva| ImportTableBuilder::new(is_64bit, base_rva).keep_unchanged_iats(&current);

        // Try to replace the data in place. Do not write in place if a kept IAT is in the way.
        let existing_dir = self.data_directory(DataDirectoryType::Import).copied();
        if let Some(dir) = &existing_dir
            && dir.is_present()
            && let Ok((data, iat_rva, iat_size)) =
                builder_at(dir.virtual_address).try_build(imports)
            && data.len() <= dir.size as usize
            && self.write_at_rva(dir.virtual_address, &data).is_some()
        {
            let import_size = import_descriptor_table_size(imports.dlls.len())?;
            self.set_data_directory(DataDirectoryType::Import, dir.virtual_address, import_size);
            set_iat_directory(self, iat_rva, iat_size);
            return Ok(dir.virtual_address);
        }

        // Find the target section for the append, in this order:
        // 1. The section that the caller specified.
        // 2. The section that contains the existing imports, if there are imports.
        // 3. `.rdata`.
        // 4. The last section.
        let section_name: String = target_section
            .map(str::to_string)
            .or_else(|| {
                // Find the section that contains the existing import directory.
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rdata".to_string());

        // Find the section index. An index prevents borrow problems.
        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let Some(section_idx) = section_idx else {
            return Err(crate::Error::invalid_section(section_name));
        };

        // Build the import data at the append RVA, and append it to the section.
        let (append_rva, (iat_rva, iat_size)) =
            self.append_section_data(section_idx, target_section.is_some(), |rva| {
                let (data, iat_rva, iat_size) = builder_at(rva).try_build(imports)?;
                Ok((data, (iat_rva, iat_size)))
            })?;

        // Update the data directories.
        let import_size = import_descriptor_table_size(imports.dlls.len())?;
        self.set_data_directory(DataDirectoryType::Import, append_rva, import_size);
        set_iat_directory(self, iat_rva, iat_size);

        Ok(append_rva)
    }

    /// Update the exports.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the target section. If `target_section` is `None`, the function
    /// uses one of these sections, in this order:
    /// 1. The section that contains the existing exports.
    /// 2. `.rdata`.
    /// 3. The last section.
    ///
    /// Returns the RVA of the export directory. Returns 0 if `exports` has no functions and no
    /// DLL name; then the function clears the export data directory.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no export slot and cannot be extended.
    /// - The export table cannot be serialized, for example because two exports have the same
    ///   ordinal or the same name, a name is empty, or a named export has RVA 0 (see
    ///   [`crate::export::ExportTableBuilder::try_calculate_size`]). The function does not
    ///   change the image in this condition.
    /// - The target section does not exist.
    /// - The layout update fails, or the data does not fit in the target section that you
    ///   named. See [Directory updates](crate::PeImage#directory-updates).
    pub fn update_exports(
        &mut self,
        exports: &crate::export::ExportTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::export::ExportTableBuilder;

        if exports.is_empty() && exports.dll_name.is_empty() {
            self.clear_data_directory(DataDirectoryType::Export);
            return Ok(0);
        }
        // Calculate the required size. This also validates the table before the image changes.
        let required_size = ExportTableBuilder::try_calculate_size(exports)?;
        self.ensure_data_directory_slot(DataDirectoryType::Export)?;

        // Try to replace the data in place.
        let existing_dir = self.data_directory(DataDirectoryType::Export).copied();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // The data fits in place.
            let builder = ExportTableBuilder::new(dir.virtual_address);
            let (data, export_size) = builder.try_build(exports)?;

            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                self.set_data_directory(
                    DataDirectoryType::Export,
                    dir.virtual_address,
                    export_size,
                );
                return Ok(dir.virtual_address);
            }
        }

        // Find the target section for the append, in this order:
        // 1. The section that the caller specified.
        // 2. The section that contains the existing exports, if there are exports.
        // 3. `.rdata`.
        // 4. The last section.
        let section_name: String = target_section
            .map(str::to_string)
            .or_else(|| {
                // Find the section that contains the existing export directory.
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rdata".to_string());

        // Find the section index. An index prevents borrow problems.
        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let Some(section_idx) = section_idx else {
            return Err(crate::Error::invalid_section(section_name));
        };

        // Build the export data at the RVA of the append, and append it.
        let (append_rva, export_size) =
            self.append_section_data(section_idx, target_section.is_some(), |rva| {
                ExportTableBuilder::new(rva).try_build(exports)
            })?;

        // Update the data directory.
        self.set_data_directory(DataDirectoryType::Export, append_rva, export_size);

        Ok(append_rva)
    }

    /// Recalculate the layout, and panics if the state cannot be represented.
    ///
    /// A manually constructed state can cause the panic. For fallible workflows, use
    /// [`Self::try_update_layout`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_update_layout`] returns an error.
    pub fn update_layout(&mut self) {
        self.try_update_layout().expect(
            "PE layout failed: use PeImage::try_update_layout() to handle invalid structures",
        );
    }

    /// Recalculate the section RVAs, the section file offsets and all derived header fields.
    ///
    /// The update is atomic. If an address, a size or an aggregate overflows, the function does
    /// not change the image.
    ///
    /// The update changes the header structures in these conditions:
    ///
    /// - `SizeOfOptionalHeader` grows to the size of the optional header, so that the section
    ///   table follows the optional header.
    /// - If the NT headers overlap the DOS header, and a new layout field changes the bytes of
    ///   `e_lfanew`, the NT headers move to offset 64 (`e_lfanew` = 0x40).
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The `SectionAlignment` or the `FileAlignment` of the optional header is invalid.
    /// - The image has more than [`MAX_NUMBER_OF_SECTIONS`] sections.
    /// - `e_lfanew` is smaller than 2, so that the PE signature overlaps `e_magic`.
    /// - A header size, a section address, a section size or an aggregate size overflows its
    ///   field.
    pub fn try_update_layout(&mut self) -> Result<()> {
        if usize::try_from(self.dos_header.e_lfanew)
            .is_ok_and(|pe_offset| pe_offset < DosHeader::SIZE)
        {
            // NT headers that overlap the DOS header are rare, so a copy costs little here.
            let mut updated = self.clone();
            updated.update_layout_fields()?;
            if !updated.nt_headers_keep_e_lfanew() {
                updated.clone_from(self);
                updated.dos_header.e_lfanew = DOS_HEADER_END;
                updated.update_layout_fields()?;
            }
            *self = updated;
            return Ok(());
        }
        self.update_layout_fields()
    }

    /// Recalculate the layout for the current `e_lfanew`. This is the atomic part of
    /// [`Self::try_update_layout`].
    fn update_layout_fields(&mut self) -> Result<()> {
        let config = LayoutConfig::from_optional_header(&self.optional_header);
        validate_layout_config(&config)?;
        if self.sections.len() > MAX_NUMBER_OF_SECTIONS {
            return Err(Error::invalid_section(format!(
                "section count {} exceeds the PE image limit of {MAX_NUMBER_OF_SECTIONS}",
                self.sections.len()
            )));
        }

        // Calculate the size of the headers.
        let pe_offset = usize::try_from(self.dos_header.e_lfanew)
            .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
        if pe_offset < DosHeader::MIN_PE_OFFSET {
            return Err(Error::invalid_section(format!(
                "e_lfanew {pe_offset:#x} is smaller than {:#x}: the PE signature overlaps e_magic",
                DosHeader::MIN_PE_OFFSET
            )));
        }
        let actual_optional_size = self.optional_header.size();
        let declared_optional_size = usize::from(self.coff_header.size_of_optional_header);
        let serialized_optional_size = actual_optional_size.max(declared_optional_size);
        let serialized_optional_size_u16 = u16::try_from(serialized_optional_size)
            .map_err(|_| Error::invalid_section("optional header exceeds u16"))?;
        let table_end =
            layout::headers_size_at(pe_offset, self.sections.len(), serialized_optional_size)
                .ok_or_else(|| Error::invalid_section("header table exceeds u32"))?;
        // Keep the header tail at its offset: data directories refer to it by RVA. A section
        // table that grows into the tail replaces the tail.
        let drops_tail =
            !self.header_tail.bytes.is_empty() && self.header_tail_after(table_end).is_none();
        let headers_size = self
            .header_data_end(table_end)
            .and_then(|size| u32::try_from(size).ok())
            .ok_or_else(|| Error::invalid_section("header table exceeds u32"))?;
        let size_of_headers = layout::checked_align_up(headers_size, config.file_alignment)
            .ok_or_else(|| Error::invalid_section("SizeOfHeaders exceeds u32"))?;

        // Work on a clone, so that an overflow cannot leave sections half updated. The raw
        // offsets of a loader-mapped source do not describe that source, so pack them.
        let mut sections = self.sections.clone();
        let keep_raw_offsets = self.source_layout == super::SourceLayout::File;
        layout::try_layout_sections(&mut sections, &config, headers_size, keep_raw_offsets)?;

        // Update `SizeOfImage`.
        let size_of_image =
            layout::try_calculate_size_of_image_with_headers(&sections, &config, size_of_headers)?;
        let aggregates = calculate_optional_layout_fields(&sections)?;
        let section_count = u16::try_from(sections.len())
            .map_err(|_| Error::invalid_section("section count exceeds u16"))?;
        let directory_count = u32::try_from(self.optional_header.data_directories().len())
            .map_err(|_| Error::invalid_data_directory("data-directory count exceeds u32"))?;

        self.sections = sections;
        if drops_tail {
            self.drop_header_tail();
        }
        self.set_size_of_headers(size_of_headers);
        self.set_size_of_image(size_of_image);
        self.apply_optional_layout_fields(aggregates, directory_count);

        // Update the COFF header.
        self.coff_header.number_of_sections = section_count;
        self.coff_header.size_of_optional_header = serialized_optional_size_u16;
        Ok(())
    }

    /// Return the RVA where the layout places the first section, for a section table of
    /// `section_count` entries.
    ///
    /// The result is `None` if the header size overflows. The calculation follows
    /// [`Self::update_layout_fields`].
    pub(super) fn first_section_rva(&self, section_count: usize) -> Option<u32> {
        let pe_offset = usize::try_from(self.dos_header.e_lfanew).ok()?;
        let optional_size = self
            .optional_header
            .size()
            .max(usize::from(self.coff_header.size_of_optional_header));
        let table_end = layout::headers_size_at(pe_offset, section_count, optional_size)?;
        let headers_size = u32::try_from(self.header_data_end(table_end)?).ok()?;
        layout::checked_align_up(headers_size, self.optional_header.section_alignment())
    }

    /// Remove the header tail after the section table grows into it.
    ///
    /// The section table replaces the start of the tail. If the `BoundImport` directory points
    /// into the tail, clear the directory. The loader then resolves the imports without the
    /// bound import table.
    fn drop_header_tail(&mut self) {
        use crate::data_dir::DataDirectoryType;

        let tail = core::mem::take(&mut self.header_tail);
        if self
            .data_directory(DataDirectoryType::BoundImport)
            .is_some_and(|directory| tail.contains_rva(directory.virtual_address))
        {
            self.clear_data_directory(DataDirectoryType::BoundImport);
        }
    }

    fn apply_optional_layout_fields(&mut self, fields: OptionalLayoutFields, count: u32) {
        match &mut self.optional_header {
            OptionalHeader::Pe32(header) => {
                header.size_of_code = fields.size_of_code;
                header.size_of_initialized_data = fields.size_of_initialized_data;
                header.size_of_uninitialized_data = fields.size_of_uninitialized_data;
                header.base_of_code = fields.base_of_code;
                header.base_of_data = fields.base_of_data;
                header.number_of_rva_and_sizes = count;
            }
            OptionalHeader::Pe32Plus(header) => {
                header.size_of_code = fields.size_of_code;
                header.size_of_initialized_data = fields.size_of_initialized_data;
                header.size_of_uninitialized_data = fields.size_of_uninitialized_data;
                header.base_of_code = fields.base_of_code;
                header.number_of_rva_and_sizes = count;
            }
        }
    }

    fn set_size_of_headers(&mut self, size: u32) {
        match &mut self.optional_header {
            OptionalHeader::Pe32(h) => h.size_of_headers = size,
            OptionalHeader::Pe32Plus(h) => h.size_of_headers = size,
        }
    }

    fn set_size_of_image(&mut self, size: u32) {
        match &mut self.optional_header {
            OptionalHeader::Pe32(h) => h.size_of_image = size,
            OptionalHeader::Pe32Plus(h) => h.size_of_image = size,
        }
    }

    // ========== Section Management ==========

    /// Remove the section with the given name, and return it.
    ///
    /// The method removes only a section that leaves no gap in the RVA range: the last section
    /// in RVA order, a section with no size, or a section that has no RVA yet. The loader
    /// rejects an image with a gap between two sections.
    ///
    /// **Warning**: Removing a section can break the PE image if data directories or code refer
    /// to data in that section. Use this function with caution.
    ///
    /// # Errors
    ///
    /// Returns an error if no section has the name `name`, or if the removal leaves a gap in the
    /// RVA range. Then the image does not change.
    pub fn remove_section(&mut self, name: &str) -> Result<Section> {
        let index = self
            .section_index(name)
            .ok_or_else(|| Error::invalid_section(format!("no section is named '{name}'")))?;
        self.remove_section_at(index)
    }

    /// Remove the section at `index` in the section table, and return it.
    ///
    /// See [`Self::remove_section`].
    ///
    /// # Errors
    ///
    /// Returns an error if `index` is out of bounds, or if the removal leaves a gap in the RVA
    /// range. Then the image does not change.
    pub fn remove_section_at(&mut self, index: usize) -> Result<Section> {
        let section = self.sections.get(index).ok_or_else(|| {
            Error::invalid_section(format!("section index {index} is out of range"))
        })?;
        let start = section.header.virtual_address;
        let alignment = self.optional_header.section_alignment();
        if start != 0
            && section.header.mapped_size(alignment) != 0
            && self
                .sections
                .iter()
                .any(|other| other.header.virtual_address > start)
        {
            return Err(Error::invalid_section(format!(
                "removing section '{}' leaves a gap in the RVA range; the loader rejects a gap",
                section.name()
            )));
        }
        let section = self.sections.remove(index);
        self.coff_header.number_of_sections =
            u16::try_from(self.sections.len()).unwrap_or(u16::MAX);
        Ok(section)
    }

    /// Return the index of the first section with the given name.
    fn section_index(&self, name: &str) -> Option<usize> {
        self.sections
            .iter()
            .position(|section| section.name() == name)
    }

    /// Resize the data of a section.
    ///
    /// See [`Self::try_resize_section`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_resize_section`] returns an error.
    pub fn resize_section(&mut self, name: &str, new_size: usize) {
        self.try_resize_section(name, new_size)
            .expect("invalid section resize: use try_resize_section() for fallible updates");
    }

    /// Resize the data of a section.
    ///
    /// If the new size is larger, the method pads the data with zeros. If the new size is
    /// smaller, the method truncates the data. The method never moves a section, and never
    /// leaves a gap in the RVA range:
    ///
    /// - The last section in RVA order, and a section that has no RVA yet, get `new_size` as
    ///   `VirtualSize` (at least 1).
    /// - Each other section keeps the RVA range that the loader maps. Its `VirtualSize` becomes
    ///   `new_size` only if that is larger, and the bytes after the data read as zeros.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions. Then the image does not change.
    ///
    /// - No section has the name `name`.
    /// - `new_size` exceeds `u32`, or the memory for the data cannot be allocated.
    /// - The new size does not fit before the next section.
    pub fn try_resize_section(&mut self, name: &str, new_size: usize) -> Result<()> {
        let new_size_u32 = u32::try_from(new_size)
            .map_err(|_| Error::invalid_section("section size exceeds u32"))?;
        let index = self
            .section_index(name)
            .ok_or_else(|| Error::invalid_section(format!("no section is named '{name}'")))?;
        let alignment = self.optional_header.section_alignment();
        let section = &self.sections[index];
        let start = section.header.virtual_address;
        let next = (start != 0)
            .then(|| {
                self.sections
                    .iter()
                    .map(|other| other.header.virtual_address)
                    .filter(|address| *address > start)
                    .min()
            })
            .flatten();
        let virtual_size = match next {
            None => new_size_u32.max(1),
            Some(next) => {
                let header = &section.header;
                let current = if header.virtual_size == 0 {
                    header.size_of_raw_data
                } else {
                    header.virtual_size
                };
                let virtual_size = current.max(new_size_u32);
                let resized = SectionHeader {
                    virtual_size,
                    ..header.clone()
                };
                if u64::from(start) + resized.mapped_size(alignment) > u64::from(next) {
                    return Err(Error::invalid_section(format!(
                        "section '{name}' with {new_size:#x} bytes does not fit before the next \
                         section at {next:#x}; a resize must not move a section"
                    )));
                }
                virtual_size
            }
        };

        let section = &mut self.sections[index];
        if let Some(additional) = new_size.checked_sub(section.data.len()) {
            section
                .data
                .try_reserve(additional)
                .map_err(|_| Error::invalid_section("section data is too large to allocate"))?;
        }
        section.data.resize(new_size, 0);
        section.mapped_raw_size = None;
        section.mapped_data_len = 0;
        section.header.virtual_size = virtual_size;
        Ok(())
    }

    /// Add a new section with the given name, data and characteristics.
    ///
    /// This convenience function creates a `Section` from these parts. The next
    /// `update_layout()` or `build()` calculates the section layout (RVA and file offset).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::PeImage;
    /// use portex::section::characteristics;
    ///
    /// # let file_bytes: &[u8] = &[];
    /// let mut pe = PeImage::parse(file_bytes)?;
    /// pe.add_section_with_data(".newsec", vec![0u8; 0x1000], characteristics::INITIALIZED_DATA | characteristics::READ);
    /// let rebuilt = pe.try_build()?;
    /// assert!(!rebuilt.is_empty());
    /// # Ok::<(), portex::Error>(())
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_add_section_with_data`] returns an error.
    pub fn add_section_with_data(&mut self, name: &str, data: Vec<u8>, characteristics: u32) {
        self.try_add_section_with_data(name, data, characteristics)
            .expect("invalid PE section: use try_add_section_with_data() for fallible updates");
    }

    /// Add a section from its parts, with a check of the section count and the data size.
    ///
    /// # Errors
    ///
    /// Returns an error if the image already has [`MAX_NUMBER_OF_SECTIONS`]
    /// sections or if `data` exceeds `u32`.
    pub fn try_add_section_with_data(
        &mut self,
        name: &str,
        data: Vec<u8>,
        characteristics: u32,
    ) -> Result<()> {
        let mut header = SectionHeader::default();
        header.set_name(name);
        header.characteristics = characteristics;
        self.try_add_section(Section::from_header_and_data(header, data))
    }
}

fn import_descriptor_table_size(dll_count: usize) -> Result<u32> {
    dll_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(crate::import::ImportDescriptor::SIZE))
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| Error::invalid_data_directory("import descriptor table exceeds u32"))
}

/// Set the IAT data directory to `iat_rva..iat_rva + iat_size` if one section holds this
/// range. Else clear the IAT data directory.
///
/// The loader makes the IAT range writable while it binds the imports. A range over more than
/// one section can include pages with other protections. Without an IAT data directory, the
/// loader uses the section of each IAT.
fn set_iat_directory(image: &mut PeImage, iat_rva: u32, iat_size: u32) {
    use crate::data_dir::DataDirectoryType;

    let one_section = iat_size
        .checked_sub(1)
        .and_then(|last| iat_rva.checked_add(last))
        .and_then(|last| {
            image
                .section_by_rva(iat_rva)
                .zip(image.section_by_rva(last))
        })
        .is_some_and(|(first, last)| core::ptr::eq(first, last));
    if one_section {
        image.set_data_directory(DataDirectoryType::Iat, iat_rva, iat_size);
    } else {
        image.clear_data_directory(DataDirectoryType::Iat);
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct OptionalLayoutFields {
    pub(super) size_of_code: u32,
    pub(super) size_of_initialized_data: u32,
    pub(super) size_of_uninitialized_data: u32,
    pub(super) base_of_code: u32,
    pub(super) base_of_data: u32,
}

fn validate_layout_config(config: &LayoutConfig) -> Result<()> {
    let file = config.file_alignment;
    let section = config.section_alignment;
    if section == 0 || !section.is_power_of_two() {
        return Err(Error::invalid_section(format!(
            "invalid SectionAlignment {section:#x}"
        )));
    }
    let low_alignment = section < 0x1000;
    if file == 0
        || !file.is_power_of_two()
        || file > 0x1_0000
        || file > section
        || (low_alignment && file != section)
        || (!low_alignment && file < 0x200)
    {
        return Err(Error::invalid_section(format!(
            "invalid FileAlignment {file:#x} for SectionAlignment {section:#x}"
        )));
    }
    Ok(())
}

pub(super) fn calculate_optional_layout_fields(
    sections: &[Section],
) -> Result<OptionalLayoutFields> {
    use crate::section::characteristics;

    let mut fields = OptionalLayoutFields {
        size_of_code: 0,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        base_of_code: 0,
        base_of_data: 0,
    };
    for section in sections {
        let flags = section.header.characteristics;
        if flags & characteristics::CODE != 0 {
            fields.size_of_code = fields
                .size_of_code
                .checked_add(section.header.size_of_raw_data)
                .ok_or_else(|| Error::invalid_section("SizeOfCode exceeds u32"))?;
            fields.base_of_code =
                minimum_nonzero(fields.base_of_code, section.header.virtual_address);
        }
        if flags & characteristics::INITIALIZED_DATA != 0 {
            fields.size_of_initialized_data = fields
                .size_of_initialized_data
                .checked_add(section.header.size_of_raw_data)
                .ok_or_else(|| Error::invalid_section("SizeOfInitializedData exceeds u32"))?;
            fields.base_of_data =
                minimum_nonzero(fields.base_of_data, section.header.virtual_address);
        }
        if flags & characteristics::UNINITIALIZED_DATA != 0 {
            fields.size_of_uninitialized_data = fields
                .size_of_uninitialized_data
                .checked_add(section.header.virtual_size)
                .ok_or_else(|| Error::invalid_section("SizeOfUninitializedData exceeds u32"))?;
            fields.base_of_data =
                minimum_nonzero(fields.base_of_data, section.header.virtual_address);
        }
    }
    Ok(fields)
}

fn minimum_nonzero(current: u32, candidate: u32) -> u32 {
    if current == 0 {
        candidate
    } else if candidate == 0 {
        current
    } else {
        current.min(candidate)
    }
}

/// The value of `e_lfanew` for NT headers directly after the DOS header.
const DOS_HEADER_END: i32 = 0x40;

/// The alignment of the data that an edit appends to a section, in bytes.
///
/// The structures of the data directories need at most 8-byte alignment (for example the
/// PE32+ `IMAGE_TLS_DIRECTORY64` and `IMAGE_LOAD_CONFIG_DIRECTORY64`).
const APPEND_ALIGNMENT: u32 = 8;

/// The name of the section that an edit adds for data that fits in no existing section.
const APPEND_SECTION_NAME: &str = ".portex";
