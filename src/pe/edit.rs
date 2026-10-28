use super::{MAX_NUMBER_OF_SECTIONS, PeImage};
use crate::dos::DosHeader;
use crate::layout::{self, LayoutConfig};
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::section::{Section, SectionHeader};
use crate::{Error, Result};

impl PeImage {
    pub(super) fn prepare_section_append(&mut self, section_index: usize) -> Result<u32> {
        self.try_update_layout()?;
        let section = self
            .sections
            .get(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?;
        let offset = u32::try_from(section.data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?;
        section
            .header
            .virtual_address
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))
    }

    pub(super) fn commit_section_append(
        &mut self,
        section_index: usize,
        expected_rva: u32,
        data: &[u8],
    ) -> Result<()> {
        let mut candidate = self.clone();
        let section = candidate
            .sections
            .get_mut(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?;
        let offset = section.try_append_data(data)?;
        candidate.try_update_layout()?;
        let section = candidate
            .sections
            .get(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?;
        let actual_rva = section
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
        Ok(())
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
    /// Returns the RVA of the import directory. Returns 0 if `imports` is empty; then the
    /// function clears the import and IAT data directories.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no IAT slot and cannot be extended.
    /// - The import table cannot be serialized, or its descriptor table does not fit in `u32`.
    /// - The target section does not exist.
    /// - The append breaks the image layout.
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

        // Calculate the required size.
        let builder_temp = ImportTableBuilder::new(self.is_64bit(), 0);
        let required_size = builder_temp.try_calculate_size(imports)?;

        // Try to replace the data in place.
        let existing_dir = self.data_directory(DataDirectoryType::Import).copied();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // The data fits in place.
            let builder = ImportTableBuilder::new(self.is_64bit(), dir.virtual_address);
            let (data, iat_rva, iat_size) = builder.try_build(imports)?;

            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                let import_size = import_descriptor_table_size(imports.dlls.len())?;
                self.set_data_directory(
                    DataDirectoryType::Import,
                    dir.virtual_address,
                    import_size,
                );
                self.set_data_directory(DataDirectoryType::Iat, iat_rva, iat_size);
                return Ok(dir.virtual_address);
            }
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

        // Calculate the RVA at which to put the data.
        let append_rva = self.prepare_section_append(section_idx)?;

        // Build the import data at the append RVA.
        let builder = ImportTableBuilder::new(self.is_64bit(), append_rva);
        let (data, iat_rva, iat_size) = builder.try_build(imports)?;

        // Append the data to the section.
        self.commit_section_append(section_idx, append_rva, &data)?;

        // Update the data directories.
        let import_size = import_descriptor_table_size(imports.dlls.len())?;
        self.set_data_directory(DataDirectoryType::Import, append_rva, import_size);
        self.set_data_directory(DataDirectoryType::Iat, iat_rva, iat_size);

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
    /// - The export table cannot be serialized (see
    ///   [`crate::export::ExportTableBuilder::try_build`]).
    /// - The target section does not exist.
    /// - The append breaks the image layout.
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
        self.ensure_data_directory_slot(DataDirectoryType::Export)?;

        // Calculate the required size.
        let required_size = ExportTableBuilder::try_calculate_size(exports)?;

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

        // Calculate the RVA at which to put the data.
        let append_rva = self.prepare_section_append(section_idx)?;

        // Build the export data at the append RVA.
        let builder = ExportTableBuilder::new(append_rva);
        let (data, export_size) = builder.try_build(exports)?;

        // Append the data to the section.
        self.commit_section_append(section_idx, append_rva, &data)?;

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
    /// - `e_lfanew` is smaller than 4, the minimum of the loader.
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
                "e_lfanew {pe_offset:#x} is smaller than {:#x}, the minimum of the loader",
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

        // Work on a clone, so that an overflow cannot leave sections half updated.
        let mut sections = self.sections.clone();
        layout::try_layout_sections(&mut sections, &config, headers_size)?;

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

    /// Remove the section at `index`.
    ///
    /// Returns the removed section, or `None` if `index` is out of bounds.
    ///
    /// **Warning**: Removing a section can break the PE image if data directories or code refer
    /// to data in that section. Use this function with caution.
    pub fn remove_section_at(&mut self, index: usize) -> Option<Section> {
        if index >= self.sections.len() {
            return None;
        }
        let section = self.sections.remove(index);
        self.coff_header.number_of_sections =
            u16::try_from(self.sections.len()).unwrap_or(u16::MAX);
        Some(section)
    }

    /// Find a section by name.
    #[must_use]
    pub fn find_section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    /// Find a section by name and returns a mutable reference.
    pub fn find_section_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name() == name)
    }

    /// Resize the data of a section.
    ///
    /// If the new size is larger, the function pads the data with zeros. If the new size is
    /// smaller, the function truncates the data.
    ///
    /// Returns `true` if the function found and resized the section, `false` otherwise.
    pub fn resize_section(&mut self, name: &str, new_size: usize) -> bool {
        self.try_resize_section(name, new_size).unwrap_or(false)
    }

    /// Resize a section after a check that its virtual size fits in a PE section header.
    ///
    /// Returns `Ok(false)` if no section has that name.
    ///
    /// # Errors
    ///
    /// Returns an error if `new_size` exceeds `u32`.
    pub fn try_resize_section(&mut self, name: &str, new_size: usize) -> Result<bool> {
        let new_size_u32 = u32::try_from(new_size)
            .map_err(|_| Error::invalid_section("section size exceeds u32"))?;
        if let Some(section) = self.find_section_mut(name) {
            section.data.resize(new_size, 0);
            section.mapped_raw_size = None;
            section.mapped_data_len = 0;
            section.header.virtual_size = new_size_u32;
            Ok(true)
        } else {
            Ok(false)
        }
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
