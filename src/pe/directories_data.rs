use super::PeImage;
use crate::prelude::*;
use crate::{Error, Result};

impl PeImage {
    /// Parse the bound import directory.
    ///
    /// Bound imports are a legacy optimization that makes DLL loading faster.
    /// Returns `Ok(None)` if the bound import data directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read at its RVA, or if its
    /// `IMAGE_BOUND_IMPORT_DESCRIPTOR` entries are malformed.
    pub fn bound_imports(&self) -> Result<Option<crate::bound_import::BoundImportDirectory>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::BoundImport)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let data = self
                    .read_rva(d.virtual_address, d.size as usize)
                    .ok_or_else(|| crate::Error::invalid_rva(d.virtual_address))?;
                Ok(Some(crate::bound_import::BoundImportDirectory::parse(
                    &data,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Update the bound imports.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the target section. If the old table is in the header bytes after
    /// the section table, the function also removes it from these bytes.
    ///
    /// Bound imports are a legacy optimization: the linker resolves the import addresses at link
    /// time. Returns the RVA of the written bound import data. Returns 0 if `directory` has no
    /// descriptors; then the function clears the data directory.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no bound import slot and cannot be extended.
    /// - The descriptors cannot be serialized.
    /// - The target section does not exist.
    /// - The append breaks the image layout.
    pub fn update_bound_imports(
        &mut self,
        directory: &crate::bound_import::BoundImportDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if directory.descriptors.is_empty() {
            self.clear_data_directory(DataDirectoryType::BoundImport);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::BoundImport)?;

        let (data, encoded_size) = crate::bound_import::BoundImportBuilder::try_build(directory)?;
        let required_size = data.len();

        // Try to replace the data in place.
        let existing_dir = self.data_directory(DataDirectoryType::BoundImport).copied();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
            && self.write_at_rva(dir.virtual_address, &data).is_some()
        {
            self.set_data_directory(
                DataDirectoryType::BoundImport,
                dir.virtual_address,
                encoded_size,
            );
            return Ok(dir.virtual_address);
        }

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
            .or_else(|| {
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

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let Some(section_idx) = section_idx else {
            return Err(crate::Error::invalid_section(section_name));
        };

        let append_rva = self.prepare_section_append(section_idx)?;

        self.commit_section_append(section_idx, append_rva, &data)?;
        // The old table can be in the header bytes after the section table. Remove it there.
        if let Some(dir) = existing_dir {
            self.header_tail
                .clear_rva_range(dir.virtual_address, dir.size);
        }
        self.set_data_directory(DataDirectoryType::BoundImport, append_rva, encoded_size);

        Ok(append_rva)
    }

    /// Parse the delay-load import directory.
    ///
    /// The loader loads a delay-loaded DLL on first use, not at startup.
    ///
    /// # Errors
    ///
    /// Returns an error if the delay-load descriptors, their name tables or
    /// their strings cannot be read from the image, or if they are malformed.
    pub fn delay_imports(&self) -> Result<crate::delay_import::DelayImportDirectory> {
        self.delay_imports_at_image_base(self.runtime_image_base())
    }

    /// Parse the delay-load imports with an explicit image base.
    ///
    /// The function uses `runtime_image_base` for legacy descriptors that hold VAs. Modern
    /// descriptors hold RVAs, and the image base has no effect on them.
    ///
    /// # Errors
    ///
    /// Returns an error if the delay-load descriptors, their name tables or
    /// their strings cannot be read from the image, or if they are malformed.
    pub fn delay_imports_at_image_base(
        &self,
        runtime_image_base: u64,
    ) -> Result<crate::delay_import::DelayImportDirectory> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::DelayImport)
            .filter(|d| d.is_present());
        let is_64bit = matches!(
            self.optional_header,
            crate::optional::OptionalHeader::Pe32Plus(_)
        );
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                crate::delay_import::DelayImportDirectory::parse_sized_with_image_base(
                    d.virtual_address,
                    d.size,
                    runtime_image_base,
                    is_64bit,
                    read_fn,
                )
            }
            None => Ok(crate::delay_import::DelayImportDirectory::default()),
        }
    }

    /// Update the delay-load imports.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the target section.
    ///
    /// With delay-load imports, the loader loads a DLL on first use and not at startup.
    /// Returns the RVA of the written delay import data. Returns 0 if `directory` has no DLLs;
    /// then the function clears the data directory.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no delay import slot and cannot be extended.
    /// - The target section does not exist.
    /// - The descriptors cannot be serialized.
    /// - The append breaks the image layout.
    pub fn update_delay_imports(
        &mut self,
        directory: &crate::delay_import::DelayImportDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if directory.dlls.is_empty() {
            self.clear_data_directory(DataDirectoryType::DelayImport);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::DelayImport)?;

        // Find out if the image is 64-bit.
        let is_64bit = matches!(
            self.optional_header,
            crate::optional::OptionalHeader::Pe32Plus(_)
        );

        // Find the target section first, to get the base RVA.
        let existing_dir = self.data_directory(DataDirectoryType::DelayImport).copied();
        let section_name: String = target_section
            .map(str::to_string)
            .or_else(|| {
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
                } else if self.section_by_name(".didat").is_some() {
                    Some(".didat".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rdata".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let Some(section_idx) = section_idx else {
            return Err(crate::Error::invalid_section(section_name));
        };

        // Calculate the RVA at which to put the data.
        let base_rva = self.prepare_section_append(section_idx)?;

        let builder = crate::delay_import::DelayImportBuilder::new(is_64bit, base_rva);
        let (data, encoded_size) = builder.try_build(&directory.dlls)?;
        let required_size = data.len();

        // Try to replace the data in place.
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // For an in-place write, rebuild the data with the existing RVA.
            let existing_builder =
                crate::delay_import::DelayImportBuilder::new(is_64bit, dir.virtual_address);
            let (existing_data, existing_size) = existing_builder.try_build(&directory.dlls)?;
            if self
                .write_at_rva(dir.virtual_address, &existing_data)
                .is_some()
            {
                self.set_data_directory(
                    DataDirectoryType::DelayImport,
                    dir.virtual_address,
                    existing_size,
                );
                return Ok(dir.virtual_address);
            }
        }

        // Append the data to the section.
        self.commit_section_append(section_idx, base_rva, &data)?;
        self.set_data_directory(DataDirectoryType::DelayImport, base_rva, encoded_size);

        Ok(base_rva)
    }

    /// Parse the resource directory (metadata only).
    ///
    /// To also load the resource data, use `resources_with_data()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the resource directory tree cannot be read from the
    /// image, or if it is malformed.
    pub fn resources(&self) -> Result<crate::resource::ResourceDirectory> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Resource)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                crate::resource::ResourceDirectory::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::resource::ResourceDirectory::default()),
        }
    }

    /// Parse the resource directory and the resource data.
    ///
    /// This function is slower than `resources()`. It loads the data of each resource into the
    /// `Resource::data` field.
    ///
    /// # Errors
    ///
    /// Returns an error if the resource directory tree or a resource data
    /// entry cannot be read from the image, or if it is malformed.
    pub fn resources_with_data(&self) -> Result<crate::resource::ResourceDirectory> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Resource)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                crate::resource::ResourceDirectory::parse_with_data(
                    d.virtual_address,
                    d.size,
                    read_fn,
                )
            }
            None => Ok(crate::resource::ResourceDirectory::default()),
        }
    }

    /// Update the base relocations.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the target section.
    ///
    /// Returns the RVA of the written base relocation blocks. Returns 0 if `relocs` has no
    /// blocks; then the function clears the data directory.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no base relocation slot and cannot be extended.
    /// - The blocks cannot be serialized, or their size does not fit in `u32`.
    /// - The target section does not exist.
    /// - The append breaks the image layout.
    pub fn update_relocations(
        &mut self,
        relocs: &crate::reloc::RelocationTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if relocs.blocks.is_empty() {
            self.clear_data_directory(DataDirectoryType::BaseReloc);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::BaseReloc)?;

        let data = relocs.try_build()?;
        let required_size = data.len();
        let encoded_size = u32::try_from(required_size)
            .map_err(|_| Error::invalid_data_directory("relocation table exceeds u32"))?;

        // Try to replace the data in place.
        let existing_dir = self.data_directory(DataDirectoryType::BaseReloc).copied();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
            && self.write_at_rva(dir.virtual_address, &data).is_some()
        {
            self.set_data_directory(
                DataDirectoryType::BaseReloc,
                dir.virtual_address,
                encoded_size,
            );
            return Ok(dir.virtual_address);
        }

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
            .or_else(|| {
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".reloc").is_some() {
                    Some(".reloc".to_string())
                } else if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".reloc".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let Some(section_idx) = section_idx else {
            return Err(crate::Error::invalid_section(section_name));
        };

        let append_rva = self.prepare_section_append(section_idx)?;

        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::BaseReloc, append_rva, encoded_size);

        Ok(append_rva)
    }

    /// Update the resources.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the target section.
    ///
    /// Parse `directory` with `resources_with_data()`, so that the resource data is available.
    /// Returns the RVA of the written resource directory. Returns 0 if `directory` has no
    /// resources; then the function clears the data directory.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no resource slot and cannot be extended.
    /// - The resource data is not loaded.
    /// - The tree cannot be serialized.
    /// - The target section does not exist.
    /// - The append breaks the image layout.
    pub fn update_resources(
        &mut self,
        directory: &crate::resource::ResourceDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if directory.resources.is_empty() {
            self.clear_data_directory(DataDirectoryType::Resource);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::Resource)?;

        let builder =
            crate::resource::ResourceBuilder::from_directory(directory).ok_or_else(|| {
                crate::Error::generic("Resource data not available - use resources_with_data()")
            })?;

        let required_size = builder.try_calculate_size()?;

        // Try to replace the data in place.
        let existing_dir = self.data_directory(DataDirectoryType::Resource).copied();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            let (data, size) = builder.try_build(dir.virtual_address)?;
            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                self.set_data_directory(DataDirectoryType::Resource, dir.virtual_address, size);
                return Ok(dir.virtual_address);
            }
        }

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
            .or_else(|| {
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".rsrc").is_some() {
                    Some(".rsrc".to_string())
                } else if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rsrc".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let Some(section_idx) = section_idx else {
            return Err(crate::Error::invalid_section(section_name));
        };

        let append_rva = self.prepare_section_append(section_idx)?;

        let (data, size) = builder.try_build(append_rva)?;
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Resource, append_rva, size);

        Ok(append_rva)
    }

    /// Update the resources from a builder.
    ///
    /// Use this function to make new resources. To change existing resources, use
    /// `update_resources()` with a parsed `ResourceDirectory`.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the target section. Returns the RVA of the written resource
    /// directory. Returns 0 if the builder is empty; then the function clears the data directory.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The data directory table has no resource slot and cannot be extended.
    /// - The tree cannot be serialized.
    /// - The target section does not exist.
    /// - The append breaks the image layout.
    pub fn update_resources_from_builder(
        &mut self,
        builder: &crate::resource::ResourceBuilder,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        let required_size = builder.try_calculate_size()?;
        if required_size == 0 {
            self.clear_data_directory(DataDirectoryType::Resource);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::Resource)?;

        // Try to replace the data in place.
        let existing_dir = self.data_directory(DataDirectoryType::Resource).copied();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            let (data, size) = builder.try_build(dir.virtual_address)?;
            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                self.set_data_directory(DataDirectoryType::Resource, dir.virtual_address, size);
                return Ok(dir.virtual_address);
            }
        }

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
            .or_else(|| {
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".rsrc").is_some() {
                    Some(".rsrc".to_string())
                } else if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rsrc".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let Some(section_idx) = section_idx else {
            return Err(crate::Error::invalid_section(section_name));
        };

        let append_rva = self.prepare_section_append(section_idx)?;

        let (data, size) = builder.try_build(append_rva)?;
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Resource, append_rva, size);

        Ok(append_rva)
    }
}
