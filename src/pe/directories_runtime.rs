use super::PeImage;
use crate::prelude::*;
use crate::{Error, Result};

impl PeImage {
    /// Parse the TLS directory (`IMAGE_TLS_DIRECTORY32` or `IMAGE_TLS_DIRECTORY64`).
    ///
    /// Returns `Ok(None)` if the TLS data directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS directory or its callback array cannot be
    /// read from the image, or if the directory is malformed.
    pub fn tls(&self) -> Result<Option<crate::tls::TlsInfo>> {
        self.tls_at_image_base(self.runtime_image_base())
    }

    /// Parse the TLS directory with the actual runtime base of the image.
    ///
    /// A loader relocates the VA fields in a mapped TLS directory. To parse an ASLR-relocated
    /// mapped image, give the current base address (a VA) of the module.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS directory or its callback array cannot be
    /// read from the image, or if the directory is malformed.
    pub fn tls_at_image_base(
        &self,
        runtime_image_base: u64,
    ) -> Result<Option<crate::tls::TlsInfo>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Tls)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                Ok(Some(crate::tls::TlsInfo::parse(
                    d.virtual_address,
                    d.size,
                    runtime_image_base,
                    self.is_64bit(),
                    read_fn,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Write a new TLS directory (`IMAGE_TLS_DIRECTORY32` or `IMAGE_TLS_DIRECTORY64`).
    ///
    /// This function creates the TLS directory, or replaces the current one. If
    /// `target_section` is `None`, the function uses ".rdata". If ".rdata" does not exist, it
    /// uses the last section. See [Directory updates](crate::PeImage#directory-updates) for
    /// the fallback if the data does not fit.
    ///
    /// The function keeps the original TLS index (`AddressOfIndex`); see
    /// [`TlsBuilder::try_build_from_info`](crate::tls::TlsBuilder::try_build_from_info).
    ///
    /// The new block holds VAs. If the image has a base relocation directory, the function
    /// adds a `HIGHLOW` (PE32) or `DIR64` (PE32+) relocation for each VA that is not zero.
    /// These are the directory VA fields and the callback array entries.
    ///
    /// # Arguments
    /// * `tls_info` - The TLS data to write.
    /// * `target_section` - The name of the section that gets the TLS data (optional).
    ///
    /// Returns the RVA of the new TLS directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the data-directory table has no TLS slot and cannot
    /// be extended, if the target section does not exist, if the TLS data
    /// cannot be serialized, or if the append fails (see
    /// [Directory updates](crate::PeImage#directory-updates)). Also returns an
    /// error if the base relocations cannot be parsed or written. If an error occurs, the
    /// image does not change.
    pub fn update_tls(
        &mut self,
        tls_info: &crate::tls::TlsInfo,
        target_section: Option<&str>,
    ) -> Result<u32> {
        self.transact(|image| image.update_tls_in(tls_info, target_section))
    }

    /// Do the work of [`Self::update_tls`] on the image. An error can leave the image half
    /// updated.
    fn update_tls_in(
        &mut self,
        tls_info: &crate::tls::TlsInfo,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::tls::TlsBuilder;
        self.ensure_data_directory_slot(DataDirectoryType::Tls)?;

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
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
            return Err(crate::Error::invalid_section(&section_name));
        };

        // Parse the relocations before the image changes.
        let relocations = self.relocations_for_new_vas()?;

        // Build the TLS data at the RVA of the append, and append it.
        let (image_base, is_64bit) = (self.image_base(), self.is_64bit());
        let (append_rva, (dir_size, va_offsets)) =
            self.append_section_data(section_idx, target_section.is_some(), |rva| {
                let builder = TlsBuilder::new(rva, image_base, is_64bit);
                let (data, dir_size) = builder.try_build_from_info(tls_info)?;
                let va_offsets = builder.va_offsets(&data);
                Ok((data, (dir_size, va_offsets)))
            })?;
        self.set_data_directory(DataDirectoryType::Tls, append_rva, dir_size);
        self.add_va_relocations(relocations, append_rva, &va_offsets)?;

        Ok(append_rva)
    }

    /// Parse the debug directory (an array of `IMAGE_DEBUG_DIRECTORY`).
    ///
    /// Returns `Ok(None)` if the debug data directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the debug directory entries cannot be read from the
    /// image or are malformed. Returns an
    /// [`ErrorKind::InvalidDataDirectory`](crate::ErrorKind) error if the debug directory is
    /// larger than the data that the image holds.
    pub fn debug_info(&self) -> Result<Option<crate::debug::DebugInfo>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Debug)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let reader = self.rva_reader();
                if reader.exceeds_zero_fill(d.size) {
                    return Err(crate::Error::invalid_data_directory(
                        "debug directory is larger than the data that the image holds",
                    ));
                }
                let read_fn = |rva: u32, len: usize| reader.read(rva, len);
                Ok(Some(crate::debug::DebugInfo::parse(
                    d.virtual_address,
                    d.size,
                    read_fn,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Write a debug directory with one CodeView entry that points to a PDB.
    ///
    /// This is the most common debug directory format. The function writes one CodeView RSDS
    /// entry. If `target_section` is `None`, the function uses ".rdata". If ".rdata" does not
    /// exist, it uses the last section.
    ///
    /// # Arguments
    /// * `codeview` - The `CodeView` data, with the PDB path and the GUID.
    /// * `target_section` - The name of the section that gets the debug data (optional).
    ///
    /// Returns the RVA of the new debug directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the data-directory table has no debug slot and
    /// cannot be extended, if the target section does not exist, if the
    /// `CodeView` record cannot be serialized, or if the append fails (see
    /// [Directory updates](crate::PeImage#directory-updates)).
    pub fn update_debug_codeview(
        &mut self,
        codeview: &crate::debug::CodeViewRsds,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::debug::DebugBuilder;
        self.ensure_data_directory_slot(DataDirectoryType::Debug)?;

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
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
            return Err(crate::Error::invalid_section(&section_name));
        };

        // Build the debug data at the RVA of the append, and append it.
        let (append_rva, dir_size) =
            self.append_section_data(section_idx, target_section.is_some(), |rva| {
                let (data, dir_size, _) = DebugBuilder::new(rva).try_build_codeview(codeview)?;
                Ok((data, dir_size))
            })?;
        self.set_data_directory(DataDirectoryType::Debug, append_rva, dir_size);

        Ok(append_rva)
    }

    /// Write the debug directory from a `DebugInfo` structure.
    ///
    /// Returns the RVA of the new debug directory. If `debug_info` has no entries, the
    /// function clears the directory and returns 0.
    ///
    /// # Errors
    ///
    /// Returns an error if the data-directory table has no debug slot and
    /// cannot be extended, if the target section does not exist, if the debug
    /// entries cannot be serialized, or if the append fails (see
    /// [Directory updates](crate::PeImage#directory-updates)).
    pub fn update_debug(
        &mut self,
        debug_info: &crate::debug::DebugInfo,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::debug::DebugBuilder;

        // There is no debug data to write.
        if debug_info.directories.is_empty() {
            self.clear_data_directory(DataDirectoryType::Debug);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::Debug)?;

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
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
            return Err(crate::Error::invalid_section(&section_name));
        };

        // Rebuild each entry together with its kept raw payload, at the RVA of the append.
        let (append_rva, dir_size) =
            self.append_section_data(section_idx, target_section.is_some(), |rva| {
                let (data, dir_size, _) = DebugBuilder::new(rva).try_build(debug_info)?;
                Ok((data, dir_size))
            })?;
        self.set_data_directory(DataDirectoryType::Debug, append_rva, dir_size);

        Ok(append_rva)
    }

    /// Parse the CLI header (`IMAGE_COR20_HEADER`) of a .NET assembly.
    ///
    /// Returns `Ok(None)` if the CLR data directory is absent.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::PeImage;
    ///
    /// # let file_bytes: &[u8] = &[];
    /// let pe = PeImage::parse(file_bytes)?;
    /// if let Some(cli) = pe.clr_header()? {
    ///     println!("Metadata at RVA {:#x}", cli.metadata_rva);
    /// }
    /// # Ok::<(), portex::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the CLR data directory is smaller than
    /// `IMAGE_COR20_HEADER`, cannot be read at its RVA, or is malformed.
    pub fn clr_header(&self) -> Result<Option<crate::clr::CliHeader>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::ClrRuntime)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                if (d.size as usize) < crate::clr::CliHeader::SIZE {
                    return Err(Error::invalid_data_directory(format!(
                        "CLR header is {} bytes, expected at least {}",
                        d.size,
                        crate::clr::CliHeader::SIZE
                    )));
                }
                let data = self
                    .read_rva(d.virtual_address, crate::clr::CliHeader::SIZE)
                    .ok_or_else(|| crate::Error::invalid_rva(d.virtual_address))?;
                Ok(Some(crate::clr::CliHeader::parse(&data)?))
            }
            None => Ok(None),
        }
    }

    /// Return the raw CLR metadata blob, for use by a metadata crate.
    ///
    /// Portex does not parse past this point. Crates such as `clrmeta` parse the metadata
    /// streams and tables.
    ///
    /// Returns `Ok(None)` if the CLR data directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI header cannot be parsed, or if the metadata blob cannot be
    /// read. Also returns an error if the metadata RVA or the metadata size is zero. A .NET
    /// assembly always has metadata.
    pub fn clr_metadata(&self) -> Result<Option<Vec<u8>>> {
        let Some(header) = self.clr_header()? else {
            return Ok(None);
        };
        if header.metadata_rva == 0 || header.metadata_size == 0 {
            return Err(Error::invalid_data_directory(
                "CLR header has a zero metadata RVA or a zero metadata size",
            ));
        }
        self.read_rva(header.metadata_rva, header.metadata_size as usize)
            .map(Some)
            .ok_or_else(|| Error::invalid_rva(header.metadata_rva))
    }

    /// Parse the Rich header from the DOS stub, if the header is present.
    #[must_use]
    pub fn rich_header(&self) -> Option<crate::rich::RichHeader> {
        let pe_offset = usize::try_from(self.dos_header.e_lfanew).ok()?;
        if pe_offset.checked_sub(crate::dos::DosHeader::SIZE)? != self.dos_stub.len() {
            return None;
        }

        let mut bytes = vec![0; crate::dos::DosHeader::SIZE];
        self.dos_header.write(&mut bytes).ok()?;
        bytes.extend_from_slice(&self.dos_stub);
        bytes.extend_from_slice(&crate::coff::PE_SIGNATURE.to_le_bytes());
        crate::rich::RichHeader::parse(&bytes)
    }

    /// Parse the exception directory with the ABI of the image's machine type.
    ///
    /// Returns `Ok(None)` if the exception data directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the exception directory cannot be read or is
    /// malformed for the image's machine type. Returns an
    /// [`ErrorKind::InvalidDataDirectory`](crate::ErrorKind) error if the exception table is
    /// larger than the data that the image holds.
    pub fn exception_table(&self) -> Result<Option<crate::exception::ExceptionTable>> {
        use crate::data_dir::DataDirectoryType;

        let Some(directory) = self
            .data_directory(DataDirectoryType::Exception)
            .filter(|directory| directory.is_present())
        else {
            return Ok(None);
        };
        let reader = self.rva_reader();
        if reader.exceeds_zero_fill(directory.size) {
            return Err(crate::Error::invalid_data_directory(
                "exception table is larger than the data that the image holds",
            ));
        }
        let read = |rva: u32, len: usize| reader.read(rva, len);
        crate::exception::ExceptionTable::parse(
            self.coff_header.machine,
            directory.virtual_address,
            directory.size,
            read,
        )
        .map(Some)
    }

    /// Parse an AMD64 exception directory (an array of `RUNTIME_FUNCTION`).
    ///
    /// For code that can inspect ARM-family images or other architecture-specific images, use
    /// [`Self::exception_table`].
    ///
    /// # Errors
    ///
    /// Returns an error if the exception directory cannot be parsed, or if the
    /// image is not AMD64 and its exception directory is present.
    pub fn exception_directory(&self) -> Result<crate::exception::ExceptionDirectory> {
        match self.exception_table()? {
            Some(crate::exception::ExceptionTable::X64(directory)) => Ok(directory),
            Some(_) => Err(Error::invalid_data_directory(
                "exception_directory() is AMD64-only; use exception_table()",
            )),
            None => Ok(crate::exception::ExceptionDirectory::default()),
        }
    }

    /// Write an exception table for the image's architecture.
    ///
    /// The function appends the table to `target_section`. If `target_section` is `None`, it
    /// uses ".pdata", then ".rdata", then the last section. Returns the RVA of the table.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    ///
    /// - The data-directory table has no exception slot, and cannot be extended.
    /// - The table encoding does not match the PE machine type.
    /// - The table cannot be serialized, or its size exceeds `u32`.
    /// - No target section exists.
    /// - The layout update fails, or the table does not fit in the target section that you
    ///   named. See [Directory updates](crate::PeImage#directory-updates).
    pub fn update_exception_table(
        &mut self,
        table: &crate::exception::ExceptionTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        self.ensure_data_directory_slot(DataDirectoryType::Exception)?;

        let machine_matches = match table {
            crate::exception::ExceptionTable::X64(_) => {
                self.coff_header.machine == crate::coff::MachineType::Amd64 as u16
            }
            crate::exception::ExceptionTable::Arm(_) => {
                self.coff_header.machine == crate::coff::MachineType::ArmNt as u16
            }
            crate::exception::ExceptionTable::Arm64(_) => matches!(
                crate::coff::MachineType::from_u16(self.coff_header.machine),
                Some(
                    crate::coff::MachineType::Arm64
                        | crate::coff::MachineType::Arm64Ec
                        | crate::coff::MachineType::Arm64X
                )
            ),
            crate::exception::ExceptionTable::Raw { machine, .. } => {
                *machine == self.coff_header.machine
            }
        };
        if !machine_matches {
            return Err(Error::invalid_data_directory(
                "exception-table encoding does not match the PE machine",
            ));
        }

        let data = table.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("exception table exceeds u32"))?;
        let section_name = target_section
            .map(str::to_string)
            .or_else(|| self.section_by_name(".pdata").map(|_| ".pdata".to_string()))
            .or_else(|| self.section_by_name(".rdata").map(|_| ".rdata".to_string()))
            .or_else(|| {
                self.sections
                    .last()
                    .map(|section| section.name().to_string())
            })
            .ok_or_else(|| Error::invalid_section("no section available for exception data"))?;
        let section_index = self
            .sections
            .iter()
            .position(|section| section.name() == section_name)
            .ok_or_else(|| Error::invalid_section(&section_name))?;
        let (rva, ()) =
            self.append_section_data(section_index, target_section.is_some(), |_| {
                Ok((data.clone(), ()))
            })?;
        self.set_data_directory(DataDirectoryType::Exception, rva, size);
        Ok(rva)
    }

    /// Write the exception directory (the `.pdata` array of `RUNTIME_FUNCTION`).
    ///
    /// This function creates the exception directory with the new function entries, or replaces
    /// the current one. The function sorts a copy of the entries by `begin_address`. If
    /// `target_section` is `None`, the function uses ".pdata", then ".rdata", then the last
    /// section.
    ///
    /// The entries are AMD64 `RUNTIME_FUNCTION` records. For an image of other machine
    /// types, use [`Self::update_exception_table`].
    ///
    /// # Arguments
    /// * `directory` - The exception directory to write.
    /// * `target_section` - The name of the section that gets the exception data (optional).
    ///
    /// Returns the RVA of the new exception directory.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::update_exception_table`]. Thus the function returns an
    /// error if the image machine is not AMD64.
    pub fn update_exception(
        &mut self,
        directory: &crate::exception::ExceptionDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        let mut sorted = directory.clone();
        sorted.sort();
        self.update_exception_table(
            &crate::exception::ExceptionTable::X64(sorted),
            target_section,
        )
    }

    /// Parse the load config directory (`IMAGE_LOAD_CONFIG_DIRECTORY32` or
    /// `IMAGE_LOAD_CONFIG_DIRECTORY64`).
    ///
    /// The Windows loader reads the structure through its own `Size` field. It does not use the
    /// size in the data directory. For 32-bit images, linkers write a directory size of 0x40 for
    /// the Windows XP loader. They write a larger `Size` for the fields that later versions read.
    ///
    /// Thus this function reads `Size` bytes at the directory RVA. If `Size` is zero, the
    /// function uses the directory size. If the mapped image cannot hold the structure, the
    /// function returns an error.
    ///
    /// Returns `Ok(None)` if the load config data directory is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the `Size` field or the structure it describes
    /// cannot be read at the directory RVA, or if the structure is malformed.
    pub fn load_config(&self) -> Result<Option<crate::loadconfig::LoadConfigDirectory>> {
        use crate::data_dir::DataDirectoryType;

        let Some(directory) = self
            .data_directory(DataDirectoryType::LoadConfig)
            .filter(|d| d.is_present())
        else {
            return Ok(None);
        };
        let invalid = || crate::Error::invalid_rva(directory.virtual_address);
        let header = self
            .read_rva(directory.virtual_address, core::mem::size_of::<u32>())
            .ok_or_else(invalid)?;
        let header: [u8; 4] = header.as_slice().try_into().map_err(|_| invalid())?;
        let size = u32::from_le_bytes(header);
        let length = if size == 0 { directory.size } else { size };
        let data = self
            .read_rva(directory.virtual_address, length as usize)
            .ok_or_else(invalid)?;
        Ok(Some(crate::loadconfig::LoadConfigDirectory::parse(
            &data,
            self.is_64bit(),
        )?))
    }

    /// Write the load config directory (`IMAGE_LOAD_CONFIG_DIRECTORY32` or
    /// `IMAGE_LOAD_CONFIG_DIRECTORY64`).
    ///
    /// This function creates the `LoadConfig` directory, or replaces the current one. If
    /// `target_section` is `None`, the function uses ".rdata". If ".rdata" does not exist, it
    /// uses the last section. See [Directory updates](crate::PeImage#directory-updates) for
    /// the fallback if the data does not fit.
    ///
    /// The structure holds VAs, for example `SecurityCookie` and the CFG pointers. If the image
    /// has a base relocation directory, the function adds a `HIGHLOW` (PE32) or `DIR64`
    /// (PE32+) relocation for each VA field that is not zero. This includes the VA fields in
    /// `trailing_data`, up to `GuardMemcpyFunctionPointer`.
    ///
    /// # Arguments
    /// * `config` - The `LoadConfig` directory to write.
    /// * `target_section` - The name of the section that gets the `LoadConfig` data (optional).
    ///
    /// Returns the RVA of the new `LoadConfig` directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the data-directory table has no load config slot
    /// and cannot be extended, if the target section does not exist, if the
    /// structure cannot be serialized, or if the append fails (see
    /// [Directory updates](crate::PeImage#directory-updates)). Also returns an error if the
    /// base relocations cannot be parsed or written. If an error occurs, the image does not
    /// change.
    pub fn update_load_config(
        &mut self,
        config: &crate::loadconfig::LoadConfigDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        self.transact(|image| image.update_load_config_in(config, target_section))
    }

    /// Do the work of [`Self::update_load_config`] on the image. An error can leave the image
    /// half updated.
    fn update_load_config_in(
        &mut self,
        config: &crate::loadconfig::LoadConfigDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::loadconfig::LoadConfigBuilder;
        self.ensure_data_directory_slot(DataDirectoryType::LoadConfig)?;

        // Find the target section.
        let section_name: String = target_section
            .map(str::to_string)
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
            return Err(crate::Error::invalid_section(&section_name));
        };

        // Build the LoadConfig data.
        let builder = LoadConfigBuilder::new(self.is_64bit());
        let (data, dir_size) = builder.try_build(config)?;
        let va_offsets = config.va_field_offsets();

        // Parse the relocations before the image changes.
        let relocations = self.relocations_for_new_vas()?;

        // Append the data to the section.
        let (append_rva, ()) =
            self.append_section_data(section_idx, target_section.is_some(), |_| {
                Ok((data.clone(), ()))
            })?;
        self.set_data_directory(DataDirectoryType::LoadConfig, append_rva, dir_size);
        self.add_va_relocations(relocations, append_rva, &va_offsets)?;

        Ok(append_rva)
    }

    /// Return the base relocations that get the entries for a new block of VAs.
    ///
    /// Returns `Ok(None)` if the image has no base relocation directory.
    fn relocations_for_new_vas(&self) -> Result<Option<crate::reloc::RelocationTable>> {
        let present = self
            .data_directory(crate::data_dir::DataDirectoryType::BaseReloc)
            .is_some_and(|directory| directory.is_present());
        if present {
            self.relocations().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Add a `HIGHLOW` (PE32) or `DIR64` (PE32+) relocation for the VA at each `rva + offset`.
    ///
    /// Then write `relocations` with [`Self::update_relocations`]. If `relocations` is `None`,
    /// the image has no base relocation directory, and the function does nothing.
    fn add_va_relocations(
        &mut self,
        relocations: Option<crate::reloc::RelocationTable>,
        rva: u32,
        offsets: &[usize],
    ) -> Result<()> {
        let Some(mut relocations) = relocations else {
            return Ok(());
        };
        if offsets.is_empty() {
            return Ok(());
        }
        for &offset in offsets {
            let target = u32::try_from(offset)
                .ok()
                .and_then(|offset| rva.checked_add(offset))
                .ok_or_else(|| Error::invalid_data_directory("relocated VA has no valid RVA"))?;
            if self.is_64bit() {
                relocations.add_dir64(target);
            } else {
                relocations.add_highlow(target);
            }
        }
        self.update_relocations(&relocations, None)?;
        Ok(())
    }

    pub(crate) fn clear_security(&mut self) {
        use crate::data_dir::DataDirectoryType;
        self.clear_data_directory(DataDirectoryType::Security);
    }
}
