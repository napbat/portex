use super::{MAX_NUMBER_OF_SECTIONS, PeImage};
use crate::data_dir::DataDirectoryType;
use crate::dos::DosHeader;
use crate::layout::{self, LayoutConfig};
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::validation::{ValidationCode, ValidationIssue, ValidationResult};

impl PeImage {
    // ========== Validation ==========

    /// Validate the structural integrity of the PE image.
    ///
    /// Returns a collection of validation issues (errors and warnings). An empty result means
    /// that the image passed all validation checks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::PeImage;
    ///
    /// # let file_bytes: &[u8] = &[];
    /// let pe = PeImage::parse(file_bytes).unwrap();
    /// let result = pe.validate();
    ///
    /// if result.has_errors() {
    ///     for issue in result.errors() {
    ///         eprintln!("Error: {}", issue);
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn validate(&self) -> ValidationResult {
        let mut result = ValidationResult::new();

        self.validate_header_fields(&mut result);

        let file_align = self.optional_header.file_alignment();
        let section_align = self.optional_header.section_alignment();
        Self::validate_alignments(&mut result, file_align, section_align);
        self.validate_headers_size(&mut result, file_align);
        self.validate_image_size(&mut result, section_align);
        self.validate_optional_summaries(&mut result);
        self.validate_entry_point(&mut result);
        self.validate_section_file_overlaps(&mut result);
        self.validate_section_placement(&mut result, file_align, section_align);
        self.validate_section_virtual_overlaps(&mut result);
        self.validate_data_directories(&mut result);
        self.validate_checksum(&mut result);

        result
    }

    /// Check the consistency of the DOS, COFF and optional-header fields.
    fn validate_header_fields(&self, result: &mut ValidationResult) {
        // Check the DOS signature.
        if self.dos_header.e_magic != 0x5A4D {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidDosSignature,
                "DOS signature is not 'MZ'",
            ));
        }
        // The parser reads an unknown magic with the layout of the machine type.
        let magic = match &self.optional_header {
            OptionalHeader::Pe32(header) => header.magic,
            OptionalHeader::Pe32Plus(header) => header.magic,
        };
        if magic != crate::optional::PE32_MAGIC && magic != crate::optional::PE32PLUS_MAGIC {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidOptionalMagic,
                format!("optional-header magic {magic:#06x} is not PE32 or PE32+"),
            ));
        }

        // Check that sections exist.
        if self.sections.is_empty() {
            result.push(ValidationIssue::warning(
                ValidationCode::NoSections,
                "PE has no sections",
            ));
        }

        if usize::from(self.coff_header.number_of_sections) != self.sections.len() {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentSectionCount,
                format!(
                    "COFF declares {} sections, but {} section records are present",
                    self.coff_header.number_of_sections,
                    self.sections.len()
                ),
            ));
        }
        if self.sections.len() > MAX_NUMBER_OF_SECTIONS {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentSectionCount,
                format!(
                    "section count {} exceeds the PE image limit of {}",
                    self.sections.len(),
                    MAX_NUMBER_OF_SECTIONS
                ),
            ));
        }

        // The loader reads all fields of the optional header, also if the section table overlaps
        // them. Thus this is valid, but unusual.
        let expected_optional_size = self.optional_header.size();
        if usize::from(self.coff_header.size_of_optional_header) < expected_optional_size {
            result.push(ValidationIssue::warning(
                ValidationCode::InconsistentOptionalHeader,
                format!(
                    "COFF optional-header size is {}, but the optional header has {} bytes: the section table overlaps it",
                    self.coff_header.size_of_optional_header, expected_optional_size
                ),
            ));
        }
        let (declared_count, directory_len) = match &self.optional_header {
            OptionalHeader::Pe32(header) => (
                header.number_of_rva_and_sizes,
                header.data_directories.len(),
            ),
            OptionalHeader::Pe32Plus(header) => (
                header.number_of_rva_and_sizes,
                header.data_directories.len(),
            ),
        };
        let loaded_count = usize::try_from(declared_count)
            .unwrap_or(usize::MAX)
            .min(crate::data_dir::NUMBER_OF_DIRECTORY_ENTRIES);
        if loaded_count != directory_len {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentOptionalHeader,
                format!(
                    "NumberOfRvaAndSizes is {declared_count}, but {directory_len} directory entries are present"
                ),
            ));
        } else if loaded_count < declared_count as usize {
            result.push(ValidationIssue::warning(
                ValidationCode::InconsistentOptionalHeader,
                format!(
                    "NumberOfRvaAndSizes is {declared_count}, but the loader reads only {loaded_count} entries"
                ),
            ));
        }

        let machine_magic_matches = crate::coff::MachineType::from_u16(self.coff_header.machine)
            .is_none_or(|machine| {
                machine == crate::coff::MachineType::Unknown
                    || machine.is_64_bit() == self.is_64bit()
            });
        if !machine_magic_matches {
            result.push(ValidationIssue::error(
                ValidationCode::MachineMagicMismatch,
                format!(
                    "machine {:#x} is inconsistent with the optional-header width",
                    self.coff_header.machine
                ),
            ));
        }
    }

    /// Check `FileAlignment` and `SectionAlignment` values.
    fn validate_alignments(result: &mut ValidationResult, file_align: u32, section_align: u32) {
        // Check the file alignment.
        let low_alignment = section_align != 0 && section_align < 0x1000;
        if file_align == 0
            || !file_align.is_power_of_two()
            || file_align > 0x1_0000
            || (low_alignment && file_align != section_align)
            || (!low_alignment && file_align < 512)
        {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidFileAlignment,
                format!("Invalid file alignment: {file_align:#x}"),
            ));
        }

        // Check the section alignment.
        if section_align == 0 || !section_align.is_power_of_two() {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidSectionAlignment,
                format!("Invalid section alignment: {section_align:#x}"),
            ));
        }
        if section_align != 0 && file_align > section_align {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidSectionAlignment,
                format!(
                    "file alignment {file_align:#x} exceeds section alignment {section_align:#x}"
                ),
            ));
        }
    }

    /// Check `e_lfanew` and `SizeOfHeaders` against the header table.
    fn validate_headers_size(&self, result: &mut ValidationResult, file_align: u32) {
        // The loader of executable images needs `e_lfanew` of 4 or more. The data-file loader
        // also accepts 2 and 3.
        match usize::try_from(self.dos_header.e_lfanew) {
            Ok(pe_offset) if pe_offset >= DosHeader::SIZE => {}
            Ok(pe_offset) if pe_offset >= 4 => {
                result.push(ValidationIssue::warning(
                    ValidationCode::InconsistentHeadersSize,
                    "e_lfanew places the NT headers inside the DOS header",
                ));
            }
            _ => {
                result.push(ValidationIssue::error(
                    ValidationCode::InconsistentHeadersSize,
                    "e_lfanew is smaller than 4, the minimum for an executable image",
                ));
            }
        }
        let minimum_headers_size = self
            .nt_headers_end()
            .and_then(|size| u32::try_from(size).ok());
        if let Some(minimum) = minimum_headers_size
            && self.optional_header.size_of_headers() < minimum
        {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentHeadersSize,
                format!(
                    "SizeOfHeaders {:#x} is smaller than the header table ending at {:#x}",
                    self.optional_header.size_of_headers(),
                    minimum
                ),
            ));
        }
        if file_align != 0
            && !self
                .optional_header
                .size_of_headers()
                .is_multiple_of(file_align)
        {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentHeadersSize,
                format!(
                    "SizeOfHeaders {:#x} is not aligned to FileAlignment {:#x}",
                    self.optional_header.size_of_headers(),
                    file_align
                ),
            ));
        }

        if file_align != 0 && file_align.is_power_of_two() {
            let expected_headers = self
                .nt_headers_end()
                .and_then(|table_end| self.header_data_end(table_end))
                .and_then(|size| u32::try_from(size).ok())
                .and_then(|size| layout::checked_align_up(size, file_align));
            if let Some(expected) = expected_headers
                && self.optional_header.size_of_headers() != expected
            {
                result.push(ValidationIssue::error(
                    ValidationCode::InconsistentHeadersSize,
                    format!(
                        "SizeOfHeaders is {:#x}, expected {:#x}",
                        self.optional_header.size_of_headers(),
                        expected
                    ),
                ));
            }
        }
    }

    /// Check `SizeOfImage` against the header size and the section layout.
    fn validate_image_size(&self, result: &mut ValidationResult, section_align: u32) {
        if section_align != 0 && section_align.is_power_of_two() {
            let config = LayoutConfig::from_optional_header(&self.optional_header);
            match layout::try_calculate_size_of_image_with_headers(
                &self.sections,
                &config,
                self.optional_header.size_of_headers(),
            ) {
                Ok(expected) if expected != self.optional_header.size_of_image() => {
                    result.push(ValidationIssue::error(
                        ValidationCode::InconsistentImageSize,
                        format!(
                            "SizeOfImage is {:#x}, expected {:#x}",
                            self.optional_header.size_of_image(),
                            expected
                        ),
                    ));
                }
                Err(error) => result.push(
                    ValidationIssue::error(
                        ValidationCode::InvalidSectionLayout,
                        "section ranges cannot produce a valid SizeOfImage",
                    )
                    .with_context(error.to_string()),
                ),
                _ => {}
            }
        }
    }

    /// Check the code and data summaries in the optional header. The linker sets these fields.
    fn validate_optional_summaries(&self, result: &mut ValidationResult) {
        match super::edit::calculate_optional_layout_fields(&self.sections) {
            Ok(expected) => {
                let (size_of_code, initialized, uninitialized, base_of_code, base_of_data) =
                    match &self.optional_header {
                        OptionalHeader::Pe32(header) => (
                            header.size_of_code,
                            header.size_of_initialized_data,
                            header.size_of_uninitialized_data,
                            header.base_of_code,
                            Some(header.base_of_data),
                        ),
                        OptionalHeader::Pe32Plus(header) => (
                            header.size_of_code,
                            header.size_of_initialized_data,
                            header.size_of_uninitialized_data,
                            header.base_of_code,
                            None,
                        ),
                    };
                if size_of_code != expected.size_of_code
                    || initialized != expected.size_of_initialized_data
                    || uninitialized != expected.size_of_uninitialized_data
                    || base_of_code != expected.base_of_code
                    || base_of_data.is_some_and(|value| value != expected.base_of_data)
                {
                    // These fields are linker summaries, not loader invariants. For example,
                    // the Microsoft linker can count auxiliary code sections in
                    // SizeOfInitializedData, even when they only have IMAGE_SCN_CNT_CODE.
                    // Report the difference, but do not reject images that are otherwise valid.
                    result.push(
                        ValidationIssue::warning(
                            ValidationCode::InconsistentOptionalHeader,
                            "linker-derived optional-header code/data summaries differ from section characteristics",
                        )
                        .with_context(format!(
                            "declared code={size_of_code:#x}, initialized={initialized:#x}, uninitialized={uninitialized:#x}, base_of_code={base_of_code:#x}, base_of_data={base_of_data:?}; section-derived code={:#x}, initialized={:#x}, uninitialized={:#x}, base_of_code={:#x}, base_of_data={:#x}",
                            expected.size_of_code,
                            expected.size_of_initialized_data,
                            expected.size_of_uninitialized_data,
                            expected.base_of_code,
                            expected.base_of_data,
                        )),
                    );
                }
            }
            Err(error) => result.push(
                ValidationIssue::error(
                    ValidationCode::InvalidSectionLayout,
                    "section aggregates exceed PE limits",
                )
                .with_context(error.to_string()),
            ),
        }
    }

    /// Check that `AddressOfEntryPoint` lies within a section.
    fn validate_entry_point(&self, result: &mut ValidationResult) {
        // Check that the entry point is in a section, or is 0 for a DLL.
        let entry = self.optional_header.address_of_entry_point();
        if entry != 0 {
            let entry_in_section = self.sections.iter().any(|s| s.header.contains_rva(entry));
            if !entry_in_section {
                result.push(ValidationIssue::warning(
                    ValidationCode::EntryPointOutOfBounds,
                    format!("Entry point {entry:#x} is not within any section"),
                ));
            }
        }
    }

    /// Check that the raw file ranges of the sections do not overlap.
    ///
    /// Each range starts where the loader reads the raw data (see
    /// [`layout::loader_raw_offset`]).
    fn validate_section_file_overlaps(&self, result: &mut ValidationResult) {
        let file_alignment = self.optional_header.file_alignment();
        let ranges = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, section)| {
                section.header.pointer_to_raw_data != 0 && section.header.size_of_raw_data != 0
            })
            .map(|(index, section)| {
                let start = u64::from(layout::loader_raw_offset(
                    section.header.pointer_to_raw_data,
                    file_alignment,
                ));
                (
                    start,
                    start + u64::from(section.header.size_of_raw_data),
                    index,
                )
            })
            .collect();
        for (earlier, later) in overlapping_ranges(ranges) {
            self.push_overlap(result, "file", earlier, later);
        }
    }

    /// Report that the section ranges `earlier` and `later` overlap in `place`.
    fn push_overlap(
        &self,
        result: &mut ValidationResult,
        place: &str,
        earlier: SectionRange,
        later: SectionRange,
    ) {
        let first = self.sections[earlier.2].header.name_str();
        let second = self.sections[later.2].header.name_str();
        result.push(
            ValidationIssue::error(
                ValidationCode::OverlappingSections,
                format!("Sections '{first}' and '{second}' overlap in {place}"),
            )
            .with_context(format!(
                "{first}: {:#x}-{:#x}, {second}: {:#x}-{:#x}",
                earlier.0, earlier.1, later.0, later.1
            )),
        );
    }

    /// Check the section alignment and the loaded raw data.
    fn validate_section_placement(
        &self,
        result: &mut ValidationResult,
        file_align: u32,
        section_align: u32,
    ) {
        for section in &self.sections {
            if file_align != 0
                && section.header.pointer_to_raw_data != 0
                && !section
                    .header
                    .pointer_to_raw_data
                    .is_multiple_of(file_align)
            {
                result.push(
                    ValidationIssue::error(
                        ValidationCode::MisalignedSection,
                        format!(
                            "section '{}' raw offset {:#x} is not aligned to {:#x}",
                            section.name(),
                            section.header.pointer_to_raw_data,
                            file_align
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
            if section_align != 0 && !section.header.virtual_address.is_multiple_of(section_align) {
                result.push(
                    ValidationIssue::error(
                        ValidationCode::MisalignedSection,
                        format!(
                            "section '{}' RVA {:#x} is not aligned to {:#x}",
                            section.name(),
                            section.header.virtual_address,
                            section_align
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
            if file_align != 0
                && section.header.size_of_raw_data != 0
                && !section.header.size_of_raw_data.is_multiple_of(file_align)
            {
                result.push(
                    ValidationIssue::error(
                        ValidationCode::MisalignedSection,
                        format!(
                            "section '{}' raw size {:#x} is not aligned to {:#x}",
                            section.name(),
                            section.header.size_of_raw_data,
                            file_align
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
            if section.data.is_empty() && section.header.size_of_raw_data != 0 {
                result.push(
                    ValidationIssue::warning(
                        ValidationCode::EmptySectionWithSize,
                        format!(
                            "section '{}' declares raw data but no bytes were loaded",
                            section.name()
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
        }
    }

    /// Check that the virtual ranges of the sections do not overlap.
    fn validate_section_virtual_overlaps(&self, result: &mut ValidationResult) {
        let ranges = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, section)| {
                section
                    .header
                    .virtual_size
                    .max(section.header.size_of_raw_data)
                    != 0
            })
            .map(|(index, section)| {
                let start = u64::from(section.header.virtual_address);
                let size = section
                    .header
                    .virtual_size
                    .max(section.header.size_of_raw_data);
                (start, start + u64::from(size), index)
            })
            .collect();
        for (earlier, later) in overlapping_ranges(ranges) {
            self.push_overlap(result, "virtual memory", earlier, later);
        }
    }

    /// Check the data directory entries against the image.
    fn validate_data_directories(&self, result: &mut ValidationResult) {
        // Check that the data directories point to valid sections.
        for dir_type in DataDirectoryType::all() {
            if let Some(dir) = self.data_directory(dir_type)
                && dir.is_present()
            {
                if dir_type != DataDirectoryType::GlobalPtr
                    && (dir.virtual_address == 0 || dir.size == 0)
                {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::InvalidDataDirectoryRange,
                            format!(
                                "data directory {} has only one of address/size set",
                                dir_type.name()
                            ),
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                    continue;
                }
                if matches!(
                    dir_type,
                    DataDirectoryType::Architecture | DataDirectoryType::Reserved
                ) {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::ReservedDataDirectory,
                            format!("reserved data directory {} must be zero", dir_type.name()),
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                    continue;
                }
                if dir_type == DataDirectoryType::GlobalPtr && dir.size != 0 {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::ReservedDataDirectory,
                            "Global Pointer directory size must be zero",
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                }
                if dir_type == DataDirectoryType::Security {
                    // Its address is a file offset, and `PeImage` intentionally does not own
                    // overlay bytes. `PeFile` validates the actual range.
                    continue;
                }
                let rva = dir.virtual_address;
                let in_image = u64::from(rva)
                    .checked_add(u64::from(dir.size))
                    .is_some_and(|end| end <= u64::from(self.optional_header.size_of_image()));
                let range_readable =
                    usize::try_from(dir.size).is_ok_and(|size| self.contains_rva_range(rva, size));
                if !in_image || !range_readable {
                    result.push(
                        ValidationIssue::warning(
                            ValidationCode::InvalidDataDirectoryRange,
                            format!(
                                "data directory {} range {:#x}..+{:#x} is outside the image",
                                dir_type.name(),
                                rva,
                                dir.size
                            ),
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                }
            }
        }
    }

    /// Check a nonzero `CheckSum` against the computed checksum.
    fn validate_checksum(&self, result: &mut ValidationResult) {
        // Warn only if the checksum is nonzero and does not match.
        let stored_checksum = match &self.optional_header {
            OptionalHeader::Pe32(h) => h.check_sum,
            OptionalHeader::Pe32Plus(h) => h.check_sum,
        };
        if stored_checksum == 0 {
            return;
        }
        // The checksum covers the serialized image. Malformed file data can stop the build.
        match self.try_calculate_checksum() {
            Ok(computed) if computed != stored_checksum => {
                result.push(ValidationIssue::warning(
                    ValidationCode::InvalidChecksum,
                    format!(
                        "Checksum mismatch: stored {stored_checksum:#x}, computed {computed:#x}"
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                result.push(ValidationIssue::warning(
                    ValidationCode::InvalidChecksum,
                    format!("Checksum {stored_checksum:#x} cannot be verified: {error}"),
                ));
            }
        }
    }
}

/// The range of a section as `(start, end, section index)`.
type SectionRange = (u64, u64, usize);

/// Find the section ranges that overlap an earlier range.
///
/// The function sorts the ranges by their start. It reports each range that starts before the
/// end of an earlier range, together with the earlier range that ends last. Thus the work is
/// O(n log n) also for 65535 sections, and the result has fewer entries than `ranges`.
fn overlapping_ranges(mut ranges: Vec<SectionRange>) -> Vec<(SectionRange, SectionRange)> {
    ranges.sort_unstable();
    let mut overlaps = Vec::new();
    let mut widest: Option<SectionRange> = None;
    for range in ranges {
        if let Some(earlier) = widest {
            if range.0 < earlier.1 {
                overlaps.push((earlier, range));
            }
            if range.1 <= earlier.1 {
                continue;
            }
        }
        widest = Some(range);
    }
    overlaps
}
