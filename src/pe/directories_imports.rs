use super::PeImage;
use crate::data_dir::DataDirectoryType;
use crate::{Error, Result};

/// The IAT ranges of an import table that `update_imports` wrote. Each range is
/// `start..end` in RVAs.
#[derive(Debug, Clone, Copy)]
struct IatRanges {
    /// The new IATs in the written data.
    new: Option<(u32, u32)>,
    /// The kept IATs, from the first to the end of the last.
    kept: Option<(u32, u32)>,
}

impl PeImage {
    /// Update the imports.
    ///
    /// The function first tries to replace the data in place. If the data does not fit, the
    /// function appends it to the section with the index `target_section` in
    /// [`Self::sections`]. If `target_section` is `None`, the function adds a new section for
    /// the data. See [Directory updates](crate::PeImage#directory-updates).
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
    /// The loader writes each IAT when it binds the imports. It makes the range of the IAT
    /// data directory writable for this. Without an IAT data directory, it makes only the
    /// section of the import descriptors writable. Thus the function sets the IAT data
    /// directory as follows:
    ///
    /// - If one section holds all IATs, the directory gets the range from the first IAT to the
    ///   end of the last IAT.
    /// - If the new IATs are in a different section than the kept IATs, the directory gets the
    ///   range of the kept IATs. The section of the new IATs must then be writable. A new
    ///   section for the data is writable in this case. If `target_section` selects a section
    ///   that is not writable, the function returns an error.
    /// - If the kept IATs are in more than one section, the IAT data directory does not
    ///   change.
    ///
    /// Returns the RVA of the import directory. Returns 0 if `imports` is empty; then the
    /// function clears the import and IAT data directories.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions. Then the image does not change.
    /// - The data directory table has no IAT slot and cannot be extended.
    /// - The import table cannot be serialized, or its descriptor table does not fit in `u32`.
    /// - `target_section` is not the index of a section.
    /// - The layout update fails, or the data does not fit in the selected section. See
    ///   [Directory updates](crate::PeImage#directory-updates).
    /// - The new IATs need a writable section, and the selected section is not writable.
    pub fn update_imports(
        &mut self,
        imports: &crate::import::ImportTable,
        target_section: Option<usize>,
    ) -> Result<u32> {
        if imports.is_empty() {
            self.clear_data_directory(DataDirectoryType::Import);
            self.clear_data_directory(DataDirectoryType::Iat);
            return Ok(0);
        }
        self.transact(|image| image.update_imports_in(imports, target_section))
    }

    /// Do the work of [`Self::update_imports`] for a table that is not empty.
    fn update_imports_in(
        &mut self,
        imports: &crate::import::ImportTable,
        target_section: Option<usize>,
    ) -> Result<u32> {
        use crate::import::ImportTableBuilder;

        self.ensure_data_directory_slot(DataDirectoryType::Iat)?;
        let import_size = import_descriptor_table_size(imports.dlls.len())?;

        // Keep the IATs of the unchanged DLLs. If the current table is malformed, no DLL is
        // unchanged, and each DLL gets a new IAT.
        let current = self.imports().unwrap_or_default();
        let is_64bit = self.is_64bit();
        let build_at = |base_rva| {
            let built = ImportTableBuilder::new(is_64bit, base_rva)
                .keep_unchanged_iats(&current)
                .try_build_parts(imports)?;
            let ranges = IatRanges {
                new: built.new_iats,
                kept: built.kept_iats,
            };
            Ok((built.data, ranges))
        };

        // Try to replace the data in place. Do not write in place if a kept IAT is in the way,
        // or if the new IATs need a writable section there.
        let existing_dir = self.data_directory(DataDirectoryType::Import).copied();
        if let Some(dir) = &existing_dir
            && dir.is_present()
            && let Ok((data, ranges)) = build_at(dir.virtual_address)
            && data.len() <= dir.size as usize
            && let Some(index) = self.section_index_at(dir.virtual_address)
            && (self.sections[index].header.is_writable()
                || !needs_writable_iats(self, index, ranges))
            && self.write_at_rva(dir.virtual_address, &data).is_some()
        {
            self.set_data_directory(DataDirectoryType::Import, dir.virtual_address, import_size);
            set_iat_directory(self, ranges);
            return Ok(dir.virtual_address);
        }

        // Build the import data at the append RVA, and append it to the section.
        let (append_rva, ranges) =
            self.append_section_data_with(target_section, build_at, |image, index, ranges| {
                needs_writable_iats(image, index, *ranges)
            })?;

        self.set_data_directory(DataDirectoryType::Import, append_rva, import_size);
        set_iat_directory(self, ranges);
        Ok(append_rva)
    }
}

fn import_descriptor_table_size(dll_count: usize) -> Result<u32> {
    dll_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(crate::import::ImportDescriptor::SIZE))
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| Error::invalid_data_directory("import descriptor table exceeds u32"))
}

/// Return the index of the one section that holds the RVA range `start..end`, if there is
/// one.
fn range_section(image: &PeImage, (start, end): (u32, u32)) -> Option<usize> {
    let last = end.checked_sub(1).filter(|last| *last >= start)?;
    let index = image.section_index_at(start)?;
    (image.section_index_at(last)? == index).then_some(index)
}

/// Return `true` if the new IATs need a writable section when the data goes to the section
/// at `index`.
///
/// This is the case if there are new IATs and kept IATs, and the kept IATs are not all in the
/// section at `index`. Then the IAT data directory holds only the kept IATs (see
/// [`set_iat_directory`]), and the loader writes the new IATs without a change of protection.
fn needs_writable_iats(image: &PeImage, index: usize, ranges: IatRanges) -> bool {
    match (ranges.new, ranges.kept) {
        (Some(_), Some(kept)) => range_section(image, kept) != Some(index),
        _ => false,
    }
}

/// Set the IAT data directory after an update of the imports.
///
/// The loader makes the range of the IAT data directory writable while it binds the imports.
/// Without an IAT data directory, it makes only the section of the import descriptors
/// writable. A directory range over more than one section is not safe: the loader gives the
/// complete range the old protection of its first page after the binding. Thus:
///
/// - If one section holds all IATs, the directory covers them all.
/// - Else the directory covers the kept IATs. The new IATs are then in a writable section (see
///   [`needs_writable_iats`]).
/// - If the kept IATs are in more than one section, the directory does not change.
fn set_iat_directory(image: &mut PeImage, ranges: IatRanges) {
    let all = match (ranges.new, ranges.kept) {
        (Some((new_start, new_end)), Some((kept_start, kept_end))) => {
            Some((new_start.min(kept_start), new_end.max(kept_end)))
        }
        (Some(range), None) | (None, Some(range)) => Some(range),
        (None, None) => None,
    };
    let range = all
        .filter(|range| range_section(image, *range).is_some())
        .or(ranges.kept)
        .filter(|range| range_section(image, *range).is_some());
    if let Some((start, end)) = range {
        image.set_data_directory(DataDirectoryType::Iat, start, end - start);
    }
}
