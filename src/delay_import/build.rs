//! Serialization of a delay-load import table.

use nostdio::{Cursor, Seek, Write, WriteLe};

use super::{DelayImportDirectory, DelayLoadDescriptor, DelayLoadedDll};
use crate::import::{
    IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, ImportThunk, skip_to_even, split_parts,
};
use crate::prelude::*;
use crate::{Error, Result};

/// Builder that serializes delay-load import tables.
///
/// The built data has these parts, in this order: the descriptors, the new delay-load import
/// address tables (IAT), the import name tables (INT), the new module handles, the hint/name
/// entries and the DLL names.
///
/// # Keep rule
///
/// Code calls a delay-loaded function through its slot in the delay IAT. Each slot holds the VA
/// of a load stub until the first call. The stub passes the address of its descriptor to the
/// delay-load helper.
///
/// By default, the builder writes new tables for each DLL. Call [`Self::keep_unchanged`] with
/// the directory that the image holds now. Then, for each DLL whose function list is unchanged,
/// the builder keeps these descriptor fields: the module handle, the IAT, the bound IAT, the
/// unload IAT and the time stamp. Only the INT, the names and the descriptor move.
///
/// # Caution
///
/// A new IAT holds placeholder values: the same values as the INT. Each slot must hold the VA
/// of a load stub, with a base relocation. Write the stubs, and patch the slots, before the
/// image runs.
#[derive(Debug)]
pub struct DelayImportBuilder {
    /// If `true`, build for PE32+. If `false`, build for PE32.
    pub is_64bit: bool,
    /// RVA of the start of the built delay import data.
    pub base_rva: u32,
    /// The descriptors that the builder can keep, and their functions, keyed by the IAT RVA.
    existing: BTreeMap<u32, (DelayLoadDescriptor, Vec<ImportThunk>)>,
}

impl DelayImportBuilder {
    /// Create a new builder. The builder writes new tables for each DLL.
    #[must_use]
    pub fn new(is_64bit: bool, base_rva: u32) -> Self {
        Self {
            is_64bit,
            base_rva,
            existing: BTreeMap::new(),
        }
    }

    /// Keep the tables of each DLL whose function list is the same as in `existing`.
    ///
    /// `existing` is the directory that the image holds now, for example from
    /// [`crate::PeImage::delay_imports`]. A DLL in the built table keeps its tables if
    /// `existing` has a DLL with the same nonzero `import_address_table_rva` and the same
    /// `imports`. Each existing IAT is kept for one DLL only. See the keep rule in the type
    /// docs.
    #[must_use]
    pub fn keep_unchanged(mut self, existing: &DelayImportDirectory) -> Self {
        for dll in existing.dlls.iter().rev() {
            let iat = dll.descriptor.import_address_table_rva;
            if iat != 0 {
                self.existing
                    .insert(iat, (dll.descriptor, dll.imports.clone()));
            }
        }
        self
    }

    /// Calculate the total size of the delay import data.
    ///
    /// The size depends on [`Self::is_64bit`] and on the kept tables, so this is a method and
    /// not an associated function.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(&self, dlls: &[DelayLoadedDll]) -> usize {
        self.try_calculate_size(dlls)
            .expect("delay-import size overflow: use try_calculate_size()")
    }

    /// Calculate the size. Use checked arithmetic for the descriptor, thunk,
    /// handle and name counts.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error if a DLL name or a function name
    /// is empty or contains NUL. Also returns this error if a size computation
    /// overflows `usize`.
    pub fn try_calculate_size(&self, dlls: &[DelayLoadedDll]) -> Result<usize> {
        if dlls.is_empty() {
            return Ok(0);
        }
        Ok(self.layout(dlls)?.total_size)
    }

    /// Return the kept descriptor of each DLL in `dlls`, or `None` for a DLL that gets new
    /// tables.
    fn kept_descriptors(&self, dlls: &[DelayLoadedDll]) -> Vec<Option<DelayLoadDescriptor>> {
        let mut used = BTreeSet::new();
        let mut kept = Vec::with_capacity(dlls.len());
        for dll in dlls {
            let iat = dll.descriptor.import_address_table_rva;
            let descriptor = self
                .existing
                .get(&iat)
                .filter(|(_, imports)| iat != 0 && *imports == dll.imports)
                .map(|(descriptor, _)| *descriptor)
                .filter(|_| used.insert(iat));
            kept.push(descriptor);
        }
        kept
    }

    /// Validate the names in `dlls` and calculate the layout of the built
    /// table. Do not call this function for an empty list.
    fn layout(&self, dlls: &[DelayLoadedDll]) -> Result<DelayImportLayout> {
        let thunk_size = self.thunk_size();
        let kept = self.kept_descriptors(dlls);

        // Descriptors: one for each DLL, plus a null terminator.
        let descriptors_size = dlls
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(DelayLoadDescriptor::SIZE))
            .ok_or_else(|| {
                Error::invalid_data_directory("delay-import descriptor size overflow")
            })?;

        // The INT has the thunks of each DLL plus a null terminator for each DLL. The new IAT
        // has the same entries, and one module handle, for each DLL that gets new tables.
        let count_error = || Error::invalid_data_directory("delay-import thunk count overflow");
        let mut name_table_count = 0usize;
        let mut iat_count = 0usize;
        let mut handle_count = 0usize;
        for (dll, kept) in dlls.iter().zip(&kept) {
            if dll.name.is_empty() || dll.name.as_bytes().contains(&0) {
                return Err(Error::invalid_data_directory(
                    "delay-import DLL names must be nonempty and contain no NUL bytes",
                ));
            }
            let entries = dll.imports.len().checked_add(1).ok_or_else(count_error)?;
            name_table_count = name_table_count
                .checked_add(entries)
                .ok_or_else(count_error)?;
            if kept.is_none() {
                iat_count = iat_count.checked_add(entries).ok_or_else(count_error)?;
                handle_count += 1;
            }
        }
        let size_error = || Error::invalid_data_directory("delay-import thunk table size overflow");
        let iat_size = iat_count.checked_mul(thunk_size).ok_or_else(size_error)?;
        let name_table_size = name_table_count
            .checked_mul(thunk_size)
            .ok_or_else(size_error)?;
        // Module handles: one `HMODULE` pointer for each DLL with new tables.
        let handles_size = handle_count
            .checked_mul(thunk_size)
            .ok_or_else(|| Error::invalid_data_directory("delay-import handle size overflow"))?;

        let hint_names_size = hint_names_size(dlls)?;

        // DLL names.
        let mut dll_names_size = 0usize;
        for dll in dlls {
            dll_names_size = dll_names_size
                .checked_add(dll.name.len().checked_add(1).ok_or_else(|| {
                    Error::invalid_data_directory("delay-import DLL name size overflow")
                })?)
                .ok_or_else(|| {
                    Error::invalid_data_directory("delay-import DLL names size overflow")
                })?;
        }

        let overflow = || Error::invalid_data_directory("delay-import table size overflow");
        let name_table_offset = descriptors_size
            .checked_add(iat_size)
            .ok_or_else(overflow)?;
        let handles_offset = name_table_offset
            .checked_add(name_table_size)
            .ok_or_else(overflow)?;
        let hint_names_offset = handles_offset
            .checked_add(handles_size)
            .ok_or_else(overflow)?;
        let dll_names_offset = hint_names_offset
            .checked_add(hint_names_size)
            .ok_or_else(overflow)?;
        let total_size = dll_names_offset
            .checked_add(dll_names_size)
            .ok_or_else(overflow)?;
        Ok(DelayImportLayout {
            descriptors_size,
            name_table_offset,
            handles_offset,
            hint_names_offset,
            dll_names_offset,
            total_size,
            kept,
        })
    }

    /// Build the delay import data and return `(section_data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self, dlls: &[DelayLoadedDll]) -> (Vec<u8>, u32) {
        self.try_build(dlls)
            .expect("delay-import build failed: use try_build() for fallible serialization")
    }

    /// Build a delay import table. Use checked RVAs and sizes.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`]. Also returns an
    /// invalid-data-directory error if one of these conditions occurs:
    ///
    /// - The table is larger than `u32`.
    /// - The RVA range of the table overflows.
    /// - For PE32, an RVA reaches the ordinal flag bit.
    /// - A kept IAT or module handle overlaps the built data, or its RVA range overflows.
    pub fn try_build(&self, dlls: &[DelayLoadedDll]) -> Result<(Vec<u8>, u32)> {
        if dlls.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let layout = self.layout(dlls)?;
        let total_size_u32 = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("delay-import table exceeds u32"))?;
        let end = self
            .base_rva
            .checked_add(total_size_u32)
            .ok_or_else(|| Error::invalid_data_directory("delay-import RVA range overflow"))?;
        if !self.is_64bit && end > IMAGE_ORDINAL_FLAG32 {
            return Err(Error::invalid_data_directory(
                "PE32 delay-import RVAs would overlap the ordinal flag",
            ));
        }
        for (dll, kept) in dlls.iter().zip(&layout.kept) {
            if let Some(kept) = kept {
                let entries = dll.imports.len().saturating_add(1);
                self.check_kept_range(kept.import_address_table_rva, entries, end)?;
                self.check_kept_range(kept.module_handle_rva, 1, end)?;
            }
        }
        let data = self.write_table(dlls, &layout)?;
        Ok((data, total_size_u32))
    }

    /// Make sure that `entries` kept thunks at `rva` do not overlap the built data, which ends
    /// at `end`.
    fn check_kept_range(&self, rva: u32, entries: usize, end: u32) -> Result<()> {
        if rva == 0 {
            return Ok(());
        }
        let kept_end = entries
            .checked_mul(self.thunk_size())
            .and_then(|size| u32::try_from(size).ok())
            .and_then(|size| rva.checked_add(size))
            .ok_or_else(|| Error::invalid_data_directory("kept delay-import RVA overflow"))?;
        if rva < end && self.base_rva < kept_end {
            return Err(Error::invalid_data_directory(
                "a kept delay-import table overlaps the built table",
            ));
        }
        Ok(())
    }

    /// Serialize `dlls` into a new buffer with the parts at the offsets in
    /// `layout`.
    fn write_table(&self, dlls: &[DelayLoadedDll], layout: &DelayImportLayout) -> Result<Vec<u8>> {
        let thunk_skip = self.thunk_skip();
        let mut data = vec![0u8; layout.total_size];

        // The parts are in this order: descriptors, IAT, INT, module handles,
        // hint/name entries, DLL names. The IAT starts after the descriptors.
        let starts = [
            0,
            layout.descriptors_size,
            layout.name_table_offset,
            layout.handles_offset,
            layout.hint_names_offset,
            layout.dll_names_offset,
        ];
        let [
            _,
            iat_start,
            name_table_start,
            handle_start,
            hint_name_start,
            dll_name_start,
        ] = starts;
        let [
            mut desc,
            mut iat,
            mut name_table,
            mut handle,
            mut hint_name,
            mut dll_name,
        ] = split_parts(&mut data, starts)?;

        for (dll, kept) in dlls.iter().zip(&layout.kept) {
            // Write the descriptor. Attributes value 1 means that the fields are RVAs
            // (the modern format).
            let dll_name_rva = self.rva_at(dll_name_start, dll_name.position())?;
            let import_name_table_rva = self.rva_at(name_table_start, name_table.position())?;
            let descriptor = match kept {
                Some(kept) => DelayLoadDescriptor {
                    attributes: 1,
                    dll_name_rva,
                    import_name_table_rva,
                    ..*kept
                },
                None => DelayLoadDescriptor {
                    attributes: 1,
                    dll_name_rva,
                    module_handle_rva: self.rva_at(handle_start, handle.position())?,
                    import_address_table_rva: self.rva_at(iat_start, iat.position())?,
                    import_name_table_rva,
                    bound_import_address_table_rva: 0,
                    unload_information_table_rva: 0,
                    time_date_stamp: 0,
                },
            };
            desc.write_all(&descriptor.to_array())?;

            // Write the DLL name. The zeroed buffer supplies the null terminator.
            dll_name.write_all(dll.name.as_bytes())?;
            dll_name.seek_relative(1)?;

            // Write the INT entries, the new IAT entries and the hint/name entries.
            for import in &dll.imports {
                let (by_ordinal, thunk_value) = match import {
                    ImportThunk::Ordinal(ord) => (true, u32::from(*ord)),
                    ImportThunk::Name { hint, name } => {
                        // Write the hint/name entry: hint, name, null terminator,
                        // and padding to an even offset in the part.
                        let hint_name_rva = self.rva_at(hint_name_start, hint_name.position())?;
                        hint_name.write_u16_le(*hint)?;
                        hint_name.write_all(name.as_bytes())?;
                        hint_name.seek_relative(1)?;
                        skip_to_even(&mut hint_name)?;

                        (false, hint_name_rva)
                    }
                };
                if kept.is_none() {
                    // A placeholder: the caller must write the VA of a load stub.
                    self.write_thunk(&mut iat, by_ordinal, thunk_value)?;
                }
                self.write_thunk(&mut name_table, by_ordinal, thunk_value)?;
            }

            // Skip the null terminators of the IAT and the INT, and the zeroed module handle.
            name_table.seek_relative(thunk_skip)?;
            if kept.is_none() {
                iat.seek_relative(thunk_skip)?;
                handle.seek_relative(thunk_skip)?;
            }
        }

        // The null terminator descriptor is already zero.

        Ok(data)
    }

    /// Size of one thunk or module handle: 8 bytes for PE32+, 4 bytes for PE32.
    fn thunk_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Return the size of one thunk or module handle as a cursor offset.
    fn thunk_skip(&self) -> i64 {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Return the RVA of byte `position` in the part that starts at byte `start` of the built
    /// delay import data.
    fn rva_at(&self, start: usize, position: u64) -> Result<u32> {
        u32::try_from(start)
            .ok()
            .zip(u32::try_from(position).ok())
            .and_then(|(start, position)| start.checked_add(position))
            .and_then(|offset| self.base_rva.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory("delay-import RVA overflow"))
    }

    /// Write one IAT/INT thunk at `cursor`: an ordinal (with the ordinal flag
    /// set) or a hint/name RVA, sized for PE32 or PE32+.
    fn write_thunk(
        &self,
        cursor: &mut Cursor<&mut [u8]>,
        by_ordinal: bool,
        value: u32,
    ) -> Result<()> {
        if self.is_64bit {
            let flag = if by_ordinal { IMAGE_ORDINAL_FLAG64 } else { 0 };
            cursor.write_u64_le(flag | u64::from(value))?;
        } else {
            let flag = if by_ordinal { IMAGE_ORDINAL_FLAG32 } else { 0 };
            cursor.write_u32_le(flag | value)?;
        }
        Ok(())
    }
}

/// Validate the function names of `dlls`, and return the size of their hint/name entries.
fn hint_names_size(dlls: &[DelayLoadedDll]) -> Result<usize> {
    let mut size = 0usize;
    for import in dlls.iter().flat_map(|dll| &dll.imports) {
        if let ImportThunk::Name { name, .. } = import {
            if name.is_empty() || name.as_bytes().contains(&0) {
                return Err(Error::invalid_data_directory(
                    "delay-import names must be nonempty and contain no NUL bytes",
                ));
            }
            // Each entry: 2-byte hint, name, null terminator, padding to an even size.
            let entry_size = name
                .len()
                .checked_add(3)
                .and_then(|size| size.checked_next_multiple_of(2))
                .ok_or_else(|| Error::invalid_data_directory("delay-import name size overflow"))?;
            size = size
                .checked_add(entry_size)
                .ok_or_else(|| Error::invalid_data_directory("delay-import names size overflow"))?;
        }
    }
    Ok(size)
}

/// Offsets and sizes of the parts of a built delay-import table.
///
/// The parts are in this order: descriptors, new IATs, INT, new module handles,
/// hint/name entries, DLL names. The IAT starts at `descriptors_size`.
struct DelayImportLayout {
    /// Size of the descriptor array, with its null terminator.
    descriptors_size: usize,
    /// Offset of the INT in the built buffer.
    name_table_offset: usize,
    /// Offset of the module handles in the built buffer.
    handles_offset: usize,
    /// Offset of the first hint/name entry in the built buffer.
    hint_names_offset: usize,
    /// Offset of the first DLL name in the built buffer.
    dll_names_offset: usize,
    /// Size of the full table.
    total_size: usize,
    /// The kept descriptor of each DLL, or `None` for a DLL with new tables.
    kept: Vec<Option<DelayLoadDescriptor>>,
}
