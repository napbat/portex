//! Serialization of an import table.

use nostdio::{Cursor, Seek, Write, WriteLe};

use super::parts::{skip_to_even, split_parts};
use super::{
    IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, ImportDescriptor, ImportTable, ImportThunk,
    ImportedDll,
};
use crate::prelude::*;
use crate::{Error, Result};

/// Builder that serializes an import table to section data.
///
/// The built data has these parts, in this order: the descriptors, the import lookup tables
/// (ILT), the new import address tables (IAT), the hint/name entries and the DLL names.
///
/// # IAT keep rule
///
/// Code calls an imported function through its slot in the IAT. The loader writes the function
/// addresses into the IAT at `FirstThunk`. If the IAT moves, the old slots stay unresolved and
/// each call through them fails.
///
/// By default, the builder writes a new IAT for each DLL. Call [`Self::keep_unchanged_iats`]
/// with the table that the image holds now. Then the builder keeps `FirstThunk` for each DLL
/// whose function list is unchanged. Only the ILT, the names and the descriptor of that DLL
/// move. A new DLL, or a DLL whose function list changed, gets a new IAT. Code that uses the
/// old IAT of a changed DLL must be patched by the caller.
#[derive(Debug)]
pub struct ImportTableBuilder {
    /// If `true`, build for PE32+. If `false`, build for PE32.
    pub is_64bit: bool,
    /// RVA of the start of the built import data.
    pub base_rva: u32,
    /// The IATs that the builder can keep: the functions of each IAT, keyed by its RVA.
    existing_iats: BTreeMap<u32, Vec<ImportThunk>>,
}

impl ImportTableBuilder {
    /// Create a new builder. The builder writes a new IAT for each DLL.
    #[must_use]
    pub fn new(is_64bit: bool, base_rva: u32) -> Self {
        Self {
            is_64bit,
            base_rva,
            existing_iats: BTreeMap::new(),
        }
    }

    /// Keep the IAT of each DLL whose function list is the same as in `existing`.
    ///
    /// `existing` is the import table that the image holds now, for example from
    /// [`crate::PeImage::imports`]. The builder keeps the `descriptor.first_thunk` of a DLL in
    /// the built table if `existing` has a DLL with the same nonzero `first_thunk` and the same
    /// `imports`. The IAT then keeps its address and its entry count. Each existing IAT is kept
    /// for one DLL only. See the IAT keep rule in the type docs.
    #[must_use]
    pub fn keep_unchanged_iats(mut self, existing: &ImportTable) -> Self {
        for dll in existing.dlls.iter().rev() {
            if dll.descriptor.first_thunk != 0 {
                self.existing_iats
                    .insert(dll.descriptor.first_thunk, dll.imports.clone());
            }
        }
        self
    }

    /// Calculate the total size of the import section.
    ///
    /// The size depends on [`Self::is_64bit`] and on the kept IATs, so this is a method and not
    /// an associated function.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(&self, table: &ImportTable) -> usize {
        self.try_calculate_size(table)
            .expect("import table size overflow: use try_calculate_size()")
    }

    /// Calculate the serialized size. Use checked arithmetic and validate the
    /// names.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error if a DLL name or a function name
    /// is empty or contains NUL. Also returns this error if a size computation
    /// overflows `usize`.
    pub fn try_calculate_size(&self, table: &ImportTable) -> Result<usize> {
        if table.dlls.is_empty() {
            return Ok(0);
        }
        Ok(self.layout(table)?.total_size)
    }

    /// Return the kept IAT RVA of each DLL in `table`, or `None` for a DLL that gets a new IAT.
    fn kept_iats(&self, table: &ImportTable) -> Vec<Option<u32>> {
        let mut used = BTreeSet::new();
        let mut kept = Vec::with_capacity(table.dlls.len());
        for dll in &table.dlls {
            let first_thunk = dll.descriptor.first_thunk;
            let keep = first_thunk != 0
                && self
                    .existing_iats
                    .get(&first_thunk)
                    .is_some_and(|imports| *imports == dll.imports)
                && used.insert(first_thunk);
            kept.push(keep.then_some(first_thunk));
        }
        kept
    }

    /// Validate the names in `table` and calculate the layout of the built
    /// table. Do not call this function for an empty table.
    fn layout(&self, table: &ImportTable) -> Result<ImportLayout> {
        let thunk_size = self.thunk_size();
        let kept = self.kept_iats(table);

        // Import descriptors: one for each DLL, plus a null terminator. For PE32+, the ILT and
        // the IAT that follow must have 8-byte alignment.
        let descriptors_size = table
            .dlls
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(ImportDescriptor::SIZE))
            .and_then(|size| size.checked_next_multiple_of(thunk_size))
            .ok_or_else(|| Error::invalid_data_directory("import descriptor size overflow"))?;

        // The ILT has the thunks of each DLL plus a null terminator for each DLL. The new IAT
        // has the same entries for each DLL that does not keep its IAT.
        let count_error = || Error::invalid_data_directory("import thunk count overflow");
        let mut lookup_count = 0usize;
        let mut iat_count = 0usize;
        for (dll, kept) in table.dlls.iter().zip(&kept) {
            if dll.name.is_empty() || dll.name.as_bytes().contains(&0) {
                return Err(Error::invalid_data_directory(
                    "import DLL names must be nonempty and contain no NUL bytes",
                ));
            }
            let entries = dll.imports.len().checked_add(1).ok_or_else(count_error)?;
            lookup_count = lookup_count.checked_add(entries).ok_or_else(count_error)?;
            if kept.is_none() {
                iat_count = iat_count.checked_add(entries).ok_or_else(count_error)?;
            }
        }
        let table_error = || Error::invalid_data_directory("import thunk table size overflow");
        let lookup_table_size = lookup_count
            .checked_mul(thunk_size)
            .ok_or_else(table_error)?;
        let iat_size = iat_count.checked_mul(thunk_size).ok_or_else(table_error)?;

        let hint_names_size = hint_names_size(&table.dlls)?;

        // DLL names.
        let mut dll_names_size = 0usize;
        for dll in &table.dlls {
            dll_names_size = dll_names_size
                .checked_add(dll.name.len().checked_add(1).ok_or_else(|| {
                    Error::invalid_data_directory("import DLL name size overflow")
                })?)
                .ok_or_else(|| Error::invalid_data_directory("import DLL names size overflow"))?;
        }

        let overflow = || Error::invalid_data_directory("import table size overflow");
        let iat_offset = descriptors_size
            .checked_add(lookup_table_size)
            .ok_or_else(overflow)?;
        let hint_names_offset = iat_offset.checked_add(iat_size).ok_or_else(overflow)?;
        let dll_names_offset = hint_names_offset
            .checked_add(hint_names_size)
            .ok_or_else(overflow)?;
        let total_size = dll_names_offset
            .checked_add(dll_names_size)
            .ok_or_else(overflow)?;
        Ok(ImportLayout {
            descriptors_size,
            iat_offset,
            iat_size,
            hint_names_offset,
            dll_names_offset,
            total_size,
            kept,
        })
    }

    /// Build the import section data and return `(section_data, iat_rva, iat_size)`.
    ///
    /// The IAT range starts at the first IAT and ends at the end of the last IAT. It includes
    /// the new IATs in `section_data` and the kept IATs. Use it to update the IAT data
    /// directory.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self, table: &ImportTable) -> (Vec<u8>, u32, u32) {
        self.try_build(table)
            .expect("import table build failed: use try_build() for fallible serialization")
    }

    /// Build the import table with checked offsets and sizes.
    ///
    /// Return `(section_data, iat_rva, iat_size)`, as [`Self::build`] does.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`]. Also returns an
    /// invalid-data-directory error if one of these conditions occurs:
    ///
    /// - The table is larger than `u32`.
    /// - The RVA range of the table overflows.
    /// - For PE32, an RVA reaches the ordinal flag bit.
    /// - A kept IAT overlaps the built data, or its RVA range overflows.
    pub fn try_build(&self, table: &ImportTable) -> Result<(Vec<u8>, u32, u32)> {
        if table.dlls.is_empty() {
            return Ok((Vec::new(), 0, 0));
        }
        let layout = self.layout(table)?;
        let size = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("import table exceeds u32"))?;
        let end = self
            .base_rva
            .checked_add(size)
            .ok_or_else(|| Error::invalid_data_directory("import table RVA range overflow"))?;
        if !self.is_64bit && end > IMAGE_ORDINAL_FLAG32 {
            return Err(Error::invalid_data_directory(
                "PE32 import hint/name RVAs would overlap the ordinal flag",
            ));
        }

        // The IAT range: the new IATs, then each kept IAT.
        let mut iat_range = if layout.iat_size == 0 {
            None
        } else {
            let start = self.rva_at(layout.iat_offset, 0)?;
            Some((start, self.rva_at(layout.hint_names_offset, 0)?))
        };
        for (dll, kept) in table.dlls.iter().zip(&layout.kept) {
            let Some(start) = *kept else {
                continue;
            };
            let iat_end = dll
                .imports
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(self.thunk_size()))
                .and_then(|size| u32::try_from(size).ok())
                .and_then(|size| start.checked_add(size))
                .ok_or_else(|| Error::invalid_data_directory("kept IAT RVA range overflow"))?;
            if start < end && self.base_rva < iat_end {
                return Err(Error::invalid_data_directory(
                    "a kept IAT overlaps the built import table",
                ));
            }
            iat_range = Some(match iat_range {
                Some((first, last)) => (first.min(start), last.max(iat_end)),
                None => (start, iat_end),
            });
        }
        let (iat_rva, iat_end) = iat_range.unwrap_or_default();

        let data = self.write_table(table, &layout)?;
        Ok((data, iat_rva, iat_end - iat_rva))
    }

    /// Serialize `table` into a new buffer with the parts at the offsets in
    /// `layout`.
    fn write_table(&self, table: &ImportTable, layout: &ImportLayout) -> Result<Vec<u8>> {
        let thunk_skip = self.thunk_skip();
        let mut data = vec![0u8; layout.total_size];

        // The parts are in this order: descriptors, ILT, IAT, hint/name
        // entries, DLL names. The ILT starts after the descriptors.
        let starts = [
            0,
            layout.descriptors_size,
            layout.iat_offset,
            layout.hint_names_offset,
            layout.dll_names_offset,
        ];
        let [_, lookup_start, iat_start, hint_name_start, dll_name_start] = starts;
        let [mut desc, mut lookup, mut iat, mut hint_name, mut dll_name] =
            split_parts(&mut data, starts)?;

        for (dll, kept) in table.dlls.iter().zip(&layout.kept) {
            // Write the DLL name. The zeroed buffer supplies the null terminator.
            let dll_name_rva = self.rva_at(dll_name_start, dll_name.position())?;
            dll_name.write_all(dll.name.as_bytes())?;
            dll_name.seek_relative(1)?;

            // Write the thunks: the ILT, and the IAT if the DLL gets a new IAT.
            let lookup_table_rva = self.rva_at(lookup_start, lookup.position())?;
            let first_thunk_rva = match kept {
                Some(rva) => *rva,
                None => self.rva_at(iat_start, iat.position())?,
            };

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

                // A new IAT holds the same thunks as the ILT until the loader binds it.
                self.write_thunk(&mut lookup, by_ordinal, thunk_value)?;
                if kept.is_none() {
                    self.write_thunk(&mut iat, by_ordinal, thunk_value)?;
                }
            }

            // Skip the null terminator of each thunk table.
            lookup.seek_relative(thunk_skip)?;
            if kept.is_none() {
                iat.seek_relative(thunk_skip)?;
            }

            // Write the import descriptor.
            let descriptor = ImportDescriptor {
                original_first_thunk: lookup_table_rva,
                time_date_stamp: 0,
                forwarder_chain: 0,
                name_rva: dll_name_rva,
                first_thunk: first_thunk_rva,
            };
            desc.write_all(&descriptor.to_array())?;
        }

        // The null terminator descriptor is already zero.
        Ok(data)
    }

    /// Size of one ILT/IAT thunk: 8 bytes for PE32+, 4 bytes for PE32.
    fn thunk_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Return the size of one ILT/IAT thunk as a cursor offset.
    fn thunk_skip(&self) -> i64 {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Return the RVA of byte `position` in the part that starts at byte `start` of the built
    /// import data.
    fn rva_at(&self, start: usize, position: u64) -> Result<u32> {
        u32::try_from(start)
            .ok()
            .zip(u32::try_from(position).ok())
            .and_then(|(start, position)| start.checked_add(position))
            .and_then(|offset| self.base_rva.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory("import table RVA overflow"))
    }

    /// Write one ILT/IAT thunk at `cursor`: an ordinal (with the ordinal flag
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
fn hint_names_size(dlls: &[ImportedDll]) -> Result<usize> {
    let mut size = 0usize;
    for import in dlls.iter().flat_map(|dll| &dll.imports) {
        if let ImportThunk::Name { name, .. } = import {
            if name.is_empty() || name.as_bytes().contains(&0) {
                return Err(Error::invalid_data_directory(
                    "import names must be nonempty and contain no NUL bytes",
                ));
            }
            // Each entry: 2-byte hint, name, null terminator, padding to an even size.
            let entry_size = name
                .len()
                .checked_add(3)
                .and_then(|size| size.checked_next_multiple_of(2))
                .ok_or_else(|| Error::invalid_data_directory("import name size overflow"))?;
            size = size
                .checked_add(entry_size)
                .ok_or_else(|| Error::invalid_data_directory("import names size overflow"))?;
        }
    }
    Ok(size)
}

/// Offsets and sizes of the parts of a built import table.
///
/// The parts are in this order: descriptors, ILT, new IATs, hint/name entries,
/// DLL names. The ILT starts at `descriptors_size`.
struct ImportLayout {
    /// Size of the descriptor array, with its null terminator and the alignment padding.
    descriptors_size: usize,
    /// Offset of the new IATs in the built buffer.
    iat_offset: usize,
    /// Size of the new IATs. It is 0 if all DLLs keep their IAT.
    iat_size: usize,
    /// Offset of the first hint/name entry in the built buffer.
    hint_names_offset: usize,
    /// Offset of the first DLL name in the built buffer.
    dll_names_offset: usize,
    /// Size of the full table.
    total_size: usize,
    /// The kept IAT RVA of each DLL, or `None` for a DLL with a new IAT.
    kept: Vec<Option<u32>>,
}
