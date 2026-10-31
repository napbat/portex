//! Export table building.

use super::{ExportAddress, ExportDirectory, ExportTable, MAX_EXPORT_FUNCTIONS};
use crate::prelude::*;
use crate::{Error, Result};

/// Serialize an export table to section data.
#[derive(Debug)]
pub struct ExportTableBuilder {
    /// The RVA at which the export data starts.
    pub base_rva: u32,
}

impl ExportTableBuilder {
    /// Create a builder for export data at the RVA `base_rva`.
    #[must_use]
    pub fn new(base_rva: u32) -> Self {
        Self { base_rva }
    }

    /// Calculate the total size of the export data.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] returns an error.
    #[must_use]
    pub fn calculate_size(table: &ExportTable) -> usize {
        Self::try_calculate_size(table)
            .expect("export table size overflow: use try_calculate_size()")
    }

    /// Calculate the serialized size of the export data.
    ///
    /// The function also validates sparse ordinals, names and all intermediate offsets.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - An export ordinal is below the ordinal base, or two exports have the same ordinal.
    /// - The ordinal index of a named export does not fit in `u16`.
    /// - The sparse address table is larger than the safety limit.
    /// - A name or a forwarder contains a NUL byte.
    /// - A size overflows.
    pub fn try_calculate_size(table: &ExportTable) -> Result<usize> {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return Ok(0);
        }
        Ok(export_layout(table)?.total_size)
    }

    /// Build the export data and returns (`section_data`, `export_size`).
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] returns an error.
    #[must_use]
    pub fn build(&self, table: &ExportTable) -> (Vec<u8>, u32) {
        self.try_build(table)
            .expect("export table build failed: use try_build() for fallible serialization")
    }

    /// Build the export data.
    ///
    /// The function keeps sparse EAT slots and all names of each ordinal.
    ///
    /// It returns the serialized export data and its size in bytes. The data holds, in this
    /// order:
    /// 1. The directory.
    /// 2. The address table.
    /// 3. The name pointer table and the ordinal table.
    /// 4. The strings.
    ///
    /// # Errors
    ///
    /// Returns an error for each condition of [`Self::try_calculate_size`]. Also returns an
    /// error if the serialized size, or an RVA in the range that starts at `base_rva`, does not
    /// fit in `u32`.
    pub fn try_build(&self, table: &ExportTable) -> Result<(Vec<u8>, u32)> {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let layout = export_layout(table)?;
        let dimensions = layout.dimensions;
        let total_size_u32 = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("export table exceeds u32"))?;
        self.base_rva
            .checked_add(total_size_u32)
            .ok_or_else(|| Error::invalid_data_directory("export table RVA range overflow"))?;
        let mut data = vec![0u8; layout.total_size];

        let dll_name_rva = checked_rva(self.base_rva, layout.dll_name_offset, "export DLL name")?;
        put_c_string(&mut data, layout.dll_name_offset, &table.dll_name)?;
        let (mut names, string_pos) = self.write_names(&mut data, table, &layout)?;
        let eat_entries = self.write_forwarders(&mut data, table, &layout, string_pos)?;

        // Sort the named exports by name, so that a binary search can find them.
        names.sort_by(|left, right| left.name.cmp(right.name));
        write_tables(&mut data, &layout, &eat_entries, &names)?;

        // Build and write the directory.
        let directory = ExportDirectory {
            characteristics: table.directory.characteristics,
            time_date_stamp: table.directory.time_date_stamp,
            major_version: table.directory.major_version,
            minor_version: table.directory.minor_version,
            name_rva: dll_name_rva,
            base: table.directory.base,
            number_of_functions: u32::try_from(dimensions.function_count)
                .map_err(|_| Error::invalid_data_directory("export function count exceeds u32"))?,
            number_of_names: u32::try_from(dimensions.named_count)
                .map_err(|_| Error::invalid_data_directory("export name count exceeds u32"))?,
            address_of_functions: if dimensions.function_count > 0 {
                checked_rva(self.base_rva, ExportDirectory::SIZE, "export address table")?
            } else {
                0
            },
            address_of_names: if dimensions.named_count > 0 {
                checked_rva(self.base_rva, layout.name_ptr_offset, "export name table")?
            } else {
                0
            },
            address_of_name_ordinals: if dimensions.named_count > 0 {
                checked_rva(
                    self.base_rva,
                    layout.ordinal_table_offset,
                    "export ordinal table",
                )?
            } else {
                0
            },
        };
        directory.write(&mut data)?;

        Ok((data, total_size_u32))
    }

    /// Write each function name and alias at the start of the string area.
    ///
    /// Returns one entry for each written name, in table order. Also returns the offset after
    /// the last name.
    fn write_names<'a>(
        &self,
        data: &mut [u8],
        table: &'a ExportTable,
        layout: &ExportLayout,
    ) -> Result<(Vec<NameEntry<'a>>, usize)> {
        let mut string_pos = layout.strings_offset;
        let mut names = Vec::with_capacity(layout.dimensions.named_count);
        for export in &table.exports {
            if export.name.is_none() && export.aliases.is_empty() {
                continue;
            }
            let eat_index = export
                .ordinal
                .checked_sub(table.directory.base)
                .and_then(|index| u16::try_from(index).ok())
                .ok_or_else(|| {
                    Error::invalid_data_directory(
                        "named export ordinal index does not fit the u16 name table",
                    )
                })?;
            for name in export.name.iter().chain(export.aliases.iter()) {
                let rva = checked_rva(self.base_rva, string_pos, "export name")?;
                string_pos = put_c_string(data, string_pos, name)?;
                names.push(NameEntry {
                    name: name.as_str(),
                    eat_index,
                    rva,
                });
            }
        }
        Ok((names, string_pos))
    }

    /// Write the forwarder strings, starting at offset `string_pos`.
    ///
    /// Returns the sparse EAT. Each slot holds a function RVA, a forwarder string RVA, or 0 for
    /// an empty slot.
    fn write_forwarders(
        &self,
        data: &mut [u8],
        table: &ExportTable,
        layout: &ExportLayout,
        mut string_pos: usize,
    ) -> Result<Vec<u32>> {
        let mut eat_entries = vec![0u32; layout.dimensions.function_count];
        for export in &table.exports {
            let slot = export
                .ordinal
                .checked_sub(table.directory.base)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| eat_entries.get_mut(index))
                .ok_or_else(|| Error::invalid_data_directory("export ordinal index overflow"))?;
            *slot = match &export.address {
                ExportAddress::Rva(rva) => *rva,
                ExportAddress::Forwarder(fwd) => {
                    let fwd_rva = checked_rva(self.base_rva, string_pos, "export forwarder")?;
                    string_pos = put_c_string(data, string_pos, fwd)?;
                    fwd_rva
                }
            };
        }
        Ok(eat_entries)
    }
}

/// Byte offsets of the parts of a serialized export table.
///
/// The EAT starts at [`ExportDirectory::SIZE`]. The other parts follow in
/// field order. Each offset is at most `total_size`.
#[derive(Debug, Clone, Copy)]
struct ExportLayout {
    dimensions: ExportDimensions,
    name_ptr_offset: usize,
    ordinal_table_offset: usize,
    dll_name_offset: usize,
    strings_offset: usize,
    total_size: usize,
}

/// Calculate the layout of the serialized export table with checked arithmetic.
fn export_layout(table: &ExportTable) -> Result<ExportLayout> {
    let dimensions = export_dimensions(table)?;
    let eat_size = dimensions
        .function_count
        .checked_mul(4)
        .ok_or_else(|| Error::invalid_data_directory("export address-table size overflow"))?;
    let name_ptr_size = dimensions
        .named_count
        .checked_mul(4)
        .ok_or_else(|| Error::invalid_data_directory("export name-table size overflow"))?;
    let ordinal_size = dimensions
        .named_count
        .checked_mul(2)
        .ok_or_else(|| Error::invalid_data_directory("export ordinal-table size overflow"))?;
    let dll_name_size = checked_string_size(&table.dll_name, "export DLL name")?;

    let mut names_size = 0usize;
    let mut forwarders_size = 0usize;
    for export in &table.exports {
        for name in export.name.iter().chain(export.aliases.iter()) {
            names_size = names_size
                .checked_add(checked_string_size(name, "export name")?)
                .ok_or_else(|| Error::invalid_data_directory("export names size overflow"))?;
        }
        if let ExportAddress::Forwarder(forwarder) = &export.address {
            forwarders_size = forwarders_size
                .checked_add(checked_string_size(forwarder, "export forwarder")?)
                .ok_or_else(|| Error::invalid_data_directory("export forwarder size overflow"))?;
        }
    }

    let overflow = || Error::invalid_data_directory("export table size overflow");
    let name_ptr_offset = ExportDirectory::SIZE
        .checked_add(eat_size)
        .ok_or_else(overflow)?;
    let ordinal_table_offset = name_ptr_offset
        .checked_add(name_ptr_size)
        .ok_or_else(overflow)?;
    let dll_name_offset = ordinal_table_offset
        .checked_add(ordinal_size)
        .ok_or_else(overflow)?;
    let strings_offset = dll_name_offset
        .checked_add(dll_name_size)
        .ok_or_else(overflow)?;
    let total_size = strings_offset
        .checked_add(names_size)
        .and_then(|size| size.checked_add(forwarders_size))
        .ok_or_else(overflow)?;
    Ok(ExportLayout {
        dimensions,
        name_ptr_offset,
        ordinal_table_offset,
        dll_name_offset,
        strings_offset,
        total_size,
    })
}

/// A function name that `ExportTableBuilder` wrote to the string area.
#[derive(Debug, Clone, Copy)]
struct NameEntry<'a> {
    /// The function name.
    name: &'a str,
    /// The index of the function in the EAT.
    eat_index: u16,
    /// The RVA of the name string.
    rva: u32,
}

/// Write the EAT, the name pointer table and the ordinal table.
///
/// Sort `names` by name before you call this function.
fn write_tables(
    data: &mut [u8],
    layout: &ExportLayout,
    eat_entries: &[u32],
    names: &[NameEntry<'_>],
) -> Result<()> {
    let eat = table_region(data, ExportDirectory::SIZE, layout.name_ptr_offset)?;
    for (slot, rva) in eat.as_chunks_mut::<4>().0.iter_mut().zip(eat_entries) {
        *slot = rva.to_le_bytes();
    }
    let name_ptrs = table_region(data, layout.name_ptr_offset, layout.ordinal_table_offset)?;
    for (slot, entry) in name_ptrs.as_chunks_mut::<4>().0.iter_mut().zip(names) {
        *slot = entry.rva.to_le_bytes();
    }
    let ordinals = table_region(data, layout.ordinal_table_offset, layout.dll_name_offset)?;
    for (slot, entry) in ordinals.as_chunks_mut::<2>().0.iter_mut().zip(names) {
        *slot = entry.eat_index.to_le_bytes();
    }
    Ok(())
}

/// Get the bytes from `start` to `end` of `data`.
///
/// # Errors
///
/// Returns [`Error::buffer_too_small`] if the range is not in `data`.
fn table_region(data: &mut [u8], start: usize, end: usize) -> Result<&mut [u8]> {
    let len = data.len();
    data.get_mut(start..end)
        .ok_or_else(|| Error::buffer_too_small(end, len))
}

/// Copy `value` and a NUL terminator into `data` at `offset`.
///
/// Returns the offset after the terminator.
///
/// # Errors
///
/// Returns an error if the string does not fit in `data`.
fn put_c_string(data: &mut [u8], offset: usize, value: &str) -> Result<usize> {
    let end = offset
        .checked_add(value.len())
        .and_then(|end| end.checked_add(1))
        .ok_or_else(|| Error::invalid_data_directory("export string offset overflow"))?;
    let len = data.len();
    let Some((terminator, text)) = data.get_mut(offset..end).and_then(<[u8]>::split_last_mut)
    else {
        return Err(Error::buffer_too_small(end, len));
    };
    text.copy_from_slice(value.as_bytes());
    *terminator = 0;
    Ok(end)
}

#[derive(Debug, Clone, Copy)]
struct ExportDimensions {
    function_count: usize,
    named_count: usize,
}

fn export_dimensions(table: &ExportTable) -> Result<ExportDimensions> {
    let mut ordinals = BTreeSet::new();
    let mut function_count = 0usize;
    let mut named_count = 0usize;
    for export in &table.exports {
        let index = export
            .ordinal
            .checked_sub(table.directory.base)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "export ordinal {} is below base {}",
                    export.ordinal, table.directory.base
                ))
            })?;
        if !ordinals.insert(export.ordinal) {
            return Err(Error::invalid_data_directory(format!(
                "duplicate export ordinal {} (use aliases for multiple names)",
                export.ordinal
            )));
        }
        let index_usize = usize::try_from(index)
            .map_err(|_| Error::invalid_data_directory("export ordinal index overflow"))?;
        function_count = function_count.max(
            index_usize
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("export function count overflow"))?,
        );
        let names_for_export = usize::from(export.name.is_some())
            .checked_add(export.aliases.len())
            .ok_or_else(|| Error::invalid_data_directory("export name count overflow"))?;
        if names_for_export != 0 && index > u32::from(u16::MAX) {
            return Err(Error::invalid_data_directory(format!(
                "named export ordinal {} is too far above base {}",
                export.ordinal, table.directory.base
            )));
        }
        named_count = named_count
            .checked_add(names_for_export)
            .ok_or_else(|| Error::invalid_data_directory("export name count overflow"))?;
    }
    if function_count > MAX_EXPORT_FUNCTIONS as usize {
        return Err(Error::invalid_data_directory(format!(
            "sparse export table needs {function_count} slots, exceeding the safety limit {MAX_EXPORT_FUNCTIONS}"
        )));
    }
    Ok(ExportDimensions {
        function_count,
        named_count,
    })
}

fn checked_string_size(value: &str, context: &str) -> Result<usize> {
    if value.as_bytes().contains(&0) {
        return Err(Error::invalid_data_directory(format!(
            "{context} contains an embedded NUL byte"
        )));
    }
    value
        .len()
        .checked_add(1)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))
}

fn checked_rva(base: u32, offset: usize, context: &str) -> Result<u32> {
    let offset = u32::try_from(offset)
        .map_err(|_| Error::invalid_data_directory(format!("{context} offset exceeds u32")))?;
    base.checked_add(offset)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))
}
