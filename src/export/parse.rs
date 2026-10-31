//! Export table parsing.

use super::{
    ExportAddress, ExportDirectory, ExportTable, ExportedFunction, MAX_EXPORT_FUNCTIONS,
    MAX_NAME_LEN,
};
use crate::prelude::*;
use crate::{Error, Result};

impl ExportTable {
    /// Parse an export table from a PE file.
    ///
    /// - `export_rva` is the RVA from the data directory.
    /// - `export_size` is the size from the data directory. The parser uses it to find forwarders.
    /// - `read_at_rva` is a closure that reads bytes at an RVA.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - `export_size` is smaller than `IMAGE_EXPORT_DIRECTORY`.
    /// - The parser cannot read the directory, a table, a name or a forwarder string.
    /// - The function count is more than the safety limit, or less than the name count.
    /// - A table is outside the export directory range.
    /// - An RVA or an ordinal overflows.
    /// - A name refers to an empty slot in the address table.
    pub fn parse<F>(export_rva: u32, export_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if (export_size as usize) < ExportDirectory::SIZE {
            return Err(Error::invalid_data_directory(format!(
                "export directory is {} bytes, expected at least {}",
                export_size,
                ExportDirectory::SIZE
            )));
        }
        // Read the export directory.
        let dir_data =
            read_at_rva(export_rva, ExportDirectory::SIZE).ok_or(Error::invalid_rva(export_rva))?;
        let directory = ExportDirectory::parse(&dir_data)?;

        if directory.number_of_functions > MAX_EXPORT_FUNCTIONS {
            return Err(Error::invalid_data_directory(format!(
                "export function count {} exceeds the safety limit {}",
                directory.number_of_functions, MAX_EXPORT_FUNCTIONS
            )));
        }
        if directory.name_rva == 0 {
            return Err(Error::invalid_data_directory(
                "export directory has a null DLL name RVA",
            ));
        }

        // Read the DLL name.
        let dll_name = Self::read_string(
            &read_at_rva,
            directory.name_rva,
            export_rva,
            export_size,
            "export DLL name",
        )?;

        // Read the exports.
        let exports = Self::read_exports(&read_at_rva, &directory, export_rva, export_size)?;

        Ok(Self {
            directory,
            dll_name,
            exports,
        })
    }

    fn read_string<F>(
        read_at_rva: &F,
        rva: u32,
        export_rva: u32,
        export_size: u32,
        context: &str,
    ) -> Result<String>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        crate::parse_utils::read_c_string_in_range(
            read_at_rva,
            rva,
            export_rva,
            export_size,
            MAX_NAME_LEN,
            context,
        )
    }

    fn read_exports<F>(
        read_at_rva: &F,
        dir: &ExportDirectory,
        export_rva: u32,
        export_size: u32,
    ) -> Result<Vec<ExportedFunction>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let export_end = export_rva
            .checked_add(export_size)
            .ok_or_else(|| Error::invalid_data_directory("export directory RVA overflow"))?;
        Self::validate_tables(dir, export_rva, export_size)?;
        let mut exports =
            Self::read_address_table(read_at_rva, dir, export_rva, export_size, export_end)?;
        for index in 0..dir.number_of_names {
            Self::read_name_entry(
                read_at_rva,
                dir,
                index,
                export_rva,
                export_size,
                &mut exports,
            )?;
        }
        Ok(exports)
    }

    /// Check that the address table, the name pointer table and the ordinal table are all in
    /// the export directory range.
    ///
    /// The name count can be more than the function count, because many names (aliases) can
    /// refer to one function.
    fn validate_tables(dir: &ExportDirectory, export_rva: u32, export_size: u32) -> Result<()> {
        crate::parse_utils::bounded_table_range(
            dir.address_of_functions,
            dir.number_of_functions,
            4,
            export_rva,
            export_size,
            "export address table",
        )?;
        crate::parse_utils::bounded_table_range(
            dir.address_of_names,
            dir.number_of_names,
            4,
            export_rva,
            export_size,
            "export name-pointer table",
        )?;
        crate::parse_utils::bounded_table_range(
            dir.address_of_name_ordinals,
            dir.number_of_names,
            2,
            export_rva,
            export_size,
            "export ordinal table",
        )?;
        Ok(())
    }

    /// Read the export address table (EAT).
    ///
    /// The function skips empty slots. An entry that points into the export directory is a
    /// forwarder.
    fn read_address_table<F>(
        read_at_rva: &F,
        dir: &ExportDirectory,
        export_rva: u32,
        export_size: u32,
        export_end: u32,
    ) -> Result<Vec<ExportedFunction>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut exports = Vec::new();
        for i in 0..dir.number_of_functions {
            let addr_rva = dir
                .address_of_functions
                .checked_add(i.checked_mul(4).ok_or_else(|| {
                    Error::invalid_data_directory("export address-table offset overflow")
                })?)
                .ok_or_else(|| {
                    Error::invalid_data_directory("export address-table RVA overflow")
                })?;
            let func_rva = u32::from_le_bytes(read_array_rva(
                read_at_rva,
                addr_rva,
                "export address entry",
            )?);

            if func_rva == 0 {
                continue; // Empty slot.
            }

            let ordinal = dir
                .base
                .checked_add(i)
                .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?;

            // An RVA in the export directory range is a forwarder.
            let address = if func_rva >= export_rva && func_rva < export_end {
                let fwd_name = Self::read_string(
                    read_at_rva,
                    func_rva,
                    export_rva,
                    export_size,
                    "export forwarder",
                )?;
                ExportAddress::Forwarder(fwd_name)
            } else {
                ExportAddress::Rva(func_rva)
            };

            exports.push(ExportedFunction {
                ordinal,
                name: None,
                aliases: Vec::new(),
                address,
            });
        }
        Ok(exports)
    }

    /// Read entry `index` of the name pointer table and the ordinal table.
    ///
    /// The function attaches the name to the export that the entry refers to. If that export
    /// already has a name, the function adds the name as an alias.
    fn read_name_entry<F>(
        read_at_rva: &F,
        dir: &ExportDirectory,
        index: u32,
        export_rva: u32,
        export_size: u32,
        exports: &mut [ExportedFunction],
    ) -> Result<()>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        // Read the name RVA.
        let name_ptr_rva = dir
            .address_of_names
            .checked_add(index.checked_mul(4).ok_or_else(|| {
                Error::invalid_data_directory("export name-table offset overflow")
            })?)
            .ok_or_else(|| Error::invalid_data_directory("export name-table RVA overflow"))?;
        let name_rva = u32::from_le_bytes(read_array_rva(
            read_at_rva,
            name_ptr_rva,
            "export name pointer",
        )?);

        // Read the ordinal index.
        let ord_rva = dir
            .address_of_name_ordinals
            .checked_add(index.checked_mul(2).ok_or_else(|| {
                Error::invalid_data_directory("export ordinal-table offset overflow")
            })?)
            .ok_or_else(|| Error::invalid_data_directory("export ordinal-table RVA overflow"))?;
        let ord_index = u16::from_le_bytes(read_array_rva(read_at_rva, ord_rva, "export ordinal")?);

        // Read the name.
        let name = Self::read_string(
            read_at_rva,
            name_rva,
            export_rva,
            export_size,
            "export function name",
        )?;

        // Find the export that has this ordinal.
        let ordinal = dir
            .base
            .checked_add(u32::from(ord_index))
            .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?;
        let export = exports
            .iter_mut()
            .find(|export| export.ordinal == ordinal)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "export name references empty function slot {ord_index}"
                ))
            })?;
        if export.name.is_none() {
            export.name = Some(name);
        } else {
            export.aliases.push(name);
        }
        Ok(())
    }
}

/// Read exactly `N` bytes at `rva` through `read_at_rva`.
///
/// # Errors
///
/// Returns an error if the function cannot read the bytes.
fn read_array_rva<const N: usize, F>(read_at_rva: &F, rva: u32, context: &str) -> Result<[u8; N]>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let data = crate::parse_utils::read_exact_rva(read_at_rva, rva, N, context)?;
    data.first_chunk::<N>()
        .copied()
        .ok_or_else(|| Error::buffer_too_small(N, data.len()))
}
