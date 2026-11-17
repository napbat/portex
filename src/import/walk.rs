//! Bounded reads of thunk tables, hint/name entries and DLL names.
//!
//! The import and delay-import parsers share this walker. It limits the output of one parse:
//!
//! - The thunks of all descriptors together are at most [`MAX_TOTAL_THUNKS`].
//! - The name bytes are limited by a [`NameBudget`].
//!
//! It also keeps each thunk table, hint/name entry and DLL name that it read, by RVA. A table
//! or a name that many descriptors or thunks share is thus read only one time.

use core::mem::offset_of;

use super::budget::{MAX_NAME_LEN, NameBudget};
use super::{
    IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, ImageImportByName, ImportThunk, thunk_at,
    thunk_size,
};
use crate::parse_utils::u16_at;
use crate::prelude::*;
use crate::{Error, Result};

/// The maximum number of thunks of all descriptors in one parse.
pub(crate) const MAX_TOTAL_THUNKS: usize = 1_048_576;

/// The number of bytes of the first read of a name.
const FIRST_NAME_CHUNK: usize = 64;
/// The number of thunks of the first read of a thunk table.
const FIRST_THUNK_CHUNK: usize = 16;
/// The maximum number of thunks in one read of a thunk table.
const MAX_THUNK_CHUNK: usize = 512;

/// The format of the named entries of a thunk table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NameAddress {
    /// The entries hold RVAs of the hint/name entries.
    Rva,
    /// The entries hold VAs of the hint/name entries, for this image base. Legacy (version 1)
    /// delay-import tables use this format.
    Va(u64),
}

/// A thunk table that the walker read, and the number of name bytes in it.
#[derive(Debug)]
struct ThunkList {
    thunks: Vec<ImportThunk>,
    name_bytes: usize,
}

/// A reader of thunk tables and names with a total budget. See the module docs.
pub(crate) struct ThunkWalker<'r, F> {
    read: &'r F,
    is_64bit: bool,
    /// The table type for the error messages, for example `import` or `delay-import`.
    context: &'static str,
    thunks_left: usize,
    names: NameBudget,
    lists: BTreeMap<(u32, NameAddress), ThunkList>,
    hint_names: BTreeMap<u32, (u16, String)>,
    dll_names: BTreeMap<u32, String>,
}

impl<'r, F> ThunkWalker<'r, F>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    /// Make a walker that reads through `read`.
    pub(crate) fn new(read: &'r F, is_64bit: bool, context: &'static str) -> Self {
        Self {
            read,
            is_64bit,
            context,
            thunks_left: MAX_TOTAL_THUNKS,
            names: NameBudget::default(),
            lists: BTreeMap::new(),
            hint_names: BTreeMap::new(),
            dll_names: BTreeMap::new(),
        }
    }

    /// Read the null-terminated DLL name at `rva`.
    ///
    /// # Errors
    ///
    /// Returns an error if the name cannot be read, has more than [`MAX_NAME_LEN`] bytes, is
    /// not UTF-8, or goes past the name budget.
    pub(crate) fn dll_name(&mut self, rva: u32) -> Result<String> {
        let name = if let Some(name) = self.dll_names.get(&rva) {
            name.clone()
        } else {
            let bytes = read_terminated(self.read, rva, 0, self.context)?;
            self.names
                .add_source(u64::from(rva), bytes.len().saturating_add(1));
            let name = String::from_utf8(bytes).map_err(|_| Error::invalid_utf8())?;
            self.dll_names.insert(rva, name.clone());
            name
        };
        self.names.charge(name.len(), self.context)?;
        Ok(name)
    }

    /// Read the zero-terminated thunk table at `rva`.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    ///
    /// - A thunk or a name cannot be read.
    /// - A named thunk has a null hint/name RVA, or an address that is not in the image.
    /// - The thunks of all tables are more than [`MAX_TOTAL_THUNKS`].
    /// - The names go past the name budget.
    pub(crate) fn thunks(&mut self, rva: u32, names: NameAddress) -> Result<Vec<ImportThunk>> {
        if let Some(list) = self.lists.get(&(rva, names)) {
            self.thunks_left = self
                .thunks_left
                .checked_sub(list.thunks.len())
                .ok_or_else(|| self.too_many_thunks())?;
            self.names.charge(list.name_bytes, self.context)?;
            return Ok(list.thunks.clone());
        }
        let list = self.read_list(rva, names)?;
        let thunks = list.thunks.clone();
        self.lists.insert((rva, names), list);
        Ok(thunks)
    }

    fn too_many_thunks(&self) -> Error {
        Error::invalid_data_directory(format!(
            "{} thunk tables have more than {MAX_TOTAL_THUNKS} entries in total",
            self.context
        ))
    }

    fn read_list(&mut self, rva: u32, names: NameAddress) -> Result<ThunkList> {
        let unit = thunk_size(self.is_64bit);
        let mut list = ThunkList {
            thunks: Vec::new(),
            name_bytes: 0,
        };
        let mut offset = 0u32;
        let mut chunk = FIRST_THUNK_CHUNK;
        loop {
            let at = rva.checked_add(offset).ok_or_else(|| {
                Error::invalid_data_directory(format!("{} thunk RVA overflow", self.context))
            })?;
            // Do not read more entries than the budget permits, plus the terminator.
            let want = chunk.min(self.thunks_left.saturating_add(1));
            let bytes = read_chunk(self.read, at, want.saturating_mul(unit), unit)
                .ok_or_else(|| Error::invalid_rva(at))?;
            for entry in bytes.chunks_exact(unit) {
                let value = thunk_at(entry, 0, self.is_64bit)
                    .ok_or_else(|| Error::buffer_too_small(unit, entry.len()))?;
                if value == 0 {
                    return Ok(list);
                }
                self.thunks_left = self
                    .thunks_left
                    .checked_sub(1)
                    .ok_or_else(|| self.too_many_thunks())?;
                let thunk = self.thunk(value, names)?;
                if let ImportThunk::Name { name, .. } = &thunk {
                    list.name_bytes = list.name_bytes.saturating_add(name.len());
                }
                list.thunks.push(thunk);
            }
            offset = u32::try_from(bytes.len())
                .ok()
                .and_then(|len| offset.checked_add(len))
                .ok_or_else(|| {
                    Error::invalid_data_directory(format!(
                        "{} thunk table size overflow",
                        self.context
                    ))
                })?;
            chunk = (bytes.len() / unit).saturating_mul(2).min(MAX_THUNK_CHUNK);
        }
    }

    /// Decode one nonzero thunk value.
    fn thunk(&mut self, value: u64, names: NameAddress) -> Result<ImportThunk> {
        let ordinal_flag = if self.is_64bit {
            IMAGE_ORDINAL_FLAG64
        } else {
            u64::from(IMAGE_ORDINAL_FLAG32)
        };
        if value & ordinal_flag != 0 {
            // The loader uses only the low 16 bits (`IMAGE_ORDINAL`). It ignores the other bits.
            return Ok(ImportThunk::Ordinal(ImportThunk::ordinal_from_64(value)));
        }
        let hint_name_rva = match names {
            NameAddress::Rva => u32::try_from(value).ok(),
            NameAddress::Va(image_base) => value
                .checked_sub(image_base)
                .and_then(|rva| u32::try_from(rva).ok()),
        }
        .ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "{} hint/name address {value:#x} is not in the image",
                self.context
            ))
        })?;
        if hint_name_rva == 0 {
            return Err(Error::invalid_data_directory(format!(
                "named {} has a null hint/name RVA",
                self.context
            )));
        }
        let (hint, name) = self.hint_name(hint_name_rva)?;
        Ok(ImportThunk::Name { hint, name })
    }

    /// Read the hint/name entry (`IMAGE_IMPORT_BY_NAME`) at `rva`.
    fn hint_name(&mut self, rva: u32) -> Result<(u16, String)> {
        let entry = if let Some(entry) = self.hint_names.get(&rva) {
            entry.clone()
        } else {
            let name_offset = offset_of!(ImageImportByName, name);
            let bytes = read_terminated(self.read, rva, name_offset, self.context)?;
            self.names
                .add_source(u64::from(rva), bytes.len().saturating_add(1));
            let hint = u16_at(&bytes, offset_of!(ImageImportByName, hint));
            let (Some(hint), Some(name)) = (hint, bytes.get(name_offset..)) else {
                return Err(Error::buffer_too_small(name_offset, bytes.len()));
            };
            let name = String::from_utf8(name.to_vec()).map_err(|_| Error::invalid_utf8())?;
            let entry = (hint, name);
            self.hint_names.insert(rva, entry.clone());
            entry
        };
        self.names.charge(entry.1.len(), self.context)?;
        Ok(entry)
    }
}

/// Read the bytes at `rva`: `prefix` bytes, then a name up to its null terminator.
///
/// Return the prefix and the name, without the terminator. Read in chunks that get larger, so
/// that a long name takes few reads. Make a chunk smaller if the image ends before it.
///
/// # Errors
///
/// Returns an invalid-RVA error if a byte cannot be read. Returns an invalid-data-directory
/// error if no terminator follows in [`MAX_NAME_LEN`] name bytes.
pub(crate) fn read_terminated<F>(
    read: &F,
    rva: u32,
    prefix: usize,
    context: &str,
) -> Result<Vec<u8>>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    // The prefix, the name and the terminator.
    let limit = prefix.saturating_add(MAX_NAME_LEN).saturating_add(1);
    let mut bytes = Vec::new();
    let mut chunk = FIRST_NAME_CHUNK;
    while bytes.len() < limit {
        let at = u32::try_from(bytes.len())
            .ok()
            .and_then(|offset| rva.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory(format!("{context} name RVA overflow")))?;
        let want = chunk.min(limit - bytes.len());
        let part = read_chunk(read, at, want, 1).ok_or_else(|| Error::invalid_rva(at))?;
        let search_from = bytes.len().max(prefix);
        bytes.extend_from_slice(&part);
        if let Some(end) = bytes
            .get(search_from..)
            .and_then(|tail| tail.iter().position(|&byte| byte == 0))
        {
            bytes.truncate(search_from + end);
            return Ok(bytes);
        }
        chunk = part.len().saturating_mul(2);
    }
    Err(Error::invalid_data_directory(format!(
        "{context} name is not null-terminated within {MAX_NAME_LEN} bytes"
    )))
}

/// Read at most `want` bytes at `rva`, a multiple of `unit` bytes.
///
/// If the read fails, try again with half the size, down to one `unit`. The reader can fail
/// for a large read near the end of the image, and succeed for a smaller one. Return `None` if
/// not even one `unit` can be read.
fn read_chunk<F>(read: &F, rva: u32, want: usize, unit: usize) -> Option<Vec<u8>>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    let mut want = (want / unit).max(1).saturating_mul(unit);
    loop {
        if let Some(mut bytes) = read(rva, want) {
            let whole = bytes.len().min(want) / unit * unit;
            if whole > 0 {
                bytes.truncate(whole);
                return Some(bytes);
            }
        }
        if want <= unit {
            return None;
        }
        want = (want / unit / 2).max(1) * unit;
    }
}

#[cfg(test)]
mod tests;
