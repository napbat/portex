//! Serialization of the debug directory.

use super::{CodeViewRsds, DebugDirectory, DebugInfo, DebugType};
use crate::prelude::*;
use crate::{Error, Result};

/// A builder for the debug directory.
///
/// The debug directory can contain many entries, for example CodeView, POGO and Repro. The
/// most common directory has one CodeView entry with PDB information.
///
/// # Example
///
/// ```
/// use portex::debug::{DebugBuilder, DebugType, CodeViewRsds};
///
/// // Create a simple CodeView entry
/// let codeview = CodeViewRsds {
///     guid: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
///            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00],
///     age: 1,
///     pdb_path: b"C:\\app\\example.pdb".to_vec(),
/// };
///
/// let builder = DebugBuilder::new(0x3000);
/// let (data, dir_size, entries) = builder.build_codeview(&codeview);
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].get_type(), Some(DebugType::CodeView));
/// ```
#[derive(Debug, Clone)]
pub struct DebugBuilder {
    /// The RVA of the debug section.
    base_rva: u32,
}

impl DebugBuilder {
    /// Create a debug builder. `base_rva` is the RVA of the debug section.
    #[must_use]
    pub fn new(base_rva: u32) -> Self {
        Self { base_rva }
    }

    /// Build a debug directory with one CodeView entry.
    ///
    /// Returns the tuple (`data`, `directory_size`, `debug_directories`):
    /// - `data` contains the raw bytes to write to the section.
    /// - `directory_size` is the size of the directory entries, for the data directory.
    /// - `debug_directories` contains the directory entries for inspection.
    ///
    /// # Panics
    /// Panics if [`Self::try_build_codeview`] fails.
    #[must_use]
    pub fn build_codeview(&self, codeview: &CodeViewRsds) -> (Vec<u8>, u32, Vec<DebugDirectory>) {
        self.try_build_codeview(codeview)
            .expect("debug build failed: use try_build_codeview() for fallible serialization")
    }

    /// Build a CodeView entry. Check the string length and the RVAs.
    ///
    /// # Errors
    /// Returns an error if the CodeView record cannot be serialized, or if the payload RVA
    /// overflows.
    pub fn try_build_codeview(
        &self,
        codeview: &CodeViewRsds,
    ) -> Result<(Vec<u8>, u32, Vec<DebugDirectory>)> {
        // Layout: [DebugDirectory (28 bytes)] [CodeView data].
        let cv_data = codeview.try_to_bytes()?;
        let cv_offset = DebugDirectory::SIZE_U32;
        let payload_size = u32::try_from(cv_data.len())
            .map_err(|_| Error::invalid_data_directory("CodeView payload exceeds u32"))?;
        let payload_rva = self
            .base_rva
            .checked_add(cv_offset)
            .ok_or_else(|| Error::invalid_data_directory("CodeView payload RVA overflow"))?;

        let dir = DebugDirectory {
            debug_type: DebugType::CodeView.as_u32(),
            size_of_data: payload_size,
            address_of_raw_data: payload_rva,
            pointer_to_raw_data: 0, // Caller must update after section layout
            ..Default::default()
        };

        let capacity = DebugDirectory::SIZE
            .checked_add(cv_data.len())
            .ok_or_else(|| Error::invalid_data_directory("CodeView payload size overflow"))?;
        let mut data = Vec::with_capacity(capacity);
        data.extend_from_slice(&dir.to_bytes());
        data.extend_from_slice(&cv_data);

        let dir_size = DebugDirectory::SIZE_U32;
        Ok((data, dir_size, vec![dir]))
    }

    /// Build the debug directory from a [`DebugInfo`].
    ///
    /// This function rebuilds all entries and all available raw payloads.
    ///
    /// # Panics
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self, debug_info: &DebugInfo) -> (Vec<u8>, u32, Vec<DebugDirectory>) {
        self.try_build(debug_info)
            .expect("debug build failed: use try_build() for fallible serialization")
    }

    /// Rebuild all debug entries and their payloads. Check all offsets.
    ///
    /// [`DebugInfo::data`] is the only source of the payloads. The function writes each
    /// payload after the table and sets `SizeOfData` and `AddressOfRawData` of its entry. It
    /// sets `PointerToRawData` to 0: the image layout sets the file offset later.
    ///
    /// An entry without a payload keeps no data. Then the function writes 0 to the three
    /// payload fields. It does this only if `SizeOfData` of the entry is 0.
    ///
    /// # Errors
    /// Returns an error if one of these conditions occurs:
    /// - There are more payloads than directory entries.
    /// - An entry declares a payload (`SizeOfData` is not 0), but [`DebugInfo::data`] has no
    ///   payload for it. [`PeImage::debug_info`](crate::PeImage::debug_info) reads payloads
    ///   only at their RVA. To keep a payload that only `PointerToRawData` can reach, use
    ///   [`PeFile::debug_info`](crate::PeFile::debug_info). To remove the payload, set
    ///   `SizeOfData` to 0.
    /// - A size or an RVA overflows `u32`.
    pub fn try_build(&self, debug_info: &DebugInfo) -> Result<(Vec<u8>, u32, Vec<DebugDirectory>)> {
        if debug_info.directories.is_empty() {
            return Ok((Vec::new(), 0, Vec::new()));
        }
        if debug_info.data.len() > debug_info.directories.len() {
            return Err(Error::invalid_data_directory(
                "debug payload list is longer than the directory list",
            ));
        }
        let payload = |index: usize| debug_info.data.get(index).and_then(Option::as_deref);

        let dir_size_usize = debug_info
            .directories
            .len()
            .checked_mul(DebugDirectory::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("debug table size overflow"))?;
        let dir_size = u32::try_from(dir_size_usize)
            .map_err(|_| Error::invalid_data_directory("debug table exceeds u32"))?;
        let payload_size: usize = debug_info.directories.iter().enumerate().try_fold(
            0usize,
            |total, (index, directory)| {
                let size = match payload(index) {
                    Some(payload) => payload.len(),
                    None if directory.size_of_data != 0 => {
                        return Err(Error::invalid_data_directory(format!(
                            "debug entry {index} declares {} payload bytes, but has no payload",
                            directory.size_of_data
                        )));
                    }
                    None => 0,
                };
                u32::try_from(size)
                    .map_err(|_| Error::invalid_data_directory("debug payload exceeds u32"))?;
                total
                    .checked_add(size)
                    .ok_or_else(|| Error::invalid_data_directory("debug payload size overflow"))
            },
        )?;
        dir_size_usize
            .checked_add(payload_size)
            .and_then(|size| u32::try_from(size).ok())
            .and_then(|size| self.base_rva.checked_add(size))
            .ok_or_else(|| Error::invalid_data_directory("debug data RVA range overflow"))?;
        let mut data = vec![0u8; dir_size_usize];
        data.try_reserve(payload_size)
            .map_err(|_| Error::invalid_data_directory("debug payload is too large to allocate"))?;
        let mut dirs = Vec::with_capacity(debug_info.directories.len());

        for (index, orig_dir) in debug_info.directories.iter().enumerate() {
            let mut dir = *orig_dir;
            if let Some(payload) = payload(index) {
                dir.address_of_raw_data = self
                    .base_rva
                    .checked_add(u32::try_from(data.len()).map_err(|_| {
                        Error::invalid_data_directory("debug payload offset exceeds u32")
                    })?)
                    .ok_or_else(|| Error::invalid_data_directory("debug payload RVA overflow"))?;
                dir.pointer_to_raw_data = 0;
                dir.size_of_data = u32::try_from(payload.len())
                    .map_err(|_| Error::invalid_data_directory("debug payload exceeds u32"))?;
                data.extend_from_slice(payload);
            } else {
                dir.address_of_raw_data = 0;
                dir.pointer_to_raw_data = 0;
                dir.size_of_data = 0;
            }
            dirs.push(dir);
        }

        // `data` starts with one `DebugDirectory::SIZE` slot for each entry in `dirs`.
        let (slots, _) = data.as_chunks_mut::<{ DebugDirectory::SIZE }>();
        for (slot, dir) in slots.iter_mut().zip(&dirs) {
            *slot = dir.to_bytes();
        }

        Ok((data, dir_size, dirs))
    }

    /// Calculate the size of a CodeView debug entry.
    ///
    /// # Panics
    /// Panics if [`Self::try_calculate_codeview_size`] fails.
    #[must_use]
    pub fn calculate_codeview_size(codeview: &CodeViewRsds) -> usize {
        Self::try_calculate_codeview_size(codeview)
            .expect("CodeView size overflow: use try_calculate_codeview_size()")
    }

    /// Calculate the size of a CodeView debug entry. Validate the string.
    ///
    /// # Errors
    /// Returns an error if the CodeView record cannot be serialized, or if the size overflows.
    pub fn try_calculate_codeview_size(codeview: &CodeViewRsds) -> Result<usize> {
        let payload = codeview.try_to_bytes()?;
        DebugDirectory::SIZE
            .checked_add(payload.len())
            .ok_or_else(|| Error::invalid_data_directory("debug entry size overflow"))
    }
}
