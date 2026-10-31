//! `PeFile::normalize`: normal header fields and file layout with the same loader view.

use super::PeFile;
use crate::PeImage;
use crate::Result;
use crate::checksum::{calculate_checksum, checksum_field_offset};
use crate::pe::{
    LoaderView, Normalization, NormalizeChange, NormalizeKept, check_sum, normalize_changes,
    set_check_sum,
};
use crate::prelude::*;

impl PeFile {
    /// Set malformed header fields and the file layout to normal values, and keep the loader
    /// view of the image.
    ///
    /// The method makes these changes:
    ///
    /// - It moves NT headers that overlap the DOS header to offset 0x40. It grows
    ///   `SizeOfOptionalHeader`, so that the section table follows the optional header.
    /// - It sets an unknown `Magic`, invalid alignments, `NumberOfRvaAndSizes` and the
    ///   reserved data directories to valid values.
    /// - It lays out the raw section data again, so that each section has its own aligned raw
    ///   range. It also calculates `SizeOfHeaders` and the code and data size fields again.
    /// - It raises a `SizeOfImage` that is smaller than the end of the last section. It does not
    ///   lower a larger `SizeOfImage`, because the loader reserves and maps the extra pages.
    /// - It corrects a wrong checksum. A checksum of 0 stays 0.
    ///
    /// The method builds each fixed copy, called a candidate, and parses it again. It keeps a
    /// candidate only if the built file keeps the loader view of the built original. The loader
    /// view covers these items:
    ///
    /// - the section RVAs, virtual sizes and characteristics;
    /// - the section bytes that the loader maps, from the raw offset up to the
    ///   `FileAlignment`-aligned raw end, limited to the aligned virtual size;
    /// - the aligned size of the headers, if `SectionAlignment` is valid;
    /// - the header bytes at the entry point and at each data directory;
    /// - the header bytes that the followed structures refer to;
    /// - the nonzero header bytes after the section table.
    ///
    /// The followed structures are the structures that the loader reads through RVAs:
    ///
    /// - the import descriptor array, up to and including the null descriptor;
    /// - for each import descriptor, the DLL name with its NUL, and the `OriginalFirstThunk`
    ///   and `FirstThunk` arrays, up to and including the null thunk;
    /// - each hint/name entry: 2 bytes, the name and the NUL;
    /// - the same items for the delay-import table;
    /// - the TLS callback array, up to and including the null entry.
    ///
    /// The method checks only these indirect references. If the import or delay-import table
    /// does not parse, the bytes from the RVA of that directory to the end of the address
    /// space are protected. The same occurs if the import and delay-import tables together
    /// have more than 131,072 thunks in name tables at different RVAs.
    ///
    /// The only accepted change to section bytes is the rebase of the `PointerToRawData` file
    /// offsets of the `IMAGE_DEBUG_DIRECTORY` entries. The entries must be in a section without
    /// `IMAGE_SCN_CNT_CODE` or `IMAGE_SCN_MEM_EXECUTE`, outside other data directories, and
    /// outside the followed structures.
    /// [`Normalization::changes`] reports it as [`NormalizeChange::DebugPointers`].
    ///
    /// The method corrects a wrong nonzero checksum only if the fix keeps the loader view and
    /// builds. It does not use a candidate that would make a valid checksum wrong.
    /// [`Normalization::kept`] names the fixes that the method does not make. The overlay and
    /// the certificate table stay.
    ///
    /// A change invalidates an Authenticode signature. A new layout also drops the file bytes
    /// between the raw ranges of the sections, which the loader does not map.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails for the file, or if the built file does not
    /// parse. The file then does not change.
    pub fn normalize(&mut self) -> Result<Normalization> {
        let original_bytes = self.try_build()?;
        let original_view = LoaderView::parse(&original_bytes)?;
        let original = self.image.clone();
        let stored = check_sum(&original.optional_header);
        let valid_checksum = stored != 0
            && checksum_field_offset(&original_bytes)
                .is_some_and(|offset| calculate_checksum(&original_bytes, offset) == stored);
        let (candidates, mut kept) = original.normalize_candidates();
        let mut moves_debug_offsets = !original_view.keeps_section_data(&original);
        let mut accepted = false;
        for candidate in candidates {
            let (bytes, moved) = match self.try_normalized(candidate, &original_view) {
                Ok(result) => result,
                Err(reason) => {
                    add_kept(&mut kept, reason);
                    continue;
                }
            };
            if self.normalize_checksum(&bytes, &original_view).is_err() {
                add_kept(&mut kept, NormalizeKept::Checksum);
                if valid_checksum {
                    self.image = original.clone();
                    continue;
                }
            }
            moves_debug_offsets |= moved;
            accepted = true;
            break;
        }
        if !accepted
            && self
                .normalize_checksum(&original_bytes, &original_view)
                .is_err()
        {
            add_kept(&mut kept, NormalizeKept::Checksum);
        }
        let mut changes = normalize_changes(&original, &self.image);
        if moves_debug_offsets {
            changes.push(NormalizeChange::DebugPointers);
        }
        Ok(Normalization { changes, kept })
    }

    /// Use `candidate` if its built file keeps the loader view of `original`. Return the built
    /// file and `true` if the debug file offsets moved. On an error, the image does not change.
    fn try_normalized(
        &mut self,
        candidate: PeImage,
        original: &LoaderView<'_>,
    ) -> core::result::Result<(Vec<u8>, bool), NormalizeKept> {
        let previous = core::mem::replace(&mut self.image, candidate);
        let result = self
            .try_build()
            .map_err(|error| NormalizeKept::Build(error.to_string()))
            .and_then(|bytes| {
                let view = LoaderView::parse(&bytes)
                    .map_err(|error| NormalizeKept::Build(error.to_string()))?;
                let moved = original.check(&view)?;
                drop(view);
                Ok((bytes, moved))
            });
        if result.is_err() {
            self.image = previous;
        }
        result
    }

    /// Correct a wrong nonzero checksum of the file `bytes`, if the fix keeps the loader view
    /// of `original`. Return the reason if the fix is not made. The image then does not change.
    fn normalize_checksum(
        &mut self,
        bytes: &[u8],
        original: &LoaderView<'_>,
    ) -> core::result::Result<(), NormalizeKept> {
        let stored = check_sum(&self.image.optional_header);
        let Some(offset) = checksum_field_offset(bytes).filter(|_| stored != 0) else {
            return Ok(());
        };
        let computed = calculate_checksum(bytes, offset);
        if computed == stored {
            return Ok(());
        }
        let mut candidate = self.image.clone();
        set_check_sum(&mut candidate.optional_header, computed);
        self.try_normalized(candidate, original).map(|_| ())
    }
}

/// Add `reason` to `kept`, if it is not there.
fn add_kept(kept: &mut Vec<NormalizeKept>, reason: NormalizeKept) {
    if !kept.contains(&reason) {
        kept.push(reason);
    }
}
