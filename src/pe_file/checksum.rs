//! The checksum and validation methods of `PeFile`. They cover the complete raw file.

use super::PeFile;
use crate::checksum::compute_pe_checksum;
use crate::data_dir::DataDirectoryType;
use crate::pe::{check_sum, set_check_sum};
use crate::prelude::*;
use crate::validation::{ValidationCode, ValidationIssue, ValidationResult};
use crate::{Error, Result};

impl PeFile {
    /// Validate the structural integrity of the complete raw file.
    ///
    /// The method does the checks of [`PeImage::validate`](crate::PeImage::validate), with
    /// these differences:
    ///
    /// - The checksum check uses the file that [`Self::try_build`] makes. This file includes
    ///   the overlay and the certificate table.
    /// - The method also reports a Security directory entry that does not give a valid
    ///   certificate table in the overlay. The loader ignores such an entry.
    #[must_use]
    pub fn validate(&self) -> ValidationResult {
        let mut result = self
            .image
            .validate_with_checksum(|| self.try_calculate_checksum());
        let security = DataDirectoryType::Security;
        // `PeImage` reports an entry with only one of the two fields set.
        let invalid_entry = self.certificate_range.is_none()
            && self
                .image
                .data_directory(security)
                .is_some_and(|entry| entry.virtual_address != 0 && entry.size != 0);
        if invalid_entry {
            result.push(
                ValidationIssue::warning(
                    ValidationCode::InvalidDataDirectoryRange,
                    "data directory Security does not give a valid certificate table in the overlay",
                )
                .with_context(security.name().to_string()),
            );
        }
        result
    }

    /// Calculate and return the checksum of the complete raw file.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_checksum`] returns an error.
    #[must_use]
    pub fn calculate_checksum(&self) -> u32 {
        self.try_calculate_checksum()
            .expect("checksum calculation failed: use PeFile::try_calculate_checksum()")
    }

    /// Calculate the checksum of the complete raw file. Return an error, not a panic.
    ///
    /// The checksum covers the file that [`Self::try_build`] makes: the headers, the section
    /// data, the overlay and the certificate table.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails, or if the built file is too short to
    /// contain the `CheckSum` field of the optional header.
    pub fn try_calculate_checksum(&self) -> Result<u32> {
        let data = self.try_build()?;
        compute_pe_checksum(&data)
            .ok_or_else(|| Error::invalid_section("built file has no checksum field"))
    }

    /// Set the `CheckSum` field of the optional header to the checksum of the complete file.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_update_checksum`] returns an error.
    pub fn update_checksum(&mut self) {
        self.try_update_checksum()
            .expect("checksum update failed: use PeFile::try_update_checksum()");
    }

    /// Set the `CheckSum` field of the optional header to the checksum of the complete file.
    /// Return an error, not a panic.
    ///
    /// In some layouts, section data covers the header bytes. A new `CheckSum` value then makes
    /// the build use a new layout, and the value is not correct for the new file. The method
    /// returns an error for this case, and the field does not change.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_calculate_checksum`] fails, or if the new value changes
    /// the built file in a different location than the `CheckSum` field.
    pub fn try_update_checksum(&mut self) -> Result<()> {
        let checksum = self.try_calculate_checksum()?;
        let old = check_sum(&self.image.optional_header);
        if checksum == old {
            return Ok(());
        }
        set_check_sum(&mut self.image.optional_header, checksum);
        match self.try_calculate_checksum() {
            Ok(value) if value == checksum => Ok(()),
            result => {
                set_check_sum(&mut self.image.optional_header, old);
                result?;
                Err(Error::invalid_section(
                    "the new CheckSum value changes the file layout",
                ))
            }
        }
    }

    /// Recalculate the derived layout fields and the checksum of the complete file.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_finalize`] returns an error.
    pub fn finalize(&mut self) {
        self.try_finalize()
            .expect("finalize failed: use PeFile::try_finalize()");
    }

    /// Recalculate the derived layout fields and the checksum of the complete file. Return an
    /// error, not a panic.
    ///
    /// The layout update can make a new raw layout. The build then does not keep the raw gaps
    /// of the source.
    ///
    /// # Errors
    ///
    /// Returns an error if the layout update or [`Self::try_update_checksum`] fails.
    pub fn try_finalize(&mut self) -> Result<()> {
        self.image.try_update_layout()?;
        self.try_update_checksum()
    }
}
