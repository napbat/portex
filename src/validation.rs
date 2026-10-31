//! PE validation framework.
//!
//! This module checks the structural integrity of a PE image.
//!
//! # Example
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes).unwrap();
//! let issues = pe.validate();
//!
//! for issue in &issues {
//!     println!("{}: {}", issue.level, issue.message);
//! }
//!
//! if issues.has_errors() {
//!     eprintln!("PE has structural errors!");
//! }
//! ```

use crate::prelude::*;
use core::fmt;

/// Severity level of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ValidationLevel {
    /// Warning: the PE can be valid, but it has suspicious characteristics.
    Warning,
    /// Error: the PE has structural problems that probably make it invalid.
    Error,
}

impl fmt::Display for ValidationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationLevel::Warning => write!(f, "Warning"),
            ValidationLevel::Error => write!(f, "Error"),
        }
    }
}

/// Type of validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValidationCode {
    /// DOS signature is invalid.
    InvalidDosSignature,
    /// Optional header magic is invalid.
    InvalidOptionalMagic,
    /// The entry point is not in a section.
    EntryPointOutOfBounds,
    /// Sections overlap in the file or in the virtual address space.
    OverlappingSections,
    /// A section RVA or size is invalid.
    InvalidSectionLayout,
    /// `SizeOfImage` is not equal to the calculated value.
    InconsistentImageSize,
    /// `SizeOfHeaders` is not equal to the calculated value.
    InconsistentHeadersSize,
    /// The checksum is not correct.
    InvalidChecksum,
    /// The file alignment is not a power of 2, or it is too small.
    InvalidFileAlignment,
    /// The section alignment is not a power of 2, or it is too small.
    InvalidSectionAlignment,
    /// The PE has no sections.
    NoSections,
    /// A section has no data, but its raw size is not zero.
    EmptySectionWithSize,
    /// The COFF section count is not equal to the number of entries in the parsed section table.
    InconsistentSectionCount,
    /// A size or count field of the optional header does not agree with the parsed data.
    InconsistentOptionalHeader,
    /// A reserved standard data directory is not zero.
    ReservedDataDirectory,
    /// A data directory range goes outside the readable image or file data.
    InvalidDataDirectoryRange,
    /// A section or header address does not have the necessary alignment.
    MisalignedSection,
    /// The width of the optional header does not agree with the machine type.
    MachineMagicMismatch,
}

impl fmt::Display for ValidationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single validation issue.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidationIssue {
    /// Severity of the issue.
    pub level: ValidationLevel,
    /// Type of issue.
    pub code: ValidationCode,
    /// Description for humans.
    pub message: String,
    /// Optional context (for example, a section name or an RVA).
    pub context: Option<String>,
}

impl ValidationIssue {
    /// Create a new error.
    pub fn error(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Error,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Create a new warning.
    pub fn warning(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Warning,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Add context to this issue.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Check if this is an error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.level == ValidationLevel::Error
    }

    /// Check if this is a warning.
    #[must_use]
    pub fn is_warning(&self) -> bool {
        self.level == ValidationLevel::Warning
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.level, self.code, self.message)?;
        if let Some(ctx) = &self.context {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

/// Collection of validation issues.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ValidationResult {
    /// All validation issues found.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResult {
    /// Create an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self { issues: Vec::new() }
    }

    /// Add an issue.
    pub fn push(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    /// Check if there are any errors.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(ValidationIssue::is_error)
    }

    /// Check if there are any warnings.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.issues.iter().any(ValidationIssue::is_warning)
    }

    /// Get only errors.
    pub fn errors(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|i| i.is_error())
    }

    /// Get only warnings.
    pub fn warnings(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|i| i.is_warning())
    }

    /// Iterate over all issues.
    pub fn iter(&self) -> core::slice::Iter<'_, ValidationIssue> {
        self.issues.iter()
    }

    /// Number of issues.
    #[must_use]
    pub fn len(&self) -> usize {
        self.issues.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    /// Count of errors.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_error()).count()
    }

    /// Count of warnings.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_warning()).count()
    }
}

impl IntoIterator for ValidationResult {
    type Item = ValidationIssue;
    type IntoIter = vec::IntoIter<ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.into_iter()
    }
}

impl<'a> IntoIterator for &'a ValidationResult {
    type Item = &'a ValidationIssue;
    type IntoIter = core::slice::Iter<'a, ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.iter()
    }
}
