//! Error types for PE parsing and writing.
//!
//! An error can have a context: a file offset, an RVA, a structure name and details. Use the
//! context to find the cause of a problem when you parse or write a PE file.
//!
//! # Example
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! match PeImage::parse(file_bytes) {
//!     Ok(_pe) => println!("Loaded PE"),
//!     Err(e) => {
//!         eprintln!("Error: {}", e);
//!         if let Some(ctx) = e.context() {
//!             eprintln!("  Context: {}", ctx);
//!         }
//!     }
//! }
//! ```

use crate::prelude::*;
use core::fmt;

/// Result type alias for portex operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Information about the location of an error.
///
/// The type is `#[non_exhaustive]`, so that a later release can add fields. Use
/// [`ErrorContext::new`] and the builder methods to make a context.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ErrorContext {
    /// File offset where the error occurred (if known).
    pub file_offset: Option<u64>,
    /// RVA where the error occurred (if known).
    pub rva: Option<u32>,
    /// Name of the structure that the parser was reading (if known).
    pub structure: Option<String>,
    /// Additional details about the error.
    pub details: Option<String>,
}

impl ErrorContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            file_offset: None,
            rva: None,
            structure: None,
            details: None,
        }
    }

    /// Set the file offset.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        self.file_offset = Some(offset);
        self
    }

    /// Set the RVA.
    #[must_use]
    pub fn at_rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Set the structure name.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        self.structure = Some(name.into());
        self
    }

    /// Set additional details.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Return `true` if the context has no information.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.file_offset.is_none()
            && self.rva.is_none()
            && self.structure.is_none()
            && self.details.is_none()
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(offset) = self.file_offset {
            parts.push(format!("offset {offset:#x}"));
        }
        if let Some(rva) = self.rva {
            parts.push(format!("RVA {rva:#x}"));
        }
        if let Some(ref structure) = self.structure {
            parts.push(format!("in {structure}"));
        }
        if let Some(ref details) = self.details {
            parts.push(details.clone());
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// An error from parsing or writing a PE file.
///
/// The type is `#[non_exhaustive]`, so that a later release can add fields. Use
/// [`Error::new`] or a constructor such as [`Error::generic`] to make an error.
#[derive(Debug)]
#[non_exhaustive]
pub struct Error {
    /// The error kind.
    pub kind: ErrorKind,
    /// Optional context about where the error occurred.
    pub context: Option<ErrorContext>,
}

/// The kind of error that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// I/O error from a `nostdio` stream.
    ///
    /// # Caution
    ///
    /// The type of the payload depends on the `std` feature. Without `std`, it is the
    /// `nostdio` error type. With `std`, it is `std::io::Error`. Cargo unifies features, so
    /// a different crate in the dependency graph can enable `std` and change this type. Thus
    /// do not match on the variants of the payload. Use
    /// [`io::is_unexpected_eof`](crate::io::is_unexpected_eof),
    /// [`io::is_interrupted`](crate::io::is_interrupted) or the [`fmt::Display`] output.
    Io(nostdio::IoError),
    /// Invalid DOS signature (expected "MZ").
    InvalidDosSignature,
    /// Invalid PE signature (expected "PE\0\0").
    InvalidPeSignature,
    /// Invalid DOS, NT or section-table header, for example an `e_lfanew` value that is not
    /// valid.
    InvalidHeader(String),
    /// Invalid optional header magic.
    InvalidOptionalHeaderMagic(u16),
    /// The buffer is too small for the expected data.
    BufferTooSmall {
        /// Number of bytes required.
        expected: u64,
        /// Number of bytes available.
        actual: u64,
    },
    /// Invalid section data.
    InvalidSection(String),
    /// Invalid data directory.
    InvalidDataDirectory(String),
    /// Offset out of bounds.
    OffsetOutOfBounds {
        /// The offset that is out of bounds.
        offset: u64,
        /// Size of the region that the check used.
        size: u64,
    },
    /// Invalid RVA (the data at this address cannot be read).
    InvalidRva(u32),
    /// Invalid UTF-8 string.
    InvalidUtf8,
    /// Generic error with a message.
    Generic(String),
}

impl Error {
    /// Create a new error with the given kind.
    #[must_use]
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    /// Add context to this error.
    #[must_use]
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Add file offset context.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.at_offset(offset));
        self
    }

    /// Add RVA context.
    #[must_use]
    pub fn at_rva(mut self, rva: u32) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.at_rva(rva));
        self
    }

    /// Add structure name context.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.in_structure(name));
        self
    }

    /// Get the context if present.
    #[must_use]
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_ref()
    }

    /// Get the error kind.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    // Convenience constructors for common errors

    /// Create an `InvalidDosSignature` error.
    #[must_use]
    pub fn invalid_dos_signature() -> Self {
        Self::new(ErrorKind::InvalidDosSignature)
    }

    /// Create an `InvalidPeSignature` error.
    #[must_use]
    pub fn invalid_pe_signature() -> Self {
        Self::new(ErrorKind::InvalidPeSignature)
    }

    /// Create an `InvalidHeader` error.
    pub fn invalid_header(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidHeader(msg.into()))
    }

    /// Create an `InvalidOptionalHeaderMagic` error.
    #[must_use]
    pub fn invalid_optional_header_magic(magic: u16) -> Self {
        Self::new(ErrorKind::InvalidOptionalHeaderMagic(magic))
    }

    /// Create a `BufferTooSmall` error from in-memory sizes.
    #[must_use]
    pub fn buffer_too_small(expected: usize, actual: usize) -> Self {
        Self::buffer_too_small_u64(usize_to_u64(expected), usize_to_u64(actual))
    }

    /// Create a `BufferTooSmall` error from source sizes.
    #[must_use]
    pub fn buffer_too_small_u64(expected: u64, actual: u64) -> Self {
        Self::new(ErrorKind::BufferTooSmall { expected, actual })
    }

    /// Create an `InvalidSection` error.
    pub fn invalid_section(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidSection(msg.into()))
    }

    /// Create an `InvalidDataDirectory` error.
    pub fn invalid_data_directory(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidDataDirectory(msg.into()))
    }

    /// Create an `OffsetOutOfBounds` error from an in-memory offset and size.
    #[must_use]
    pub fn offset_out_of_bounds(offset: usize, size: usize) -> Self {
        Self::offset_out_of_bounds_u64(usize_to_u64(offset), usize_to_u64(size))
    }

    /// Create an `OffsetOutOfBounds` error from a source offset and size.
    #[must_use]
    pub fn offset_out_of_bounds_u64(offset: u64, size: u64) -> Self {
        Self::new(ErrorKind::OffsetOutOfBounds { offset, size })
    }

    /// Create an `InvalidRva` error.
    #[must_use]
    pub fn invalid_rva(rva: u32) -> Self {
        Self::new(ErrorKind::InvalidRva(rva))
    }

    /// Create an `InvalidUtf8` error.
    #[must_use]
    pub fn invalid_utf8() -> Self {
        Self::new(ErrorKind::InvalidUtf8)
    }

    /// Create a `Generic` error with a message.
    pub fn generic(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Generic(msg.into()))
    }
}

/// Convert an in-memory size to a `u64`. Each supported target has a `usize` of at most 64
/// bits, so the fallback value never occurs.
fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io(e) => write!(f, "I/O error: {e}"),
            ErrorKind::InvalidDosSignature => write!(f, "Invalid DOS signature (expected 'MZ')"),
            ErrorKind::InvalidPeSignature => {
                write!(f, "Invalid PE signature (expected 'PE\\0\\0')")
            }
            ErrorKind::InvalidHeader(msg) => write!(f, "Invalid header: {msg}"),
            ErrorKind::InvalidOptionalHeaderMagic(m) => {
                write!(f, "Invalid optional header magic: {m:#06x}")
            }
            ErrorKind::BufferTooSmall { expected, actual } => {
                write!(
                    f,
                    "Buffer too small: expected {expected} bytes, got {actual}"
                )
            }
            ErrorKind::InvalidSection(msg) => write!(f, "Invalid section: {msg}"),
            ErrorKind::InvalidDataDirectory(msg) => write!(f, "Invalid data directory: {msg}"),
            ErrorKind::OffsetOutOfBounds { offset, size } => {
                write!(f, "Offset {offset:#x} out of bounds (size: {size})")
            }
            ErrorKind::InvalidRva(rva) => write!(f, "Invalid RVA: {rva:#x}"),
            ErrorKind::InvalidUtf8 => write!(f, "Invalid UTF-8 string"),
            ErrorKind::Generic(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ref ctx) = self.context
            && !ctx.is_empty()
        {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<nostdio::IoError> for Error {
    fn from(e: nostdio::IoError) -> Self {
        Self::new(ErrorKind::Io(e))
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}
