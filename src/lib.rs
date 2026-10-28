//! # Portex
//!
//! A `no_std`-friendly library that reads and writes PE (Portable Executable) images.
//!
//! This library supplies types and utilities to parse and change Windows PE executable
//! images. It keeps raw files and loader-mapped images separate, because each layout
//! translates an RVA to a source offset in a different way.
//!
//! ## Features
//!
//! - **Multiple loading modes**: Load raw files or loader-mapped images from memory
//!   slices. For a custom source (for example, remote process memory), implement the
//!   `ReadAt` trait.
//! - **Partial loading**: Use `PeHeaders` to parse only the headers. This does not load
//!   the full file, which helps when you read a remote process.
//! - **Self-contained**: The crate defines all PE structures itself. It does not use the
//!   Windows SDK.
//! - **Normalization**: [`PeFile::normalize`] sets malformed header fields and the file layout
//!   to normal values. It keeps how the loader maps the image.
//! - **`no_std` mode**: Disable the `std` feature for `no_std + alloc` builds. The full PE
//!   API (parsers, builders, layout, validation and in-memory readers) stays available.
//!   Only these items need `std`, and they compile out:
//!   - `PeImage::from_file`, `PeImage::write_to_file`, `PeFile::from_file`,
//!     `PeFile::write_to_file` and `PeHeaders::from_file`.
//!   - `FileReader` and `SeekReader::open`.
//! - **Stream I/O**: `nostdio` supplies the `Read`, `Write` and `Seek` traits and the
//!   `nostdio::IoError` type. With the `std` feature, these are the `std::io` items. An
//!   [`ErrorKind::Io`] error holds a `nostdio::IoError` in every build, and [`Error`]
//!   implements `core::error::Error`.
//!
//! ## Architecture
//!
//! ### Parsing Patterns
//!
//! The library uses the same two-tier parsing pattern for all structures:
//!
//! 1. **Raw structures** use `parse(&[u8])` to parse contiguous binary data:
//!    - `ImportDescriptor::parse(&[u8])`, `TlsDirectory::parse(&[u8], is_64bit)`
//!    - Each call parses one fixed-size structure from a byte slice.
//!
//! 2. **High-level tables** use `parse(rva, ..., read_fn)` to follow RVA pointers:
//!    - `ImportTable::parse(rva, is_64bit, read_fn)`
//!    - `ResourceDirectory::parse(rva, size, read_fn)`
//!    - The `read_fn` closure reads from many locations, because it resolves each RVA.
//!
//! ### Builder Pattern
//!
//! Each directory builder (`ImportTableBuilder`, `ExportTableBuilder`, `ResourceBuilder` and
//! others) serializes a table into bytes. Each `build` method panics on invalid input. Use the
//! matching `try_build` method to get a `Result`.
//!
//! ## Example
//!
//! ```no_run
//! use portex::{PeFile, PeHeaders};
//!
//! // PeFile keeps certificates, overlays and raw file gaps.
//! # let bytes: &[u8] = &[];
//! let file = PeFile::parse(bytes).unwrap();
//! println!("64-bit: {}", file.image().is_64bit());
//!
//! // Or load only the headers (this is faster for large files).
//! let headers = PeHeaders::from_slice(bytes).unwrap();
//! println!("Entry point: {:#x}", headers.entry_point());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Internal prelude. Each source file uses `use crate::prelude::*;` to get the `alloc`
/// types and macros that the code needs.
///
/// With this prelude, the import header of each module is one line. It also keeps the
/// `no_std` imports in one location, so modules do not repeat `#[cfg]` blocks. All items
/// are `alloc` re-exports. Under the `std` feature, they shadow prelude items of the same
/// type, and this causes no problem.
pub(crate) mod prelude {
    pub use alloc::borrow::Cow;
    pub use alloc::collections::{BTreeMap, BTreeSet};
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod bound_import;
pub mod builder;
pub mod checksum;
pub mod clr;
pub mod coff;
pub mod data_dir;
pub mod debug;
pub mod delay_import;
pub mod directories;
pub mod dos;
pub mod error;
pub mod exception;
pub mod export;
pub mod headers;
pub mod image;
pub mod import;
pub mod io;
pub mod layout;
pub mod loadconfig;
pub mod optional;
mod parse_utils;
pub mod pe;
pub mod pe_file;
pub mod reader;
pub mod reloc;
pub mod resource;
pub mod rich;
pub mod section;
pub mod security;
pub mod tls;
pub mod validation;

pub use bound_import::{
    BoundForwarderRef, BoundImportBuilder, BoundImportDescriptor, BoundImportDirectory,
};
pub use builder::PeBuilder;
pub use checksum::{calculate_checksum, checksum_field_offset, compute_pe_checksum};
pub use clr::{CliBuilder, CliHeader};
pub use coff::{CoffHeader, MachineType};
pub use data_dir::{DataDirectory, DataDirectoryType};
pub use debug::{CodeViewRsds, DebugBuilder, DebugDirectory, DebugInfo, DebugType};
pub use delay_import::{
    DelayImportBuilder, DelayImportDirectory, DelayImportThunk, DelayLoadDescriptor, DelayLoadedDll,
};
pub use dos::DosHeader;
pub use error::{Error, ErrorContext, ErrorKind, Result};
pub use exception::{
    ExceptionBuilder, ExceptionDirectory, ExceptionTable, PackedExceptionDirectory,
    PackedRuntimeFunction, RuntimeFunction, UnwindCode, UnwindInfo, UnwindOpCode,
};
pub use export::{
    ExportAddress, ExportDirectory, ExportTable, ExportTableBuilder, ExportedFunction,
};
pub use import::{ImportDescriptor, ImportTable, ImportTableBuilder, ImportThunk, ImportedDll};
pub use layout::LayoutConfig;
pub use loadconfig::{
    CfgSettings, LoadConfigBuilder, LoadConfigDirectory, LoadConfigDirectory32,
    LoadConfigDirectory64,
};
pub use optional::{OptionalHeader, OptionalHeader32, OptionalHeader64, Subsystem};
pub use pe::{
    MissingSectionData, Normalization, NormalizeChange, NormalizeKept, ParseOptions, PeHeaders,
    PeImage, SourceLayout,
};
pub use pe_file::PeFile;
#[cfg(feature = "std")]
pub use reader::FileReader;
pub use reader::{BaseAddressReader, ReadAt, SeekReader, SliceReader, VecReader};
pub use reloc::{
    RelocationBlock, RelocationBuilder, RelocationEntry, RelocationTable, RelocationType,
};
pub use resource::{
    Resource, ResourceBuilder, ResourceDataEntry, ResourceDirectory, ResourceDirectoryEntry,
    ResourceDirectoryHeader, ResourceEntry, ResourceId, ResourceType,
};
pub use rich::{RichBuilder, RichEntry, RichHeader};
pub use section::{Section, SectionHeader};
pub use security::{
    Certificate, CertificateRevision, CertificateType, SecurityBuilder, SecurityDirectory,
};
pub use tls::{TlsBuilder, TlsDirectory, TlsDirectory32, TlsDirectory64, TlsInfo};
pub use validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};

// Compile the Rust examples in the README as doctests, so that they follow the API. The
// quick start uses the `std` file helpers.
#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
