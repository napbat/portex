//! APIs that parse, edit and build a full image.
//!
//! Use [`PeImage`] when the bytes are already in one layout: a raw file or a loader-mapped
//! image. Use [`PeFile`] when raw-only data must stay the same after a round trip. Raw-only
//! data includes overlay bytes, Authenticode certificates and file gaps.

pub use crate::builder::PeBuilder;
pub use crate::layout::LayoutConfig;
pub use crate::pe::{
    MissingSectionData, Normalization, NormalizeChange, NormalizeKept, ParseOptions, PeHeaders,
    PeImage, SourceLayout,
};
pub use crate::pe_file::PeFile;
pub use crate::validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};
