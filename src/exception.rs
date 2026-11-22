//! Parse and build the exception directory (`.pdata`).
//!
//! The exception directory contains runtime function entries. On x64, structured exception
//! handling (SEH) and stack unwinding use these entries.

mod arm;
mod builder;
mod table;
mod unwind;
mod x64;

pub use arm::{PackedExceptionDirectory, PackedRuntimeFunction};
pub use builder::ExceptionBuilder;
pub use table::ExceptionTable;
pub use unwind::{
    EpilogOpsV3, EpilogV3, ResolvedEpilogV3, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_LARGE,
    UNW_FLAG_NHANDLER, UNW_FLAG_UHANDLER, UnwindCode, UnwindInfo, UnwindInfoV3, UnwindOpCode,
    WindOp, X64UnwindInfo,
};
pub(crate) use unwind::{UnwindInfoHeader, unwind_codes_end};
pub(crate) use x64::ImageRuntimeFunctionEntry;
pub use x64::{ExceptionDirectory, RuntimeFunction};
