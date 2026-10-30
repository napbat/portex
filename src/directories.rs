//! Data directories of an executable image.
//!
//! Portex does not parse CLR metadata. [`CliHeader`] gives the PE-level data that a metadata
//! crate needs to continue.

pub use crate::bound_import::{
    BoundForwarderRef, BoundImportBuilder, BoundImportDescriptor, BoundImportDirectory,
};
pub use crate::clr::{CliBuilder, CliHeader};
pub use crate::debug::{CodeViewRsds, DebugBuilder, DebugDirectory, DebugInfo, DebugType};
pub use crate::delay_import::{
    DelayImportBuilder, DelayImportDirectory, DelayImportThunk, DelayLoadDescriptor, DelayLoadedDll,
};
pub use crate::exception::{
    ExceptionBuilder, ExceptionDirectory, ExceptionTable, PackedExceptionDirectory,
    PackedRuntimeFunction, RuntimeFunction, UnwindCode, UnwindInfo, UnwindOpCode,
};
pub use crate::export::{
    ExportAddress, ExportDirectory, ExportTable, ExportTableBuilder, ExportedFunction,
};
pub use crate::import::{
    ImportDescriptor, ImportTable, ImportTableBuilder, ImportThunk, ImportedDll,
};
pub use crate::loadconfig::{
    CfgSettings, LoadConfigBuilder, LoadConfigDirectory, LoadConfigDirectory32,
    LoadConfigDirectory64,
};
pub use crate::raw::{
    ImportTableEnd, RawAddressTable, RawCursor, RawExportDirectory, RawField, RawImportByName,
    RawImportDescriptor, RawImportDescriptors, RawIter, RawLoadConfigDirectory, RawRelocation,
    RawRelocationBlock, RawRelocationBlocks, RawRelocations, RawResourceDataEntry,
    RawResourceDirectory, RawResourceEntry, RawRuntimeFunction, RawRuntimeFunctions, RawUnwindInfo,
};
pub use crate::reloc::{
    RelocationBlock, RelocationBuilder, RelocationEntry, RelocationTable, RelocationType,
};
pub use crate::resource::{
    Resource, ResourceBuilder, ResourceDataEntry, ResourceDirectory, ResourceDirectoryEntry,
    ResourceDirectoryHeader, ResourceEntry, ResourceId, ResourceType,
};
pub use crate::security::{
    Certificate, CertificateRevision, CertificateType, SecurityBuilder, SecurityDirectory,
};
pub use crate::tls::{TlsBuilder, TlsDirectory, TlsDirectory32, TlsDirectory64, TlsInfo};
