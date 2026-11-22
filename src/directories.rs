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
    DelayImportBuilder, DelayImportDirectory, DelayLoadDescriptor, DelayLoadedDll,
};
pub use crate::dynamic_reloc::{
    DynamicRelocation, DynamicRelocationBlock, DynamicRelocationBlocks, DynamicRelocationBody,
    DynamicRelocationEntries, DynamicRelocationTable, DynamicRelocations, FunctionOverride,
    FunctionOverrideHeader, FunctionOverrides,
};
pub use crate::exception::{
    EpilogOpsV3, EpilogV3, ExceptionBuilder, ExceptionDirectory, ExceptionTable,
    PackedExceptionDirectory, PackedRuntimeFunction, ResolvedEpilogV3, RuntimeFunction,
    UNW_FLAG_LARGE, UnwindCode, UnwindInfo, UnwindInfoV3, UnwindOpCode, WindOp, X64UnwindInfo,
};
pub use crate::export::{
    ExportAddress, ExportDirectory, ExportTable, ExportTableBuilder, ExportedFunction,
};
pub use crate::import::{
    ImportDescriptor, ImportTable, ImportTableBuilder, ImportThunk, ImportedDll,
};
pub use crate::load_config::{
    CfgSettings, LoadConfigBuilder, LoadConfigDirectory, LoadConfigDirectory32,
    LoadConfigDirectory64, LoadConfigField,
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
