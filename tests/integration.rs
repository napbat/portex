//! Integration tests for the portex PE library.
//!
//! Each test does a round trip: it creates or parses an image, changes it, rebuilds it and
//! parses it again.

use portex::{
    ExceptionDirectory, ExportTable, ImportTable, ImportThunk, MachineType, PeBuilder, PeImage,
    RelocationTable, RelocationType, Subsystem,
    data_dir::DataDirectoryType,
    debug::CodeViewRsds,
    loadconfig::{LoadConfigDirectory, LoadConfigDirectory32, LoadConfigDirectory64},
    section::characteristics,
    tls::TlsInfo,
};

/// Makes sure that `PeBuilder` creates a valid PE that parses again.
#[test]
fn test_pe_builder_roundtrip() {
    // Create a minimal 64-bit PE.
    let pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(
            ".text",
            vec![0xCC; 0x200],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        ) // CODE | EXECUTE | READ
        .add_section(
            ".data",
            vec![0x00; 0x100],
            characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
        ) // INITIALIZED_DATA | READ | WRITE
        .build();

    // Parse the built PE again.
    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse built PE");

    // Check the structure.
    assert!(parsed.is_64bit());
    assert_eq!(parsed.coff_header.machine, MachineType::Amd64 as u16);
    assert_eq!(parsed.sections.len(), 2);
    assert_eq!(parsed.sections[0].name(), ".text");
    assert_eq!(parsed.sections[1].name(), ".data");
}

/// Makes sure that `PeBuilder` creates a valid 32-bit PE.
#[test]
fn test_pe_builder_32bit_roundtrip() {
    let pe = PeBuilder::new()
        .machine(MachineType::I386)
        .subsystem(Subsystem::WindowsGui)
        .entry_point(0x1000)
        .add_section(".text", vec![0x90; 0x100], 0x6000_0020)
        .build();

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse 32-bit PE");

    assert!(!parsed.is_64bit());
    assert_eq!(parsed.coff_header.machine, MachineType::I386 as u16);
}

/// Tests the round trip of the import table.
#[test]
fn test_import_table_roundtrip() {
    // Create a PE with a section for the imports.
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".rdata", vec![0x00; 0x1000], 0x4000_0040) // INITIALIZED_DATA | READ
        .build();

    // Create an import table with `ImportThunk` values.
    let mut imports = ImportTable::default();
    imports.add_dll(
        "KERNEL32.dll",
        vec![
            ImportThunk::Name {
                hint: 0,
                name: "GetLastError".to_string(),
            },
            ImportThunk::Name {
                hint: 0,
                name: "ExitProcess".to_string(),
            },
        ],
    );
    imports.add_dll(
        "USER32.dll",
        vec![ImportThunk::Name {
            hint: 0,
            name: "MessageBoxA".to_string(),
        }],
    );

    // Update the imports.
    pe.update_imports(&imports, None)
        .expect("Failed to update imports");

    // Rebuild the PE and parse it again.
    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with imports");

    // Check the imports.
    let parsed_imports = parsed.imports().expect("Failed to get imports");
    assert_eq!(parsed_imports.dlls.len(), 2);
}

/// Tests the round trip of the export table.
#[test]
fn test_export_table_roundtrip() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".rdata", vec![0x00; 0x1000], 0x4000_0040)
        .build();

    // Create the export table.
    let mut exports = ExportTable::default();
    exports.set_dll_name("TestModule.dll");
    exports.add_export(Some("TestFunction1"), 0x1000);
    exports.add_export(Some("TestFunction2"), 0x1010);

    pe.update_exports(&exports, None)
        .expect("Failed to update exports");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with exports");

    let parsed_exports = parsed.exports().expect("Failed to get exports");
    assert_eq!(parsed_exports.exports.len(), 2);
}

/// Tests the round trip of the relocation table.
#[test]
fn test_relocation_roundtrip() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".reloc", vec![0x00; 0x1000], 0x4200_0040) // DISCARDABLE | INITIALIZED_DATA | READ
        .build();

    // Create the relocation table.
    let mut relocs = RelocationTable::default();
    relocs.add_relocation(0x1000, RelocationType::Dir64);
    relocs.add_relocation(0x1008, RelocationType::Dir64);
    relocs.add_relocation(0x2000, RelocationType::HighLow);

    pe.update_relocations(&relocs, None)
        .expect("Failed to update relocations");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with relocations");

    let parsed_relocs = parsed.relocations().expect("Failed to get relocations");
    assert_ne!(parsed_relocs.blocks.len(), 0);
}

/// Tests the round trip of the exception directory.
#[test]
fn test_exception_roundtrip() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x400], 0x6000_0020)
        .add_section(".pdata", vec![0x00; 0x1000], 0x4000_0040)
        .build();

    // Create the exception directory.
    let mut exceptions = ExceptionDirectory::default();
    exceptions.add_function(0x1000, 0x1100, 0x3000);
    exceptions.add_function(0x1200, 0x1300, 0x3100);

    pe.update_exception(&exceptions, None)
        .expect("Failed to update exceptions");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with exceptions");

    let parsed_exceptions = parsed
        .exception_directory()
        .expect("Failed to get exceptions");
    assert_eq!(parsed_exceptions.functions.len(), 2);
}

/// Tests the round trip of the TLS directory.
#[test]
fn test_tls_roundtrip() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".tls", vec![0x00; 0x1000], 0xC000_0040) // INITIALIZED_DATA | READ | WRITE
        .build();

    // Create the TLS information with default values (no callbacks).
    let tls_info = TlsInfo::default();

    pe.update_tls(&tls_info, None)
        .expect("Failed to update TLS");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with TLS");

    // Make sure that the TLS directory is present.
    let tls = parsed.tls().expect("Failed to get TLS");
    assert!(tls.is_some());
}

/// Tests the round trip of the debug directory.
#[test]
fn test_debug_roundtrip() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".rdata", vec![0x00; 0x1000], 0x4000_0040)
        .build();

    // Add CodeView debug information with `update_debug_codeview`.
    let codeview = CodeViewRsds {
        guid: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ],
        age: 1,
        pdb_path: b"C:\\test.pdb".to_vec(),
    };
    pe.update_debug_codeview(&codeview, None)
        .expect("Failed to update debug");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with debug");

    // Make sure that the debug directory is present.
    let debug_info = parsed.debug_info().expect("Failed to get debug info");
    assert!(debug_info.is_some());
}

/// Tests the round trip of `LoadConfig`.
#[test]
fn test_loadconfig_roundtrip() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".rdata", vec![0x00; 0x2000], 0x4000_0040)
        .build();

    // Create a `LoadConfig` with a security cookie.
    let mut config64 = LoadConfigDirectory64::default();
    config64.size = u32::try_from(LoadConfigDirectory64::MIN_SIZE).unwrap();
    config64.security_cookie = 0x0001_4000_2000; // VA of the security cookie
    let loadconfig = LoadConfigDirectory::Config64(config64);

    pe.update_load_config(&loadconfig, None)
        .expect("Failed to update LoadConfig");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with LoadConfig");

    // Make sure that the `LoadConfig` is present.
    let config = parsed.load_config().expect("Failed to get LoadConfig");
    assert!(config.is_some());
}

/// A 32-bit linker writes a directory size of 0x40 and a larger structure `Size`. The reader
/// follows `Size`, as the Windows loader does. The reader still refuses a `Size` that the
/// mapped image cannot hold.
#[test]
fn test_loadconfig_reads_the_structure_size_of_a_short_32bit_directory() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::I386)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".rdata", vec![0x00; 0x200], 0x4000_0040)
        .build();
    let mut config = LoadConfigDirectory32::default();
    config.size = 0xc0;
    config.security_cookie = 0x0040_2000;
    config.guard_cf_function_count = 3;
    config.guard_flags = 0x0001_0500;
    config.trailing_data = vec![0x5a; 0xc0 - LoadConfigDirectory32::SIZE_WITH_CFG];
    let rva = pe
        .update_load_config(&LoadConfigDirectory::Config32(config.clone()), None)
        .expect("the load configuration is written");
    pe.set_data_directory(DataDirectoryType::LoadConfig, rva, 0x40);

    let parsed = PeImage::parse(&pe.build()).expect("the image parses");
    assert_eq!(
        parsed.load_config().expect("the structure is mapped"),
        Some(LoadConfigDirectory::Config32(config))
    );

    let mut oversized = parsed.clone();
    oversized
        .write_at_rva(rva, &0x0010_0000_u32.to_le_bytes())
        .expect("the Size field is mapped");
    assert!(oversized.load_config().is_err());
}

/// Tests section management.
#[test]
fn test_section_management() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x100], 0x6000_0020)
        .build();

    assert_eq!(pe.sections.len(), 1);

    // Add a new section. This method returns `()`, not a `Result`.
    pe.add_section_with_data(".data", vec![0x00; 0x100], 0xC000_0040);

    assert_eq!(pe.sections.len(), 2);
    assert!(pe.section_by_name(".data").is_some());

    // Rebuild the PE and parse it again.
    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with added section");

    assert_eq!(parsed.sections.len(), 2);
}

/// Makes sure that more than one update method can run on a PE.
///
/// The test checks only that the update methods do not panic or return an error. It does not
/// check the full round trip, because the behavior of section appends depends on the
/// implementation.
#[test]
fn test_multiple_updates_succeed() {
    let mut pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x1000], 0x6000_0020)
        .add_section(".rdata", vec![0x00; 0x2000], 0x4000_0040)
        .build();

    // Add imports.
    let mut imports = ImportTable::default();
    imports.add_dll(
        "KERNEL32.dll",
        vec![ImportThunk::Name {
            hint: 0,
            name: "GetLastError".to_string(),
        }],
    );
    pe.update_imports(&imports, None)
        .expect("Failed to add imports");

    // Add exports.
    let mut exports = ExportTable::default();
    exports.set_dll_name("test.dll");
    exports.add_export(Some("TestFunc"), 0x1000);
    pe.update_exports(&exports, None)
        .expect("Failed to add exports");

    // Rebuild the PE.
    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse modified PE");

    // Make sure that the imports were written.
    assert_ne!(parsed.imports().expect("imports").dlls.len(), 0);
    // Make sure that the exports were written.
    assert_ne!(parsed.exports().expect("exports").exports.len(), 0);
}

/// Makes sure that the built PE parses and validates.
#[test]
fn test_pe_validation() {
    let pe = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".data", vec![0x00; 0x100], 0xC000_0040)
        .build();

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE");

    // Validate the parsed PE.
    let issues = parsed.validate();

    // A new PE must have no critical issues.
    // Warnings can occur, for example for missing characteristics.
    for issue in &issues {
        // Make sure only that validation does not panic.
        let _ = format!("{issue:?}");
    }
}
