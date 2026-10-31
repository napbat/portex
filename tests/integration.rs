//! Integration tests for the portex PE library.
//!
//! Each test does a round trip: it creates or parses an image, changes it, rebuilds it and
//! parses it again.

use portex::{
    DebugType, ExceptionDirectory, ExportAddress, ExportTable, ImportTable, ImportThunk,
    MachineType, PeBuilder, PeImage, RelocationTable, RelocationType, Subsystem, TlsDirectory,
    TlsDirectory64,
    data_dir::DataDirectoryType,
    debug::CodeViewRsds,
    loadconfig::{LoadConfigDirectory, LoadConfigDirectory32, LoadConfigDirectory64},
    section::characteristics,
    tls::TlsInfo,
};

/// Return the DLL names and the thunks of `table`, without the descriptors.
///
/// The descriptors hold RVAs that the layout selects. Thus a round trip compares only the
/// names and the thunks.
fn import_entries(table: &ImportTable) -> Vec<(&str, &[ImportThunk])> {
    table
        .dlls
        .iter()
        .map(|dll| (dll.name.as_str(), dll.imports.as_slice()))
        .collect()
}

/// Return the ordinal, the name and the address of each export of `table`.
fn export_entries(table: &ExportTable) -> Vec<(u32, Option<&str>, &ExportAddress)> {
    table
        .exports
        .iter()
        .map(|export| (export.ordinal, export.name.as_deref(), &export.address))
        .collect()
}

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
    assert_eq!(import_entries(&parsed_imports), import_entries(&imports));
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
    assert_eq!(parsed_exports.dll_name, "TestModule.dll");
    assert_eq!(export_entries(&parsed_exports), export_entries(&exports));
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

    // Create the relocation table. The blocks are not in page order, and one block has an
    // odd number of entries.
    let mut relocs = RelocationTable::default();
    relocs.add_relocation(0x2000, RelocationType::HighLow);
    relocs.add_relocation(0x1008, RelocationType::Dir64);
    relocs.add_relocation(0x1000, RelocationType::Dir64);
    relocs.add_relocation(0x1010, RelocationType::Dir64);

    pe.update_relocations(&relocs, None)
        .expect("Failed to update relocations");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with relocations");

    // The image holds the normalized table: the blocks are in page order and each block is
    // padded to 4 bytes. The entries of a block keep their order.
    let parsed_relocs = parsed.relocations().expect("Failed to get relocations");
    assert_eq!(parsed_relocs, relocs.normalized());
    assert_eq!(parsed_relocs.relocation_count(), 4);
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
    let image_base = pe.image_base();
    let text_rva = pe
        .section_by_name(".text")
        .expect(".text")
        .header
        .virtual_address;
    let tls_rva = pe
        .section_by_name(".tls")
        .expect(".tls")
        .header
        .virtual_address;
    let va = |rva: u32| image_base + u64::from(rva);

    // Set each directory field. The builder selects the callback array address.
    let directory = TlsDirectory64 {
        start_address_of_raw_data: va(tls_rva),
        end_address_of_raw_data: va(tls_rva + 0x10),
        address_of_index: va(tls_rva + 0x20),
        address_of_callbacks: 0,
        size_of_zero_fill: 0x40,
        characteristics: 0x0030_0000, // IMAGE_SCN_ALIGN_4BYTES
    };
    let tls_info = TlsInfo {
        directory: Some(TlsDirectory::Tls64(directory)),
        callback_rvas: vec![text_rva, text_rva + 0x10],
        image_base,
    };

    pe.update_tls(&tls_info, None)
        .expect("Failed to update TLS");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with TLS");

    let tls = parsed
        .tls()
        .expect("Failed to get TLS")
        .expect("the TLS directory is present");
    assert_eq!(tls.callback_rvas, tls_info.callback_rvas);
    assert_eq!(tls.image_base, image_base);
    let Some(TlsDirectory::Tls64(parsed_directory)) = tls.directory else {
        panic!("expected a PE32+ TLS directory, got {:?}", tls.directory);
    };
    // The callback array is in the new TLS block, so its address is not zero.
    assert_ne!(parsed_directory.address_of_callbacks, 0);
    assert_eq!(
        parsed_directory,
        TlsDirectory64 {
            address_of_callbacks: parsed_directory.address_of_callbacks,
            ..directory
        }
    );
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

    let debug_info = parsed
        .debug_info()
        .expect("Failed to get debug info")
        .expect("the debug directory is present");
    assert_eq!(debug_info.directories.len(), 1);
    assert_eq!(
        debug_info.directories[0].get_type(),
        Some(DebugType::CodeView)
    );
    assert_eq!(
        debug_info.codeview().expect("the CodeView record parses"),
        Some(codeview)
    );
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

    // Create a `LoadConfig` with the CFG fields. Set each field to a value that is not zero.
    let mut config64 = LoadConfigDirectory64::default();
    config64.size = u32::try_from(LoadConfigDirectory64::SIZE_WITH_CFG).unwrap();
    config64.time_date_stamp = 0x6543_2100;
    config64.major_version = 10;
    config64.minor_version = 2;
    config64.global_flags_clear = 0x11;
    config64.global_flags_set = 0x22;
    config64.critical_section_default_timeout = 0x33;
    config64.de_commit_free_block_threshold = 0x1000;
    config64.de_commit_total_free_threshold = 0x2000;
    config64.lock_prefix_table = 0x0001_4000_1100;
    config64.maximum_allocation_size = 0x4000;
    config64.virtual_memory_threshold = 0x5000;
    config64.process_affinity_mask = 0x0f;
    config64.process_heap_flags = 0x44;
    config64.csd_version = 0x0105;
    config64.dependent_load_flags = 0x0800;
    config64.edit_list = 0x0001_4000_1200;
    config64.security_cookie = 0x0001_4000_2000; // VA of the security cookie
    config64.se_handler_table = 0x0001_4000_1300;
    config64.se_handler_count = 2;
    config64.guard_cf_check_function_pointer = 0x0001_4000_2008;
    config64.guard_cf_dispatch_function_pointer = 0x0001_4000_2010;
    config64.guard_cf_function_table = 0x0001_4000_2100;
    config64.guard_cf_function_count = 3;
    config64.guard_flags = 0x0001_0500;
    let loadconfig = LoadConfigDirectory::Config64(config64);

    pe.update_load_config(&loadconfig, None)
        .expect("Failed to update LoadConfig");

    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse PE with LoadConfig");

    let config = parsed.load_config().expect("Failed to get LoadConfig");
    assert_eq!(config, Some(loadconfig));
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

/// Makes sure that more than one update method can run on a PE, and that each later update
/// keeps the directories of the earlier updates.
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
        vec![
            ImportThunk::Name {
                hint: 7,
                name: "GetLastError".to_string(),
            },
            ImportThunk::Ordinal(42),
        ],
    );
    pe.update_imports(&imports, None)
        .expect("Failed to add imports");

    // Add exports.
    let mut exports = ExportTable::default();
    exports.set_dll_name("test.dll");
    exports.set_base(1);
    exports.add_export(Some("TestFunc"), 0x1000);
    exports.add_export(None, 0x1010);
    pe.update_exports(&exports, None)
        .expect("Failed to add exports");

    // Add relocations.
    let mut relocs = RelocationTable::default();
    relocs.add_relocation(0x1100, RelocationType::Dir64);
    relocs.add_relocation(0x1108, RelocationType::Dir64);
    pe.update_relocations(&relocs, None)
        .expect("Failed to add relocations");

    // Add debug information.
    let codeview = CodeViewRsds {
        guid: [0xa5; 16],
        age: 3,
        pdb_path: b"multi.pdb".to_vec(),
    };
    pe.update_debug_codeview(&codeview, None)
        .expect("Failed to add debug information");

    // Rebuild the PE.
    let bytes = pe.build();
    let parsed = PeImage::parse(&bytes).expect("Failed to parse modified PE");

    // Make sure that each directory parses back equal.
    let parsed_imports = parsed.imports().expect("imports");
    assert_eq!(import_entries(&parsed_imports), import_entries(&imports));
    let parsed_exports = parsed.exports().expect("exports");
    assert_eq!(parsed_exports.dll_name, "test.dll");
    assert_eq!(export_entries(&parsed_exports), export_entries(&exports));
    assert_eq!(
        parsed.relocations().expect("relocations"),
        relocs.normalized()
    );
    let debug_info = parsed
        .debug_info()
        .expect("debug information")
        .expect("the debug directory is present");
    assert_eq!(
        debug_info.codeview().expect("the CodeView record parses"),
        Some(codeview)
    );
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

    // A new PE must have no validation errors and no warnings.
    let result = parsed.validate();
    let issues: Vec<_> = result.errors().chain(result.warnings()).collect();
    assert!(
        issues.is_empty(),
        "unexpected validation issues: {issues:?}"
    );
}
