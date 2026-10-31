//! Tests for the IAT keep rule of `update_imports`, `update_delay_imports` and
//! `rebuild_supported_directories`.
//!
//! Code calls an imported function through its IAT slot. A rebuilt import table must keep the
//! IAT of each DLL whose function list is unchanged.

use portex::section::{Section, characteristics};
use portex::{
    DelayImportDirectory, DelayLoadDescriptor, DelayLoadedDll, ImportTable, ImportThunk,
    MachineType, PeBuilder, PeImage, Subsystem, data_dir::DataDirectoryType,
};

/// Build an image with `.text`, `.rdata` and `.data`. `.rdata` has free space for the tables.
fn base_image(machine: MachineType) -> PeImage {
    PeBuilder::new()
        .machine(machine)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".rdata", vec![0; 0x100], 0x4000_0040)
        .add_section(".data", vec![0; 0x200], 0xC000_0040)
        .build()
}

fn reparse(image: &PeImage) -> PeImage {
    PeImage::parse(&image.try_build().unwrap()).unwrap()
}

fn named(name: &str) -> ImportThunk {
    ImportThunk::Name {
        hint: 0,
        name: name.to_string(),
    }
}

/// Build an image with imports from two DLLs in `.rdata`.
fn image_with_imports(machine: MachineType) -> PeImage {
    let mut image = base_image(machine);
    let mut imports = ImportTable::default();
    imports.add_dll("KERNEL32.dll", vec![named("ExitProcess"), named("Sleep")]);
    imports.add_dll(
        "USER32.dll",
        vec![named("MessageBoxA"), ImportThunk::Ordinal(7)],
    );
    image.update_imports(&imports, Some(1)).unwrap();
    reparse(&image)
}

fn first_thunks(image: &PeImage) -> Vec<(String, u32)> {
    image
        .imports()
        .unwrap()
        .dlls
        .into_iter()
        .map(|dll| (dll.name, dll.descriptor.first_thunk))
        .collect()
}

const MACHINES: [MachineType; 2] = [MachineType::I386, MachineType::Amd64];

#[test]
fn update_imports_with_the_parsed_table_keeps_every_iat() {
    for machine in MACHINES {
        let mut image = image_with_imports(machine);
        let before = first_thunks(&image);
        let iat_directory = image.data_directory(DataDirectoryType::Iat).copied();
        let imports = image.imports().unwrap();

        // Before the fix, each `first_thunk` moved to the new table.
        let rva = image.update_imports(&imports, None).unwrap();
        let image = reparse(&image);
        assert_ne!(rva, imports.dlls[0].descriptor.original_first_thunk);
        assert_eq!(first_thunks(&image), before);
        assert_eq!(
            image.imports().unwrap().dlls[1].imports,
            imports.dlls[1].imports
        );
        assert_eq!(
            image.data_directory(DataDirectoryType::Iat).copied(),
            iat_directory
        );
    }
}

#[test]
fn rebuild_supported_directories_keeps_every_iat() {
    for machine in MACHINES {
        let mut image = image_with_imports(machine);
        let before = first_thunks(&image);

        // Before the fix, the rebuild moved each IAT (for example from 0x2048 to 0x2238).
        image.rebuild_supported_directories(None).unwrap();
        let image = reparse(&image);
        assert_eq!(first_thunks(&image), before);
    }
}

#[test]
fn only_new_and_changed_dlls_get_a_new_iat() {
    for machine in MACHINES {
        let mut image = image_with_imports(machine);
        let before = first_thunks(&image);
        let mut imports = image.imports().unwrap();
        imports.add_named_import("USER32.dll", "MessageBoxW", 0);
        imports.add_dll("ADVAPI32.dll", vec![named("RegCloseKey")]);

        // `.rdata` holds the kept IATs and has space for the new data.
        image.update_imports(&imports, Some(1)).unwrap();
        let after = first_thunks(&reparse(&image));
        assert_eq!(after.len(), 3);
        // KERNEL32 is unchanged and keeps its IAT.
        assert_eq!(after[0], before[0]);
        // USER32 has a new function, so it gets a new IAT. ADVAPI32 is new.
        assert_ne!(after[1].1, before[1].1);
        assert!(after[1].1 > before[1].1 && after[2].1 > before[1].1);
        if machine == MachineType::Amd64 {
            assert!(after.iter().all(|(_, rva)| rva % 8 == 0));
        }
        // The IAT data directory includes the kept IAT and the new IATs.
        let iat = *image.data_directory(DataDirectoryType::Iat).unwrap();
        assert_eq!(iat.virtual_address, before[0].1);
        assert!(iat.virtual_address + iat.size > after[2].1);
    }
}

/// Return a zeroed delay-load descriptor.
fn zero_descriptor() -> DelayLoadDescriptor {
    DelayLoadDescriptor {
        attributes: 0,
        dll_name_rva: 0,
        module_handle_rva: 0,
        import_address_table_rva: 0,
        import_name_table_rva: 0,
        bound_import_address_table_rva: 0,
        unload_information_table_rva: 0,
        time_date_stamp: 0,
    }
}

/// Build an image with two delay-loaded DLLs. Give each descriptor a bound IAT, an unload IAT
/// and a time stamp.
///
/// As in an MSVC image, the IATs and the module handles are in the writable `.data`, and the
/// descriptors and the names are in `.rdata`.
fn image_with_delay_imports(machine: MachineType) -> PeImage {
    let mut image = base_image(machine);
    let dll = |name: &str, imports| DelayLoadedDll {
        descriptor: zero_descriptor(),
        name: name.to_string(),
        imports,
    };
    let directory = DelayImportDirectory {
        dlls: vec![
            dll("a.dll", vec![named("A1"), ImportThunk::Ordinal(2)]),
            dll("b.dll", vec![named("B1")]),
        ],
    };
    image.update_delay_imports(&directory, Some(2)).unwrap();
    let mut image = reparse(&image);
    let directory = image.delay_imports().unwrap();
    let rva = image.update_delay_imports(&directory, Some(1)).unwrap();
    for (index, value) in [0x3000u32, 0x3100].into_iter().enumerate() {
        let descriptor = rva + u32::try_from(index * DelayLoadDescriptor::SIZE).unwrap();
        let fields: Vec<u8> = [value, value + 0x40, 0x5EED_0000 + value]
            .iter()
            .flat_map(|field| field.to_le_bytes())
            .collect();
        image.write_at_rva(descriptor + 20, &fields).unwrap();
    }
    // The data directory holds only the descriptors, as in an MSVC image.
    let descriptors = u32::try_from(3 * DelayLoadDescriptor::SIZE).unwrap();
    image.set_data_directory(DataDirectoryType::DelayImport, rva, descriptors);
    reparse(&image)
}

fn kept_fields(image: &PeImage) -> Vec<[u32; 5]> {
    image
        .delay_imports()
        .unwrap()
        .dlls
        .iter()
        .map(|dll| {
            let descriptor = &dll.descriptor;
            [
                descriptor.module_handle_rva,
                descriptor.import_address_table_rva,
                descriptor.bound_import_address_table_rva,
                descriptor.unload_information_table_rva,
                descriptor.time_date_stamp,
            ]
        })
        .collect()
}

#[test]
fn update_delay_imports_with_the_parsed_directory_keeps_the_tables() {
    for machine in MACHINES {
        let mut image = image_with_delay_imports(machine);
        let before = kept_fields(&image);
        assert_eq!(before[1][4], 0x5EED_3100);
        let directory = image.delay_imports().unwrap();

        // Before the fix, the IAT and the module handle moved, and the bound IAT, the unload
        // IAT and the time stamp became zero.
        image.update_delay_imports(&directory, None).unwrap();
        let rebuilt = reparse(&image);
        assert_eq!(kept_fields(&rebuilt), before);
        let parsed = rebuilt.delay_imports().unwrap();
        assert_eq!(parsed.dlls[0].imports, directory.dlls[0].imports);
        assert_ne!(
            parsed.dlls[0].descriptor.import_name_table_rva,
            directory.dlls[0].descriptor.import_name_table_rva
        );

        let mut image = image_with_delay_imports(machine);
        image.rebuild_supported_directories(None).unwrap();
        assert_eq!(kept_fields(&reparse(&image)), before);
    }
}

/// Build an image whose `.rdata` holds the imports of two DLLs and has no free space after
/// them. `.data` is writable, and the last section `.rsrc` is read-only.
fn image_with_full_rdata(machine: MachineType) -> PeImage {
    let read_data = characteristics::INITIALIZED_DATA | characteristics::READ;
    let mut image = PeBuilder::new()
        .machine(machine)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section_with_virtual_size(".rdata", vec![0; 0x100], 0x1000, read_data)
        .add_section(".data", vec![0; 0x200], read_data | characteristics::WRITE)
        .add_section(".rsrc", vec![0; 0x200], read_data)
        .build();
    // Write the first table in place at the start of `.rdata`.
    image.set_data_directory(DataDirectoryType::Import, 0x2000, 0x100);
    let mut imports = ImportTable::default();
    imports.add_dll("KERNEL32.dll", vec![named("ExitProcess"), named("Sleep")]);
    imports.add_dll("USER32.dll", vec![named("MessageBoxA")]);
    assert_eq!(image.update_imports(&imports, None).unwrap(), 0x2000);
    reparse(&image)
}

/// Return the section that holds `rva`.
fn section_of(image: &PeImage, rva: u32) -> &Section {
    image.section_by_rva(rva).unwrap()
}

#[test]
fn new_iats_outside_the_section_of_the_kept_iats_are_writable() {
    for machine in MACHINES {
        let mut image = image_with_full_rdata(machine);
        let kept_iats = *image.data_directory(DataDirectoryType::Iat).unwrap();
        assert_eq!(
            section_of(&image, kept_iats.virtual_address).name(),
            ".rdata"
        );
        let mut imports = image.imports().unwrap();
        imports.add_dll("ADVAPI32.dll", vec![named("RegCloseKey")]);

        // A named target that is not writable cannot hold the new IAT.
        let before = image.clone();
        assert!(image.update_imports(&imports, Some(3)).is_err());
        assert_eq!(image, before);

        // Before the fix, the new IAT went to the read-only last section, and the IAT data
        // directory was cleared. The loader then failed to write the kept IATs and the new IAT.
        // Now the new IAT goes to a new writable section.
        image.update_imports(&imports, None).unwrap();
        let image = reparse(&image);
        let parsed = image.imports().unwrap();
        assert_eq!(
            parsed.dlls[0].descriptor.first_thunk,
            kept_iats.virtual_address
        );
        let new_iat = parsed.dlls[2].descriptor.first_thunk;
        let section = section_of(&image, new_iat);
        assert_eq!(section.name(), ".portex");
        assert!(section.header.is_writable());
        // The IAT data directory holds the kept IATs, in `.rdata`.
        assert_eq!(
            image.data_directory(DataDirectoryType::Iat).copied(),
            Some(kept_iats)
        );
    }
}

#[test]
fn a_named_writable_target_gets_the_new_iats() {
    for machine in MACHINES {
        let mut image = image_with_full_rdata(machine);
        let kept_iats = *image.data_directory(DataDirectoryType::Iat).unwrap();
        let mut imports = image.imports().unwrap();
        imports.add_dll("ADVAPI32.dll", vec![named("RegCloseKey")]);

        image.update_imports(&imports, Some(2)).unwrap();
        let image = reparse(&image);
        let new_iat = image.imports().unwrap().dlls[2].descriptor.first_thunk;
        assert_eq!(section_of(&image, new_iat).name(), ".data");
        assert_eq!(
            image.data_directory(DataDirectoryType::Iat).copied(),
            Some(kept_iats)
        );
    }
}

/// Return an import list with `count` DLLs, each with long function names.
fn many_dlls(count: usize) -> Vec<(String, Vec<ImportThunk>)> {
    (0..count)
        .map(|index| {
            let functions = (0..4)
                .map(|function| named(&format!("LongFunctionName{index:03}With{function}")))
                .collect();
            (format!("library{index:03}.dll"), functions)
        })
        .collect()
}

/// Build an image with two delay-loaded DLLs. Their IATs and module handles are at the start
/// of `.data`. Their descriptors are at the end of a nearly full `.rdata`. The delay import
/// data directory holds only the descriptors, as in an MSVC image.
fn image_with_delay_tables_after_rdata(machine: MachineType) -> PeImage {
    let read_data = characteristics::INITIALIZED_DATA | characteristics::READ;
    let mut image = PeBuilder::new()
        .machine(machine)
        .add_section(".text", vec![0xCC; 0x200], 0x6000_0020)
        .add_section(".rdata", vec![1; 0x10], read_data)
        .add_section(".data", vec![1; 0x10], read_data | characteristics::WRITE)
        .build();
    let functions = |dll: &str| {
        (0..8)
            .map(|index| named(&format!("{dll}LongDelayLoadedFunctionName{index}")))
            .collect()
    };
    let directory = DelayImportDirectory {
        dlls: ["a", "b"]
            .into_iter()
            .map(|name| DelayLoadedDll {
                descriptor: zero_descriptor(),
                name: format!("{name}.dll"),
                imports: functions(name),
            })
            .collect(),
    };
    image.update_delay_imports(&directory, Some(2)).unwrap();
    let mut image = reparse(&image);
    let directory = image.delay_imports().unwrap();
    let rva = image.update_delay_imports(&directory, Some(1)).unwrap();
    let rdata = image.section_by_name(".rdata").unwrap();
    let used = rdata.header.virtual_size.next_multiple_of(8);
    let filler = vec![0xAA; usize::try_from(0x1000 - used - 0x20).unwrap()];
    image.try_append_to_section(1, &filler).unwrap();
    let descriptors = u32::try_from(3 * DelayLoadDescriptor::SIZE).unwrap();
    image.set_data_directory(DataDirectoryType::DelayImport, rva, descriptors);
    reparse(&image)
}

#[test]
fn a_kept_delay_table_after_the_selected_section_is_an_error() {
    for machine in MACHINES {
        let mut image = image_with_delay_tables_after_rdata(machine);
        let before = kept_fields(&image);
        assert_eq!(section_of(&image, before[0][1]).name(), ".data");
        let directory = image.delay_imports().unwrap();

        // The data at the end of `.rdata` would cover the kept IATs in `.data`.
        let unchanged = image.clone();
        assert!(image.update_delay_imports(&directory, Some(1)).is_err());
        assert_eq!(image, unchanged);

        // Each DLL keeps its tables, so the new section for the data is not writable.
        let rva = image.update_delay_imports(&directory, None).unwrap();
        let image = reparse(&image);
        let section = section_of(&image, rva);
        assert_eq!(section.name(), ".portex");
        assert!(!section.header.is_writable());
        assert_eq!(kept_fields(&image), before);
    }
}

#[test]
fn new_delay_tables_need_a_writable_section() {
    for machine in MACHINES {
        let mut image = image_with_delay_imports(machine);
        let before = kept_fields(&image);
        let mut directory = image.delay_imports().unwrap();
        directory.dlls.push(DelayLoadedDll {
            descriptor: zero_descriptor(),
            name: "c.dll".to_string(),
            imports: vec![named("C1")],
        });

        // A selected section that is not writable cannot hold the new IAT and module handle.
        let unchanged = image.clone();
        assert!(image.update_delay_imports(&directory, Some(1)).is_err());
        assert_eq!(image, unchanged);

        // Before the fix, the new tables went to the read-only `.rdata`. The delay-load helper
        // then failed to write the IAT slot and the module handle. Now they go to a new
        // writable section.
        image.update_delay_imports(&directory, None).unwrap();
        let image = reparse(&image);
        assert_eq!(kept_fields(&image)[..2], before[..]);
        let new = image.delay_imports().unwrap().dlls[2].descriptor;
        for rva in [new.import_address_table_rva, new.module_handle_rva] {
            assert!(section_of(&image, rva).header.is_writable());
        }
    }
}

#[test]
fn a_kept_iat_after_the_selected_section_is_an_error() {
    for machine in MACHINES {
        // Put the IATs in `.data`, then move the descriptors to `.rdata`.
        let mut image = base_image(machine);
        let mut imports = ImportTable::default();
        imports.add_dll("KERNEL32.dll", vec![named("ExitProcess")]);
        image.update_imports(&imports, Some(2)).unwrap();
        let mut image = reparse(&image);
        let imports = image.imports().unwrap();
        image.update_imports(&imports, Some(1)).unwrap();
        let mut image = reparse(&image);
        let kept = first_thunks(&image);
        assert_eq!(section_of(&image, kept[0].1).name(), ".data");

        let mut imports = image.imports().unwrap();
        for (name, functions) in many_dlls(40) {
            imports.add_dll(&name, functions);
        }
        // The data at the end of `.rdata` would cover the kept IAT in `.data`.
        let unchanged = image.clone();
        assert!(image.update_imports(&imports, Some(1)).is_err());
        assert_eq!(image, unchanged);

        let rva = image.update_imports(&imports, None).unwrap();
        let image = reparse(&image);
        assert_eq!(section_of(&image, rva).name(), ".portex");
        assert_eq!(first_thunks(&image)[0], kept[0]);
    }
}
