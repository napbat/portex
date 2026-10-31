//! Tests for the IAT keep rule of `update_imports`, `update_delay_imports` and
//! `rebuild_supported_directories`.
//!
//! Code calls an imported function through its IAT slot. A rebuilt import table must keep the
//! IAT of each DLL whose function list is unchanged.

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
    image.update_imports(&imports, Some(".rdata")).unwrap();
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

        image.update_imports(&imports, None).unwrap();
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
    let rva = image
        .update_delay_imports(&directory, Some(".rdata"))
        .unwrap();
    for (index, value) in [0x3000u32, 0x3100].into_iter().enumerate() {
        let descriptor = rva + u32::try_from(index * DelayLoadDescriptor::SIZE).unwrap();
        let fields: Vec<u8> = [value, value + 0x40, 0x5EED_0000 + value]
            .iter()
            .flat_map(|field| field.to_le_bytes())
            .collect();
        image.write_at_rva(descriptor + 20, &fields).unwrap();
    }
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
