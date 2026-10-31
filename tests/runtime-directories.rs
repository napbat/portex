//! Regression tests for the runtime directories: TLS, load configuration, exception and CLR.

use portex::directories::{
    ExceptionDirectory, LoadConfigDirectory, LoadConfigDirectory32, LoadConfigDirectory64,
    RelocationTable, RelocationType, RuntimeFunction, TlsDirectory, TlsDirectory32, TlsDirectory64,
    TlsInfo,
};
use portex::headers::{DataDirectoryType, MachineType};
use portex::image::{PeBuilder, PeImage};
use portex::section::characteristics;

/// Build an image with `.text`, `.rdata` and `.reloc`, and a base relocation directory with
/// one entry at `0x1010`.
fn relocatable_image(machine: MachineType) -> PeImage {
    let mut image = PeBuilder::new()
        .machine(machine)
        .add_section(
            ".text",
            vec![0xcc; 0x100],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".rdata",
            vec![0; 0x100],
            characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
        )
        .add_section(
            ".reloc",
            vec![0; 0x10],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    let mut relocations = RelocationTable::default();
    if image.is_64bit() {
        relocations.add_dir64(0x1010);
    } else {
        relocations.add_highlow(0x1010);
    }
    image.update_relocations(&relocations, Some(2)).unwrap();
    image
}

/// Return the RVA and type of each relocation in the image.
fn relocation_rvas(image: &PeImage) -> Vec<(u32, RelocationType)> {
    let table = image.relocations().unwrap();
    table
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .entries
                .iter()
                .filter(|entry| !entry.is_padding())
                .map(|&entry| {
                    (
                        block.checked_rva_for_entry(entry).unwrap(),
                        entry.reloc_type,
                    )
                })
        })
        .collect()
}

/// Before the fix, `update_tls` wrote VAs at a new RVA without base relocations, and it
/// replaced the original `AddressOfIndex`. A rebased mapping then held VAs of the preferred
/// base.
#[test]
fn moved_pe32_plus_tls_gets_relocations_and_keeps_its_index() {
    let mut image = relocatable_image(MachineType::Amd64);
    let base = image.image_base();
    let tls = TlsInfo {
        directory: Some(TlsDirectory::Tls64(TlsDirectory64 {
            start_address_of_raw_data: base + 0x2000,
            end_address_of_raw_data: base + 0x2010,
            address_of_index: base + 0x2080,
            ..TlsDirectory64::default()
        })),
        callback_rvas: vec![0x1000, 0x1020],
        image_base: base,
    };
    let tls_rva = image.update_tls(&tls, Some(1)).unwrap();

    let relocations = relocation_rvas(&image);
    assert!(relocations.contains(&(0x1010, RelocationType::Dir64)));
    // Start, end, index, callback array, then two callbacks at offset 48.
    for offset in [0, 8, 16, 24, 48, 56] {
        assert!(
            relocations.contains(&(tls_rva + offset, RelocationType::Dir64)),
            "no relocation at TLS offset {offset}"
        );
    }
    assert!(!relocations.contains(&(tls_rva + 64, RelocationType::Dir64)));

    let runtime = base + 0x10_0000;
    let mapped = image.to_mapped_image_at(runtime).unwrap();
    let parsed = PeImage::parse_mapped_at(&mapped, runtime).unwrap();
    let parsed_tls = parsed.tls().unwrap().unwrap();
    assert_eq!(parsed_tls.callback_rvas, [0x1000, 0x1020]);
    let Some(TlsDirectory::Tls64(directory)) = parsed_tls.directory else {
        panic!("expected a PE32+ TLS directory");
    };
    assert_eq!(directory.start_address_of_raw_data, runtime + 0x2000);
    assert_eq!(directory.end_address_of_raw_data, runtime + 0x2010);
    assert_eq!(directory.address_of_index, runtime + 0x2080);
}

#[test]
fn moved_pe32_tls_gets_highlow_relocations() {
    let mut image = relocatable_image(MachineType::I386);
    let base = u32::try_from(image.image_base()).unwrap();
    let tls = TlsInfo {
        directory: Some(TlsDirectory::Tls32(TlsDirectory32 {
            address_of_index: base + 0x2080,
            ..TlsDirectory32::default()
        })),
        callback_rvas: vec![0x1000],
        image_base: u64::from(base),
    };
    let tls_rva = image.update_tls(&tls, None).unwrap();
    let relocations = relocation_rvas(&image);
    // Index, callback array, then one callback at offset 28. The raw data range is zero.
    for offset in [8, 12, 28] {
        assert!(relocations.contains(&(tls_rva + offset, RelocationType::HighLow)));
    }
    assert!(!relocations.contains(&(tls_rva, RelocationType::HighLow)));
}

/// An image without a base relocation directory gets no relocations.
#[test]
fn image_without_relocations_gets_none() {
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".rdata",
            vec![0; 0x100],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    let base = image.image_base();
    let mut config = LoadConfigDirectory64::default();
    config.security_cookie = base + 0x1000;
    image
        .update_load_config(&LoadConfigDirectory::Config64(config), None)
        .unwrap();
    assert!(
        image
            .data_directory(DataDirectoryType::BaseReloc)
            .is_none_or(|directory| !directory.is_present())
    );
}

/// Before the fix, `update_load_config` moved the security cookie and CFG pointers without
/// base relocations.
#[test]
fn moved_load_config_gets_relocations() {
    let mut image = relocatable_image(MachineType::I386);
    let base = u32::try_from(image.image_base()).unwrap();
    let mut config = LoadConfigDirectory32::default();
    config.size = u32::try_from(LoadConfigDirectory32::SIZE_WITH_CFG).unwrap();
    config.security_cookie = base + 0x2000;
    config.se_handler_table = base + 0x2010;
    config.se_handler_count = 1;
    config.guard_cf_check_function_pointer = base + 0x2020;
    let rva = image
        .update_load_config(&LoadConfigDirectory::Config32(config), Some(1))
        .unwrap();

    let relocations = relocation_rvas(&image);
    for offset in [60, 64, 72] {
        assert!(
            relocations.contains(&(rva + offset, RelocationType::HighLow)),
            "no relocation at load-config offset {offset}"
        );
    }
    assert!(!relocations.contains(&(rva + 68, RelocationType::HighLow)));

    let runtime = u64::from(base) + 0x10_0000;
    let mapped = image.to_mapped_image_at(runtime).unwrap();
    let parsed = PeImage::parse_mapped_at(&mapped, runtime).unwrap();
    let Some(LoadConfigDirectory::Config32(parsed)) = parsed.load_config().unwrap() else {
        panic!("expected a PE32 load config");
    };
    assert_eq!(u64::from(parsed.security_cookie), runtime + 0x2000);
    assert_eq!(u64::from(parsed.se_handler_table), runtime + 0x2010);
    assert_eq!(parsed.se_handler_count, 1);
}

/// Before the fix, `update_exception` wrote AMD64 records into an image of any machine.
#[test]
fn update_exception_requires_an_amd64_image() {
    let directory = ExceptionDirectory {
        functions: vec![
            RuntimeFunction {
                begin_address: 0x1008,
                end_address: 0x1010,
                unwind_info_address: 0x2000,
            },
            RuntimeFunction {
                begin_address: 0x1000,
                end_address: 0x1004,
                unwind_info_address: 0x2000,
            },
        ],
    };
    let mut arm64 = PeBuilder::new()
        .machine(MachineType::Arm64)
        .add_section(
            ".pdata",
            vec![0; 0x10],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    assert!(arm64.update_exception(&directory, None).is_err());

    let mut amd64 = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".pdata",
            vec![0; 0x10],
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    amd64.update_exception(&directory, None).unwrap();
    let parsed = amd64.exception_directory().unwrap();
    assert_eq!(parsed.functions[0].begin_address, 0x1000);
    assert_eq!(parsed.functions[1].begin_address, 0x1008);
}

/// Before the fix, the error said that only one of the values was set, also when both were
/// zero.
#[test]
fn clr_metadata_reports_a_zero_rva_or_size() {
    let mut header = vec![0; 72];
    header[..4].copy_from_slice(&72_u32.to_le_bytes());
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(
            ".rdata",
            header,
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    let rva = image
        .section_by_name(".rdata")
        .unwrap()
        .header
        .virtual_address;
    image.set_data_directory(DataDirectoryType::ClrRuntime, rva, 72);
    let error = image.clr_metadata().unwrap_err();
    let message = error.to_string();
    assert!(!message.contains("only one"), "{message}");
    assert!(message.contains("zero metadata RVA or a zero metadata size"));
}
