//! Regression tests for the append of a directory table: the fallback section, the reuse of
//! zero raw padding, and the atomic updates of the TLS and load configuration directories.

use portex::directories::RelocationTable;
use portex::directories::{
    LoadConfigDirectory, LoadConfigDirectory64, TlsDirectory, TlsDirectory64, TlsInfo,
};
use portex::headers::{DataDirectoryType, MachineType};
use portex::image::{PeBuilder, PeImage};
use portex::section::characteristics;
use portex::{ExportTable, ImportTable, ImportThunk};

const READ_DATA: u32 = characteristics::INITIALIZED_DATA | characteristics::READ;

/// Return an export table that needs more than one page.
fn large_exports() -> ExportTable {
    let mut exports = ExportTable::default();
    exports.set_dll_name("large.dll");
    for index in 0..400 {
        exports.add_export(Some(&format!("ExportedFunction{index:04}")), 0x1000);
    }
    exports
}

/// Build `.text`, a full `.rdata` and a last section with the given name and flags.
fn image_with_last_section(name: &str, flags: u32) -> PeImage {
    PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section_with_virtual_size(".rdata", vec![1; 16], 0x1000, READ_DATA)
        .add_section(name, vec![2; 16], flags)
        .try_build()
        .unwrap()
}

#[test]
fn the_fallback_does_not_use_a_discardable_or_resource_section() {
    for (name, flags) in [
        (".reloc", READ_DATA | characteristics::DISCARDABLE),
        (".rsrc", READ_DATA),
    ] {
        let mut image = image_with_last_section(name, flags);
        // Before the fix, the table went to the last section.
        let rva = image.update_exports(&large_exports(), None).unwrap();
        assert_eq!(image.sections.len(), 4);
        let added = &image.sections[3];
        assert_eq!(added.name(), ".portex");
        assert_eq!(added.header.virtual_address, 0x4000);
        assert_eq!(added.header.characteristics, READ_DATA);
        assert_eq!(rva, 0x4000);
        let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
        assert_eq!(rebuilt.exports().unwrap().exports.len(), 400);
    }
}

#[test]
fn the_fallback_uses_a_readable_last_section() {
    let mut image = image_with_last_section(".data", READ_DATA | characteristics::WRITE);
    let rva = image.update_exports(&large_exports(), None).unwrap();
    assert_eq!(image.sections.len(), 3);
    assert_eq!(image.section_by_rva(rva).unwrap().name(), ".data");
}

/// Build `.text` and `.rdata`. `.rdata` has 0x200 raw bytes, and its `VirtualSize` is 0x10.
/// The raw bytes after `VirtualSize` are zero padding, except for the bytes in `extra`.
fn image_with_raw_padding(extra: &[(usize, u8)]) -> PeImage {
    let mut data = vec![0; 0x200];
    data[..0x10].fill(1);
    for &(offset, value) in extra {
        data[offset] = value;
    }
    let mut image = PeBuilder::new()
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section(".rdata", data, READ_DATA)
        .add_section(".data", vec![2; 16], READ_DATA | characteristics::WRITE)
        .try_build()
        .unwrap();
    // A linker writes a `VirtualSize` without the raw padding.
    image.sections[1].header.virtual_size = 0x10;
    image
}

#[test]
fn an_append_reuses_zero_raw_padding() {
    let mut image = image_with_raw_padding(&[]);

    // Before the fix, the append went after the 0x200 raw bytes.
    assert_eq!(
        image.try_append_to_section(".rdata", &[7; 8]).unwrap(),
        0x2010
    );
    let rdata = &image.sections[1];
    assert_eq!(rdata.data.len(), 0x200);
    assert_eq!(rdata.header.virtual_size, 0x18);
    assert_eq!(&rdata.data[0x10..0x18], &[7; 8]);
}

#[test]
fn an_append_does_not_overwrite_nonzero_bytes_after_the_virtual_size() {
    let mut image = image_with_raw_padding(&[(0x100, 0xaa)]);

    assert_eq!(
        image.try_append_to_section(".rdata", &[7; 8]).unwrap(),
        0x2108
    );
    let rdata = &image.sections[1];
    assert_eq!(rdata.data[0x100], 0xaa);
    assert_eq!(&rdata.data[0x108..0x110], &[7; 8]);
    assert_eq!(rdata.header.virtual_size, 0x110);
}

/// Build a PE32+ image with `SectionAlignment` 0x200 and a full section table. `.reloc` is
/// full and is not the last section. The last section has uninitialized data, so a fallback
/// needs a new section, but the headers have no space for it.
fn image_with_full_headers() -> PeImage {
    let mut reloc = vec![0u8; 0x200];
    reloc[4..8].copy_from_slice(&12u32.to_le_bytes());
    let mut builder = PeBuilder::new()
        .machine(MachineType::Amd64)
        .file_alignment(0x200)
        .section_alignment(0x200)
        .add_section(".text", vec![0xcc; 0x100], characteristics::CODE);
    for index in 0..11 {
        builder = builder.add_section(&format!(".d{index}"), vec![0; 0x10], READ_DATA);
    }
    let mut image = builder
        .add_section_with_virtual_size(".rdata", vec![0; 0x100], 0x100, READ_DATA)
        .add_section_with_virtual_size(".reloc", reloc, 0x200, READ_DATA)
        .add_section_with_virtual_size(
            ".bss",
            Vec::new(),
            0x200,
            characteristics::UNINITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    // One DIR64 relocation in `.text` (page 0) and one padding entry.
    let text = image.sections[0].header.virtual_address;
    let reloc_rva = image
        .section_by_name(".reloc")
        .unwrap()
        .header
        .virtual_address;
    let entry = (10u16 << 12) | u16::try_from(text + 0x10).unwrap();
    image
        .write_at_rva(reloc_rva + 8, &entry.to_le_bytes())
        .unwrap();
    image.set_data_directory(DataDirectoryType::BaseReloc, reloc_rva, 12);
    assert_eq!(image.relocations().unwrap().blocks.len(), 1);
    image
}

#[test]
fn a_failed_relocation_update_leaves_the_tls_unchanged() {
    let mut image = image_with_full_headers();
    let base = image.image_base();
    let tls = TlsInfo {
        directory: Some(TlsDirectory::Tls64(TlsDirectory64 {
            start_address_of_raw_data: base + 0x1000,
            end_address_of_raw_data: base + 0x1010,
            address_of_index: base + 0x1080,
            ..TlsDirectory64::default()
        })),
        callback_rvas: vec![],
        image_base: base,
    };
    let before = image.clone();
    // The TLS block fits in `.rdata`, but its relocations fit nowhere. Before the fix, the
    // TLS directory pointed to the new block without relocations.
    assert!(image.update_tls(&tls, Some(".rdata")).is_err());
    assert_eq!(image, before);
}

#[test]
fn a_failed_relocation_update_leaves_the_load_config_unchanged() {
    let mut image = image_with_full_headers();
    let mut config = LoadConfigDirectory64::default();
    config.size = 0x94;
    config.security_cookie = image.image_base() + 0x1100;
    let before = image.clone();
    assert!(
        image
            .update_load_config(&LoadConfigDirectory::Config64(config), Some(".rdata"))
            .is_err()
    );
    assert_eq!(image, before);
}

#[test]
fn a_failed_fallback_does_not_add_a_section() {
    // The section table is full, so the fallback cannot add a section.
    let mut image = image_with_full_headers();
    let before = image.clone();
    assert!(image.update_exports(&large_exports(), None).is_err());
    assert_eq!(image, before);
}

#[test]
fn an_added_fallback_section_gets_the_data_at_its_start() {
    // The last section ends 0x4000 bytes before the end of the RVA range. The exports need
    // 0x2486 bytes. Before the fix, the data started one page after the start of the added
    // section, so it did not fit, and the empty section stayed in the image.
    let mut exports = large_exports();
    exports.exports.truncate(300);
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section_with_virtual_size(".rdata", vec![1; 16], 0x1000, READ_DATA)
        .add_section_with_virtual_size(
            ".bss",
            Vec::new(),
            0xFFFF_9000,
            characteristics::UNINITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    let rva = image.update_exports(&exports, None).unwrap();
    assert_eq!(image.sections.len(), 4);
    assert_eq!(image.sections[3].header.virtual_address, 0xFFFF_C000);
    assert_eq!(rva, 0xFFFF_C000);
}

#[test]
fn rebuild_does_not_put_tables_in_a_discardable_last_section() {
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(".text", vec![0xc3; 0x100], characteristics::CODE)
        .add_section(".rdata", vec![1; 16], READ_DATA)
        .add_section(".data", vec![2; 16], READ_DATA | characteristics::WRITE)
        .add_section(
            ".reloc",
            vec![0; 16],
            READ_DATA | characteristics::DISCARDABLE,
        )
        .try_build()
        .unwrap();
    let mut imports = ImportTable::default();
    imports.add_dll(
        "KERNEL32.dll",
        vec![ImportThunk::Name {
            hint: 0,
            name: "ExitProcess".to_string(),
        }],
    );
    image.update_imports(&imports, Some(".rdata")).unwrap();
    let mut exports = ExportTable::default();
    exports.set_dll_name("rebuild.dll");
    exports.add_export(Some("Function"), 0x1000);
    image.update_exports(&exports, Some(".rdata")).unwrap();
    let mut relocations = RelocationTable::default();
    relocations.add_dir64(0x1010);
    image
        .update_relocations(&relocations, Some(".reloc"))
        .unwrap();
    let base = image.image_base();
    let tls = TlsInfo {
        directory: Some(TlsDirectory::Tls64(TlsDirectory64 {
            address_of_index: base + 0x3000,
            ..TlsDirectory64::default()
        })),
        callback_rvas: vec![0x1000],
        image_base: base,
    };
    image.update_tls(&tls, Some(".rdata")).unwrap();
    let mut image = PeImage::parse(&image.try_build().unwrap()).unwrap();

    // Before the fix, the rebuild put every table in the last section, `.reloc`. The base
    // relocations can stay in `.reloc`: the loader uses them only while it loads the image.
    image.rebuild_supported_directories(None).unwrap();
    let image = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(image.sections.len(), 5);
    assert_eq!(image.sections[4].name(), ".portex");
    for directory in [
        DataDirectoryType::Import,
        DataDirectoryType::Iat,
        DataDirectoryType::Export,
        DataDirectoryType::Tls,
    ] {
        let rva = image.data_directory(directory).unwrap().virtual_address;
        let section = image.section_by_rva(rva).unwrap();
        assert_eq!(
            section.header.characteristics & characteristics::DISCARDABLE,
            0,
            "{directory:?} is in section '{}'",
            section.name()
        );
    }
    assert_eq!(image.exports().unwrap().exports.len(), 1);
    assert_eq!(image.tls().unwrap().unwrap().callback_rvas, [0x1000]);
}
