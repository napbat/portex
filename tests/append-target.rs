//! Tests for the section that gets an appended directory table: a section that the caller
//! selects by its index, or a new section. Also the reuse of zero raw padding, the zero fill
//! limit and the atomic updates of the TLS and load configuration directories.

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

/// Return the parts of a section that an append to another section must not change.
fn content(image: &PeImage, index: usize) -> (u32, u32, u32, Vec<u8>) {
    let section = &image.sections[index];
    let header = &section.header;
    (
        header.virtual_address,
        header.virtual_size,
        header.characteristics,
        section.data.clone(),
    )
}

#[test]
fn an_update_without_a_section_adds_a_new_section() {
    for (name, flags) in [
        (".reloc", READ_DATA | characteristics::DISCARDABLE),
        (".rsrc", READ_DATA),
        (".data", READ_DATA | characteristics::WRITE),
    ] {
        let mut image = image_with_last_section(name, flags);
        let last = content(&image, 2);
        let rva = image.update_exports(&large_exports(), None).unwrap();
        assert_eq!(image.sections.len(), 4);
        let added = &image.sections[3];
        assert_eq!(added.name(), ".portex");
        assert_eq!(added.header.virtual_address, 0x4000);
        assert_eq!(added.header.characteristics, READ_DATA);
        assert_eq!(rva, 0x4000);
        // Before the change, the table went to a readable last section such as `.data`.
        assert_eq!(content(&image, 2), last, "{name}");
        let rebuilt = PeImage::parse(&image.try_build().unwrap()).unwrap();
        assert_eq!(rebuilt.exports().unwrap().exports.len(), 400);
    }
}

#[test]
fn an_update_does_not_reuse_a_section_with_the_new_section_name() {
    // The last section has the default name of a new section. It can come from the file or
    // from another tool, so an update must not treat it as free space.
    let mut image = image_with_last_section(".portex", READ_DATA);
    let existing = content(&image, 2);
    let rva = image.update_exports(&large_exports(), None).unwrap();
    assert_eq!(image.sections.len(), 4);
    assert_eq!(content(&image, 2), existing);
    assert_eq!(image.sections[3].name(), ".portex");
    assert_eq!(
        image.section_by_rva(rva).unwrap().header.virtual_address,
        0x4000
    );
}

#[test]
fn an_update_with_a_section_index_uses_that_section() {
    let mut image = image_with_last_section(".data", READ_DATA | characteristics::WRITE);
    let rva = image.update_exports(&large_exports(), Some(2)).unwrap();
    assert_eq!(image.sections.len(), 3);
    assert_eq!(rva, 0x3010);
    assert_eq!(image.section_by_rva(rva).unwrap().name(), ".data");
}

#[test]
fn a_section_index_out_of_range_is_an_error() {
    let mut image = image_with_last_section(".data", READ_DATA | characteristics::WRITE);
    let before = image.clone();
    assert!(image.update_exports(&large_exports(), Some(3)).is_err());
    assert!(image.try_append_to_section(3, &[1; 8]).is_err());
    assert!(image.rebuild_supported_directories(Some(3)).is_err());
    assert_eq!(image, before);
}

#[test]
fn the_new_section_has_the_configured_name() {
    let mut image = image_with_last_section(".data", READ_DATA | characteristics::WRITE);
    assert_eq!(image.append_section_name(), ".portex");
    image.try_set_append_section_name(Some(".edit")).unwrap();
    assert_eq!(image.append_section_name(), ".edit");
    image.update_exports(&large_exports(), None).unwrap();
    assert_eq!(image.sections[3].name(), ".edit");

    image.try_set_append_section_name(None).unwrap();
    assert_eq!(image.append_section_name(), ".portex");
}

#[test]
fn an_invalid_new_section_name_is_an_error() {
    let mut image = image_with_last_section(".data", READ_DATA);
    image.try_set_append_section_name(Some(".edit")).unwrap();
    for name in ["", ".toolong!", ".a\0b"] {
        assert!(image.try_set_append_section_name(Some(name)).is_err());
        assert_eq!(image.append_section_name(), ".edit");
    }
    // A name of 8 bytes uses the complete name field.
    image.try_set_append_section_name(Some("12345678")).unwrap();
    assert_eq!(image.append_section_name(), "12345678");
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
    assert_eq!(image.try_append_to_section(1, &[7; 8]).unwrap(), 0x2010);
    let rdata = &image.sections[1];
    assert_eq!(rdata.data.len(), 0x200);
    assert_eq!(rdata.header.virtual_size, 0x18);
    assert_eq!(&rdata.data[0x10..0x18], &[7; 8]);
}

#[test]
fn an_append_does_not_overwrite_nonzero_bytes_after_the_virtual_size() {
    let mut image = image_with_raw_padding(&[(0x100, 0xaa)]);
    assert_eq!(image.try_append_to_section(1, &[7; 8]).unwrap(), 0x2108);
    let rdata = &image.sections[1];
    assert_eq!(rdata.data[0x100], 0xaa);
    assert_eq!(&rdata.data[0x108..0x110], &[7; 8]);
    assert_eq!(rdata.header.virtual_size, 0x110);
}

/// The index of `.rdata` in [`image_with_full_headers`].
const FULL_RDATA: usize = 12;

/// Build a PE32+ image with `SectionAlignment` 0x200 and a full section table. `.rdata` holds
/// `rdata_used` bytes of its 0x200 bytes. `.reloc` after it is full, and the last section has
/// uninitialized data. The headers have no space for one more section.
fn image_with_full_headers(rdata_used: usize) -> PeImage {
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
    let rdata_size = u32::try_from(rdata_used).unwrap();
    let mut image = builder
        .add_section_with_virtual_size(".rdata", vec![1; rdata_used], rdata_size, READ_DATA)
        .add_section_with_virtual_size(".reloc", reloc, 0x200, READ_DATA)
        .add_section_with_virtual_size(
            ".bss",
            Vec::new(),
            0x200,
            characteristics::UNINITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    assert_eq!(image.sections[FULL_RDATA].name(), ".rdata");
    // One DIR64 relocation in `.text` (page 0) and one padding entry.
    let text = image.sections[0].header.virtual_address;
    let reloc_rva = image.sections[FULL_RDATA + 1].header.virtual_address;
    let entry = (10u16 << 12) | u16::try_from(text + 0x10).unwrap();
    image
        .write_at_rva(reloc_rva + 8, &entry.to_le_bytes())
        .unwrap();
    image.set_data_directory(DataDirectoryType::BaseReloc, reloc_rva, 12);
    assert_eq!(image.relocations().unwrap().blocks.len(), 1);
    image
}

/// Return a copy of `image` without its base relocation directory.
fn without_relocations(image: &PeImage) -> PeImage {
    let mut image = image.clone();
    image.clear_data_directory(DataDirectoryType::BaseReloc);
    image
}

#[test]
fn a_failed_relocation_update_leaves_the_tls_unchanged() {
    let base = image_with_full_headers(0x100).image_base();
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
    // Measure the TLS block. Then fill `.rdata` so that the block fits at its end.
    let mut probe = without_relocations(&image_with_full_headers(0x100));
    probe.update_tls(&tls, Some(FULL_RDATA)).unwrap();
    let block = probe.sections[FULL_RDATA].header.virtual_size as usize - 0x100;
    let mut image = image_with_full_headers((0x200 - block) & !7);
    without_relocations(&image)
        .update_tls(&tls, Some(FULL_RDATA))
        .unwrap();
    let before = image.clone();
    // The relocations do not fit in place, and they do not fit after the TLS block in
    // `.rdata`. The TLS directory must not point to a new block without relocations.
    assert!(image.update_tls(&tls, Some(FULL_RDATA)).is_err());
    assert_eq!(image, before);
}

#[test]
fn a_failed_relocation_update_leaves_the_load_config_unchanged() {
    let mut image = image_with_full_headers(0x168);
    let mut config = LoadConfigDirectory64::default();
    config.size = 0x94;
    config.security_cookie = image.image_base() + 0x1100;
    let config = LoadConfigDirectory::Config64(config);
    // The structure alone fits in `.rdata`.
    without_relocations(&image)
        .update_load_config(&config, Some(FULL_RDATA))
        .unwrap();
    let before = image.clone();
    assert!(image.update_load_config(&config, Some(FULL_RDATA)).is_err());
    assert_eq!(image, before);
}

#[test]
fn a_new_section_that_does_not_fit_in_the_headers_is_an_error() {
    let mut image = image_with_full_headers(0x100);
    let before = image.clone();
    assert!(image.update_exports(&large_exports(), None).is_err());
    assert_eq!(image, before);
}

#[test]
fn a_new_section_gets_the_data_at_its_start() {
    // The last section ends 0x4000 bytes before the end of the RVA range. The exports need
    // 0x2486 bytes, so they fit only at the start of the new section.
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

/// Build a PE32+ image with imports and exports in `.rdata`, relocations in `.reloc` and a
/// TLS directory.
fn image_with_tables() -> PeImage {
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
    image.update_imports(&imports, Some(1)).unwrap();
    let mut exports = ExportTable::default();
    exports.set_dll_name("rebuild.dll");
    exports.add_export(Some("Function"), 0x1000);
    image.update_exports(&exports, Some(1)).unwrap();
    let mut relocations = RelocationTable::default();
    relocations.add_dir64(0x1010);
    image.update_relocations(&relocations, Some(3)).unwrap();
    let base = image.image_base();
    let tls = TlsInfo {
        directory: Some(TlsDirectory::Tls64(TlsDirectory64 {
            address_of_index: base + 0x3000,
            ..TlsDirectory64::default()
        })),
        callback_rvas: vec![0x1000],
        image_base: base,
    };
    image.update_tls(&tls, Some(1)).unwrap();
    PeImage::parse(&image.try_build().unwrap()).unwrap()
}

#[test]
fn rebuild_without_a_section_puts_the_appended_tables_in_one_new_section() {
    let mut image = image_with_tables();
    image.rebuild_supported_directories(None).unwrap();
    let image = PeImage::parse(&image.try_build().unwrap()).unwrap();
    // The TLS directory has no in-place update, so it goes to a new section. Before the
    // change, the rebuild put it in the last section, `.reloc`.
    assert_eq!(image.sections.len(), 5);
    assert_eq!(image.sections[4].name(), ".portex");
    let tls = image.data_directory(DataDirectoryType::Tls).unwrap();
    assert_eq!(
        image.section_by_rva(tls.virtual_address).unwrap().name(),
        ".portex"
    );
    assert_eq!(image.exports().unwrap().exports.len(), 1);
    assert_eq!(image.tls().unwrap().unwrap().callback_rvas, [0x1000]);

    // A second rebuild adds one more section. It does not reuse the first `.portex`.
    let mut image = image;
    image.rebuild_supported_directories(None).unwrap();
    assert_eq!(image.sections.len(), 6);
    assert_eq!(image.sections[5].name(), ".portex");
}

#[test]
fn rebuild_with_a_section_index_uses_that_section() {
    let mut image = image_with_tables();
    image.rebuild_supported_directories(Some(2)).unwrap();
    let image = PeImage::parse(&image.try_build().unwrap()).unwrap();
    assert_eq!(image.sections.len(), 4);
    let tls = image.data_directory(DataDirectoryType::Tls).unwrap();
    assert_eq!(
        image.section_by_rva(tls.virtual_address).unwrap().name(),
        ".data"
    );
}

/// Build `.text` and a last `.data` section with 16 bytes of data and a 32 MiB `VirtualSize`.
fn image_with_large_bss() -> PeImage {
    PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(".text", vec![0xc3; 16], characteristics::CODE)
        .add_section_with_virtual_size(
            ".data",
            vec![2; 16],
            0x0200_0000,
            READ_DATA | characteristics::WRITE,
        )
        .try_build()
        .unwrap()
}

#[test]
fn an_append_does_not_write_a_large_zero_fill() {
    let mut image = image_with_large_bss();
    let before = image.clone();
    assert!(image.try_append_to_section(1, &[1; 16]).is_err());
    assert!(image.update_exports(&large_exports(), Some(1)).is_err());
    assert_eq!(image, before);
}
