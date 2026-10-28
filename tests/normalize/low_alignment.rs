//! Tests for files with a low alignment.

use super::{optional_offset, put32, section_header_offset};
use portex::headers::{DataDirectoryType, MachineType};
use portex::image::{NormalizeKept, PeBuilder, PeFile, PeImage};
use portex::section::characteristics;

/// The RVA and the file offset of the section.
const SECTION_START: u32 = 0x80;
/// The raw size and the virtual size of the section.
const SECTION_SIZE: u32 = 0x200;

/// Make a file with one section at 0x80. The raw section data covers the optional header and
/// the section table.
fn overlapping_file(section_alignment: u32, file_alignment: u32) -> Vec<u8> {
    let mut raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .file_alignment(0x40)
        .section_alignment(0x40)
        .entry_point(SECTION_START)
        .add_section(
            ".text",
            vec![0xcc; usize::try_from(SECTION_SIZE).unwrap()],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let start = usize::try_from(SECTION_START).unwrap();
    let end = start + usize::try_from(SECTION_SIZE).unwrap();
    raw.resize(end, 0xcc);

    let optional = optional_offset(&raw);
    put32(&mut raw, optional + 32, section_alignment);
    put32(&mut raw, optional + 36, file_alignment);
    put32(&mut raw, optional + 56, SECTION_START + SECTION_SIZE);
    let section = section_header_offset(&raw, 0);
    put32(&mut raw, section + 8, SECTION_SIZE);
    put32(&mut raw, section + 12, SECTION_START);
    put32(&mut raw, section + 16, SECTION_SIZE);
    put32(&mut raw, section + 20, SECTION_START);
    assert!(section + 40 < end);
    raw
}

/// Make a file with low alignments. The raw data of the `.text` section starts at 0x80, inside
/// the headers, but its RVA 0x200 is after the headers.
fn shifted_overlapping_file() -> Vec<u8> {
    let mut raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .file_alignment(0x40)
        .section_alignment(0x40)
        .entry_point(0x200)
        .add_section(
            ".text",
            vec![0xcc; usize::try_from(SECTION_SIZE).unwrap()],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let start = usize::try_from(SECTION_START).unwrap();
    let end = start + usize::try_from(SECTION_SIZE).unwrap();
    raw.resize(end, 0xcc);

    let optional = optional_offset(&raw);
    put32(&mut raw, optional + 56, 0x200 + SECTION_SIZE);
    let section = section_header_offset(&raw, 0);
    put32(&mut raw, section + 8, SECTION_SIZE);
    put32(&mut raw, section + 12, 0x200);
    put32(&mut raw, section + 16, SECTION_SIZE);
    put32(&mut raw, section + 20, SECTION_START);
    assert!(section + 40 < end);
    raw
}

/// A header fix inside the raw data of a section makes the build move the section. The
/// section then gets a new RVA (`SectionAddresses`), or the checksum fix is refused
/// (`Checksum`). The file does not change.
#[test]
fn a_header_fix_inside_a_section_keeps_the_file() {
    let base = overlapping_file(0x40, 0x40);
    assert_eq!(PeFile::parse(&base).unwrap().try_build().unwrap(), base);

    let optional = optional_offset(&base);
    let architecture = optional + 112 + DataDirectoryType::Architecture.as_index() * 8;
    let variants: [(&[(usize, u32)], NormalizeKept); 2] = [
        (&[(optional + 64, 1)], NormalizeKept::Checksum),
        (
            &[(architecture, 0x1234), (architecture + 4, 8)],
            NormalizeKept::SectionAddresses,
        ),
    ];
    for (fields, reason) in variants {
        let mut raw = base.clone();
        for &(offset, value) in fields {
            put32(&mut raw, offset, value);
        }
        assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

        let mut file = PeFile::parse(&raw).unwrap();
        let result = file.normalize().unwrap();
        assert_eq!(result.changes, []);
        assert_eq!(result.kept, [NormalizeKept::LowAlignment, reason]);
        assert_eq!(file.try_build().unwrap(), raw);
    }
}

/// A header fix that moves only the raw data of a low-alignment section changes the loader
/// view. The RVA, the size and the bytes of the section stay, but the loader maps the file as
/// it is.
#[test]
fn a_fix_that_moves_only_the_raw_data_keeps_the_file() {
    let mut raw = shifted_overlapping_file();
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let architecture = optional_offset(&raw) + 112 + DataDirectoryType::Architecture.as_index() * 8;
    put32(&mut raw, architecture, 0x1234);
    put32(&mut raw, architecture + 4, 8);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    // The build of the fix moves only the raw data. The RVA, the size and the bytes stay.
    let mut fixed = PeFile::parse(&raw).unwrap();
    fixed.clear_data_directory(DataDirectoryType::Architecture);
    let built = fixed.try_build().unwrap();
    let image = PeImage::parse(&built).unwrap();
    let header = &image.sections[0].header;
    assert_eq!(header.virtual_address, 0x200);
    assert_eq!(header.virtual_size, SECTION_SIZE);
    assert_eq!(header.size_of_raw_data, SECTION_SIZE);
    assert_ne!(header.pointer_to_raw_data, SECTION_START);
    let start = usize::try_from(header.pointer_to_raw_data).unwrap();
    let old = usize::try_from(SECTION_START).unwrap();
    let size = usize::try_from(SECTION_SIZE).unwrap();
    assert_eq!(built[start..start + size], raw[old..old + size]);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(
        result.kept,
        [NormalizeKept::LowAlignment, NormalizeKept::SectionData]
    );
    assert_eq!(file.try_build().unwrap(), raw);
}

#[test]
fn an_invalid_low_alignment_keeps_a_buildable_file() {
    let mut raw = overlapping_file(0x80, 0x40);
    let checksum = optional_offset(&raw) + 64;
    put32(&mut raw, checksum, 1);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(
        result.kept,
        [NormalizeKept::LowAlignment, NormalizeKept::Checksum]
    );
    assert_eq!(file.try_build().unwrap(), raw);
}

/// With a low alignment, the loader maps the whole file. The entry point can then refer to
/// header bytes after `SizeOfHeaders`. Here these bytes are the checksum, so the checksum
/// stays wrong.
#[test]
fn a_header_reference_after_size_of_headers_is_kept_with_a_low_alignment() {
    let mut raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .file_alignment(0x200)
        .section_alignment(0x200)
        .add_section(".text", vec![0xcc; 0x180], characteristics::READ)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let optional = optional_offset(&raw);
    let checksum = optional + 64;
    put32(&mut raw, optional + 60, 0x80);
    put32(&mut raw, optional + 16, u32::try_from(checksum).unwrap());
    put32(&mut raw, checksum, 1);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(
        result.kept,
        [NormalizeKept::LowAlignment, NormalizeKept::Checksum]
    );
    assert_eq!(file.try_build().unwrap(), raw);
}

/// A section without raw bytes does not end the header bytes. Here the only section has RVA 0
/// and `PointerToRawData` 0, so the loader maps the headers over the whole file. The entry point
/// is code in the Architecture entry.
#[test]
fn a_section_without_raw_bytes_does_not_end_the_headers() {
    let mut raw = PeBuilder::new()
        .machine(MachineType::Amd64)
        .file_alignment(0x200)
        .section_alignment(0x200)
        .add_section(".text", vec![0xcc; 0x180], characteristics::READ)
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();
    let size = u32::try_from(raw.len()).unwrap();
    let optional = optional_offset(&raw);
    let architecture = optional + 112 + DataDirectoryType::Architecture.as_index() * 8;
    raw[architecture..architecture + 4].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    put32(
        &mut raw,
        optional + 16,
        u32::try_from(architecture).unwrap(),
    );
    put32(&mut raw, optional + 56, size);
    put32(&mut raw, optional + 64, 0);
    let section = section_header_offset(&raw, 0);
    put32(&mut raw, section + 8, size);
    put32(&mut raw, section + 12, 0);
    put32(&mut raw, section + 16, size);
    put32(&mut raw, section + 20, 0);
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    // The fields-only candidate would make the entry bytes zero.
    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    assert_eq!(result.changes, []);
    assert_eq!(
        result.kept,
        [NormalizeKept::LowAlignment, NormalizeKept::HeaderBytesInUse]
    );
    let normalized = file.try_build().unwrap();
    assert_eq!(normalized, raw);
    assert_eq!(
        normalized[architecture..architecture + 4],
        [0x90, 0x90, 0x90, 0xc3]
    );
}
