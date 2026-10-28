//! Tests for files with a low alignment.

use super::{optional_offset, put32, section_header_offset};
use portex::headers::{DataDirectoryType, MachineType};
use portex::image::{NormalizeKept, PeBuilder, PeFile};
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

/// Return true if the reason tells that a header fix would change the section data.
fn is_rejection(kept: &NormalizeKept) -> bool {
    matches!(
        kept,
        NormalizeKept::SectionAddresses | NormalizeKept::SectionData | NormalizeKept::Build(_)
    )
}

#[test]
fn a_header_fix_inside_a_section_keeps_the_file() {
    let base = overlapping_file(0x40, 0x40);
    assert_eq!(PeFile::parse(&base).unwrap().try_build().unwrap(), base);

    let optional = optional_offset(&base);
    let architecture = optional + 112 + DataDirectoryType::Architecture.as_index() * 8;
    let variants: [&[(usize, u32)]; 2] = [
        &[(optional + 64, 1)],
        &[(architecture, 0x1234), (architecture + 4, 8)],
    ];
    for fields in variants {
        let mut raw = base.clone();
        for &(offset, value) in fields {
            put32(&mut raw, offset, value);
        }
        assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

        let mut file = PeFile::parse(&raw).unwrap();
        let result = file.normalize().unwrap();
        assert_eq!(result.changes, []);
        assert_eq!(result.kept.len(), 2, "{:?}", result.kept);
        assert_eq!(result.kept[0], NormalizeKept::LowAlignment);
        assert!(is_rejection(&result.kept[1]), "{:?}", result.kept);
        assert_eq!(file.try_build().unwrap(), raw);
    }
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
    assert!(result.kept.contains(&NormalizeKept::LowAlignment));
    assert_eq!(
        result.kept.iter().filter(|kept| is_rejection(kept)).count(),
        1,
        "{:?}",
        result.kept
    );
    assert_eq!(file.try_build().unwrap(), raw);
}
