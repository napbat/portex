//! Tests for a bound import table that a new section table covers.

use super::{
    DataDirectoryType, NormalizeChange, PeFile, PeHeaders, PeImage,
    move_nt_headers_into_the_dos_header, optional_offset, put32, section_header_offset,
    section_rvas, test_image,
};

#[test]
fn a_bound_import_table_under_the_new_section_table_is_cleared() {
    let mut raw = test_image().try_build().unwrap();
    move_nt_headers_into_the_dos_header(&mut raw);
    let count = PeHeaders::from_slice(&raw).unwrap().section_headers.len();
    // The bound import table starts at the end of the section table. The NT headers move from
    // 0x10 to 0x40, so the new section table covers this table.
    let table = section_header_offset(&raw, count);
    let mut bound_imports = Vec::new();
    bound_imports.extend_from_slice(&1_u32.to_le_bytes());
    bound_imports.extend_from_slice(&16_u16.to_le_bytes());
    bound_imports.extend_from_slice(&0_u16.to_le_bytes());
    bound_imports.extend_from_slice(&[0; 8]);
    bound_imports.extend_from_slice(b"a.dll\0");
    raw[table..table + bound_imports.len()].copy_from_slice(&bound_imports);
    let size_of_headers = PeHeaders::from_slice(&raw)
        .unwrap()
        .optional_header
        .size_of_headers();
    assert!(table + bound_imports.len() <= usize::try_from(size_of_headers).unwrap());
    // The header bytes are mapped 1:1, so the RVA is the file offset.
    let directory = optional_offset(&raw) + 112 + 11 * 8;
    put32(&mut raw, directory, u32::try_from(table).unwrap());
    put32(
        &mut raw,
        directory + 4,
        u32::try_from(bound_imports.len()).unwrap(),
    );
    let original = PeImage::parse(&raw).unwrap();
    assert_eq!(PeFile::parse(&raw).unwrap().try_build().unwrap(), raw);

    let mut file = PeFile::parse(&raw).unwrap();
    let result = file.normalize().unwrap();
    // The helper puts 0x10 in `BaseOfCode`, so the code and data fields change too.
    assert_eq!(
        result.changes,
        [
            NormalizeChange::NtHeadersOffset {
                old: 0x10,
                new: 0x40
            },
            NormalizeChange::CodeAndDataFields,
            NormalizeChange::DataDirectory(DataDirectoryType::BoundImport),
            NormalizeChange::HeaderTail,
        ]
    );
    assert_eq!(result.kept, []);
    let normalized = PeImage::parse(&file.try_build().unwrap()).unwrap();
    assert!(
        normalized
            .data_directory(DataDirectoryType::BoundImport)
            .is_none_or(|entry| entry.virtual_address == 0 && entry.size == 0)
    );
    assert_eq!(normalized.entry_point(), original.entry_point());
    assert_eq!(section_rvas(&normalized), section_rvas(&original));
}
