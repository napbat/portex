use super::*;
use crate::prelude::*;

#[test]
fn the_default_end_rule_is_the_loader_rule() {
    // The second descriptor has a `Name` and no `FirstThunk`. The loader ends the table
    // there. Before the fix, the docs said that the null-descriptor rule is the loader rule.
    let words = [
        0x2000u32, 0, 0, 0x3000, 0x4000, 0x2100, 0, 0, 0x3100, 0, 0, 0, 0, 0, 0,
    ];
    let data: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let count = |end| {
        let mut cursor = RawImportDescriptors::new(0, data.len(), end);
        let mut count = 0;
        while cursor.read_next(&data).unwrap().is_some() {
            count += 1;
        }
        count
    };
    assert_eq!(count(ImportTableEnd::default()), 1);
    assert_eq!(count(ImportTableEnd::ZeroNameOrFirstThunk), 1);
    assert_eq!(count(ImportTableEnd::NullDescriptor), 2);
}
