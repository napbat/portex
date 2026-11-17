use super::*;
use crate::load_config::{LoadConfigDirectory, LoadConfigDirectory64};
use crate::section::characteristics;
use crate::{ErrorKind, MachineType, PeBuilder, PeImage};

/// The RVA of the test tables.
const RVA: u32 = 0x2000;

/// Append little-endian words.
fn words(bytes: &mut Vec<u8>, values: &[u32]) {
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

/// Return the length of `bytes` as a `u32`.
fn len(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).expect("a small structure")
}

/// Return little-endian 16-bit entries.
fn halves(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// Return one base relocation block of `page` with `entries`.
fn block(page: u32, entries: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    words(&mut bytes, &[page, 8 + len(entries)]);
    bytes.extend_from_slice(entries);
    bytes
}

/// Return one record with a 64-bit symbol.
fn record64(symbol: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = symbol.to_le_bytes().to_vec();
    words(&mut bytes, &[len(body)]);
    bytes.extend_from_slice(body);
    bytes
}

/// Return a table of `version` with `records`.
fn table(version: u32, records: &[Vec<u8>]) -> Vec<u8> {
    let body = records.concat();
    let mut bytes = Vec::new();
    words(&mut bytes, &[version, len(&body)]);
    bytes.extend_from_slice(&body);
    bytes
}

/// Return a function override body: one override of `0x1010` with two RVAs and one block of
/// `entries`, then the BDD bytes `[1, 0, 0, 0, 0, 0, 0, 0]`.
fn function_override(entries: &[u16]) -> Vec<u8> {
    let relocations = block(0x1000, &halves(entries));
    let mut overrides = Vec::new();
    words(
        &mut overrides,
        &[0x1010, 0x20, 8, len(&relocations), 0x1100, 0x1200],
    );
    overrides.extend_from_slice(&relocations);
    let mut body = Vec::new();
    words(&mut body, &[len(&overrides)]);
    body.extend_from_slice(&overrides);
    words(&mut body, &[1, 0]);
    body
}

/// Return the RVA of an `InvalidRva` error.
fn invalid_rva(error: &Error) -> u32 {
    match error.kind() {
        ErrorKind::InvalidRva(rva) => *rva,
        kind => panic!("not an InvalidRva error: {kind:?}"),
    }
}

/// Return the page RVA and the entries of each block.
fn read_blocks(blocks: DynamicRelocationBlocks<'_>) -> Vec<(u32, Vec<u32>)> {
    blocks
        .map(|block| {
            let block = block.expect("the block reads");
            (block.page_rva(), block.entries().collect())
        })
        .collect()
}

#[test]
fn records_decode_by_symbol() {
    let import: u32 = 0x20 | 0x1000 | (5 << 13);
    let mut import_entries = import.to_le_bytes().to_vec();
    import_entries.extend_from_slice(&[0; 4]);
    let bytes = table(
        1,
        &[
            record64(symbols::FUNCTION_OVERRIDE, &function_override(&[0x1011, 0])),
            record64(
                symbols::IMPORT_CONTROL_TRANSFER,
                &block(0x1000, &import_entries),
            ),
            record64(
                symbols::INDIR_CONTROL_TRANSFER,
                &block(0x3000, &halves(&[0x5040, 0])),
            ),
            record64(symbols::ARM64X, &[1, 2, 3]),
            record64(0x1_4000_0000, &block(0x4000, &halves(&[0x0080, 0x0090]))),
            record64(0xffff_f680_0000_0000, &block(0x5000, &halves(&[0x00a0, 0]))),
        ],
    );
    let table = DynamicRelocationTable::parse(&bytes, RVA, true).expect("a version-1 table");
    assert_eq!(table.version(), 1);
    let records: Vec<_> = table
        .records()
        .expect("version 1")
        .collect::<Result<_>>()
        .expect("each record reads");
    assert_eq!(records.len(), 6);
    assert_eq!(records[0].rva(), RVA + 8);
    assert_eq!(records[0].body_rva(), RVA + 20);

    let DynamicRelocationBody::FunctionOverride(header) = records[0].body().unwrap() else {
        panic!("a function override");
    };
    let overrides: Vec<_> = header
        .overrides()
        .collect::<Result<_>>()
        .expect("each override reads");
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].rva(), RVA + 24);
    assert_eq!(overrides[0].original_rva(), 0x1010);
    assert_eq!(overrides[0].bdd_offset(), 0x20);
    assert_eq!(overrides[0].rvas().collect::<Vec<_>>(), [0x1100, 0x1200]);
    assert_eq!(read_blocks(overrides[0].blocks()), [(0x1000, vec![0x1011])]);
    assert_eq!(header.bdd(), [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(header.bdd_rva(), RVA + 24 + 16 + 8 + 12);

    // A zero 32-bit entry is not padding.
    let DynamicRelocationBody::Blocks(blocks) = records[1].body().unwrap() else {
        panic!("blocks");
    };
    assert_eq!(blocks.entry_size(), 4);
    assert_eq!(read_blocks(blocks), [(0x1000, vec![import, 0])]);

    let DynamicRelocationBody::Blocks(blocks) = records[2].body().unwrap() else {
        panic!("blocks");
    };
    assert_eq!(blocks.entry_size(), 2);
    assert_eq!(read_blocks(blocks), [(0x3000, vec![0x5040])]);

    assert!(matches!(
        records[3].body().unwrap(),
        DynamicRelocationBody::Raw([1, 2, 3])
    ));

    for (record, expected) in [
        (&records[4], (0x4000, vec![0x0080, 0x0090])),
        (&records[5], (0x5000, vec![0x00a0])),
    ] {
        let DynamicRelocationBody::Blocks(blocks) = record.body().unwrap() else {
            panic!("blocks");
        };
        assert_eq!(blocks.entry_size(), 2);
        assert_eq!(read_blocks(blocks), [expected]);
    }
}

#[test]
fn records_of_a_pe32_table_have_32_bit_symbols() {
    let mut record = Vec::new();
    let body = block(0x1000, &halves(&[0x3010, 0]));
    words(
        &mut record,
        &[symbols::SWITCHTABLE_BRANCH.try_into().unwrap(), len(&body)],
    );
    record.extend_from_slice(&body);
    let bytes = table(1, &[record]);
    let table = DynamicRelocationTable::parse(&bytes, RVA, false).expect("a version-1 table");
    let records: Vec<_> = table.records().unwrap().collect::<Result<_>>().unwrap();
    assert_eq!(records[0].symbol(), symbols::SWITCHTABLE_BRANCH);
    assert_eq!(records[0].body_rva(), RVA + 16);
    let DynamicRelocationBody::Blocks(blocks) = records[0].body().unwrap() else {
        panic!("blocks");
    };
    assert_eq!(read_blocks(blocks), [(0x1000, vec![0x3010])]);
}

/// Only a version-1 table has known records, so the reader does not read the records of
/// another version.
#[test]
fn other_versions_have_no_records() {
    let mut bytes = Vec::new();
    words(&mut bytes, &[2, 0x1000]);
    let table = DynamicRelocationTable::parse(&bytes, RVA, true).expect("the header reads");
    assert_eq!(table.version(), 2);
    assert!(matches!(
        table.records().map(|_| ()).unwrap_err().kind(),
        ErrorKind::InvalidDataDirectory(_)
    ));
}

#[test]
fn truncated_structures_state_their_rva() {
    let header =
        |bytes: &[u8]| invalid_rva(&DynamicRelocationTable::parse(bytes, RVA, true).unwrap_err());
    assert_eq!(header(&[1, 0, 0, 0]), RVA);
    let mut records_cut = table(1, &[record64(5, &block(0x1000, &halves(&[0x10, 0])))]);
    records_cut.pop();
    assert_eq!(header(&records_cut), RVA + 8);

    // Return the first error of the records, blocks and override records of `records`.
    let first_error = |records: &[Vec<u8>]| -> u32 {
        let bytes = table(1, records);
        let table = DynamicRelocationTable::parse(&bytes, RVA, true).unwrap();
        for record in table.records().unwrap() {
            let record = match record {
                Ok(record) => record,
                Err(error) => return invalid_rva(&error),
            };
            let body = match record.body() {
                Ok(body) => body,
                Err(error) => return invalid_rva(&error),
            };
            let blocks = match body {
                DynamicRelocationBody::Blocks(blocks) => blocks,
                DynamicRelocationBody::FunctionOverride(header) => {
                    let mut overrides = header.overrides();
                    match overrides.next().expect("one override") {
                        Ok(record) => record.blocks(),
                        Err(error) => return invalid_rva(&error),
                    }
                }
                DynamicRelocationBody::Raw(_) => continue,
            };
            for block in blocks {
                if let Err(error) = block {
                    return invalid_rva(&error);
                }
            }
        }
        panic!("no error");
    };

    // A record header that the table cuts.
    let mut cut = record64(5, &[]);
    cut.truncate(10);
    assert_eq!(first_error(&[cut]), RVA + 8);
    // A record body that the table cuts.
    let mut cut = record64(5, &block(0x1000, &halves(&[0x10, 0])));
    cut[8] = 0x40;
    assert_eq!(first_error(&[cut]), RVA + 8);
    // A block shorter than its header, after one whole block.
    let mut body = block(0x1000, &halves(&[0x10, 0]));
    words(&mut body, &[0x2000, 4]);
    assert_eq!(first_error(&[record64(5, &body)]), RVA + 20 + 12);
    // A block of 32-bit entries with a partial entry.
    let body = block(0x1000, &[1, 0, 0, 0, 0, 0]);
    assert_eq!(first_error(&[record64(3, &body)]), RVA + 20);
    // A `FuncOverrideSize` larger than the body.
    let mut body = function_override(&[0x1011, 0]);
    body[0] += 9;
    assert_eq!(first_error(&[record64(7, &body)]), RVA + 20);
    // An `RvaSize` that is not a multiple of 4.
    let mut body = function_override(&[0x1011, 0]);
    body[12] = 6;
    assert_eq!(first_error(&[record64(7, &body)]), RVA + 24);
    // A `BaseRelocSize` larger than the override records.
    let mut body = function_override(&[0x1011, 0]);
    body[16] += 4;
    assert_eq!(first_error(&[record64(7, &body)]), RVA + 24);
}

/// Build a PE32+ image whose second section holds `table` at offset 0, and whose load
/// configuration has `set` applied.
fn image(table: Vec<u8>, set: impl FnOnce(&mut LoadConfigDirectory64)) -> PeImage {
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .entry_point(0x1000)
        .add_section(
            ".text",
            vec![0xcc; 0x100],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".reloc",
            table,
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .expect("the test layout is valid");
    let mut config = LoadConfigDirectory64::default();
    set(&mut config);
    image
        .update_load_config(&LoadConfigDirectory::Config64(config), None)
        .expect("the configuration fits");
    PeImage::parse(&image.try_build().expect("the image serializes")).expect("the image parses")
}

#[test]
fn the_load_configuration_locates_the_table() {
    let bytes = table(1, &[record64(5, &block(0x1000, &halves(&[0x10, 0])))]);
    let located = image(bytes.clone(), |config| {
        config.dynamic_value_reloc_table_section = 2;
    });
    let config = located.load_config().unwrap().unwrap();
    let table = located
        .dynamic_relocation_table(&config)
        .expect("the table reads")
        .expect("the configuration locates a table");
    let section_rva = located.sections[1].header.virtual_address;
    assert_eq!(table.rva(), section_rva);
    assert_eq!(
        table,
        DynamicRelocationTable::parse(&bytes, section_rva, true).unwrap()
    );

    let none = image(bytes.clone(), |_| {});
    let config = none.load_config().unwrap().unwrap();
    assert_eq!(none.dynamic_relocation_table(&config).unwrap(), None);

    let error = |set: fn(&mut LoadConfigDirectory64)| {
        let image = image(bytes.clone(), set);
        let config = image.load_config().unwrap().unwrap();
        image.dynamic_relocation_table(&config).unwrap_err()
    };
    assert!(matches!(
        error(|config| config.dynamic_value_reloc_table = 0x1_4000_2000).kind(),
        ErrorKind::InvalidDataDirectory(_)
    ));
    assert!(matches!(
        error(|config| config.dynamic_value_reloc_table_offset = 4).kind(),
        ErrorKind::InvalidSection(_)
    ));
    assert!(matches!(
        error(|config| config.dynamic_value_reloc_table_section = 9).kind(),
        ErrorKind::InvalidSection(_)
    ));
    let unmapped = error(|config| {
        config.dynamic_value_reloc_table_section = 2;
        config.dynamic_value_reloc_table_offset = 0x10_0000;
    });
    assert!(matches!(unmapped.kind(), ErrorKind::InvalidRva(_)));
}
