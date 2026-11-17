use super::*;
use crate::PeBuilder;
use crate::coff::MachineType;
use crate::section::characteristics::{INITIALIZED_DATA, READ};

/// The offset of the DLL name in the import section.
const NAME: u32 = 0;
/// The offset of the thunk array in the import section.
const THUNKS: u32 = 0x10;
/// The offset of the import descriptor array in the import section.
const DESCRIPTORS: u32 = 0x2300;
/// The RVA of the import section.
const SECTION_RVA: u32 = 0x1000;

/// Return a PE32+ image with an import table of `count` descriptors. Each descriptor has
/// the DLL name at `NAME` and the name table and the address table at the offset that
/// `table` returns for it. The thunk array at `THUNKS` has `thunks` imports by ordinal.
fn import_image(count: u32, thunks: u64, table: impl Fn(u32) -> u32) -> PeImage {
    let mut data = vec![0u8; DESCRIPTORS as usize];
    data[..6].copy_from_slice(b"a.dll\0");
    for ordinal in 1..=thunks {
        let offset = (THUNKS as usize) + usize::try_from(ordinal - 1).unwrap() * 8;
        data[offset..offset + 8].copy_from_slice(&(ordinal | 1 << 63).to_le_bytes());
    }
    for index in 0..count {
        let thunk_rva = SECTION_RVA + table(index);
        for field in [thunk_rva, 0, 0, SECTION_RVA + NAME, thunk_rva] {
            data.extend_from_slice(&field.to_le_bytes());
        }
    }
    data.extend_from_slice(&[0; ImportDescriptor::SIZE]);
    let mut image = PeBuilder::new()
        .machine(MachineType::Amd64)
        .add_section(".idata", data, INITIALIZED_DATA | READ)
        .try_build()
        .unwrap();
    assert_eq!(image.sections[0].header.virtual_address, SECTION_RVA);
    image.set_data_directory(
        DataDirectoryType::Import,
        SECTION_RVA + DESCRIPTORS,
        u32::try_from(ImportDescriptor::SIZE).unwrap(),
    );
    image
}

#[test]
fn a_shared_thunk_array_counts_once() {
    let thunks = 1000;
    let count = u32::try_from(MAX_FOLLOWED_THUNKS / 1000 + 1).unwrap();
    let image = import_image(count, thunks, |_| THUNKS);

    let rva = |offset: u32| (SECTION_RVA + offset) as usize;
    let descriptors = rva(DESCRIPTORS);
    let array_end = rva(THUNKS) + usize::try_from(thunks + 1).unwrap() * 8;
    assert_eq!(
        followed_ranges(&image),
        [
            rva(NAME)..rva(NAME) + 6,
            rva(THUNKS)..array_end,
            descriptors..descriptors + (count as usize + 1) * ImportDescriptor::SIZE,
        ]
    );
}

#[test]
fn too_many_thunks_protect_the_rest_of_the_address_space() {
    // Each descriptor uses a different tail of one array, so no name table is shared.
    let count = 300;
    let image = import_image(count, 1100, |index| THUNKS + index * 8);

    let descriptors = (SECTION_RVA + DESCRIPTORS) as usize;
    let ranges = followed_ranges(&image);
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0], descriptors..usize::MAX);
}
