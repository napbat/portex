//! Fuzz target that parses arbitrary bytes as PE files, and then runs the directory accessors,
//! the validation, the build paths, the mapping, the rebase and the normalization on the result.
//!
//! The target panics in these conditions:
//!
//! - `PeFile::preserves_source_gaps` returns `true`, but `PeFile::try_build` does not return
//!   the input byte for byte.
//! - `PeImage::rebuild_supported_directories` returns `Ok`, but the result does not build or
//!   does not parse.
//! - `normalize` returns `Ok`, but the normalized file does not build or does not parse.
//! - `normalize` changes the section RVAs or the loader virtual sizes of the built original.

#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::{PeFile, PeImage};

/// The largest mapped image that the target makes, in bytes.
///
/// A mapped image needs `SizeOfImage` bytes, and libFuzzer stops at 2 GiB of memory.
const MAX_MAPPED_IMAGE_SIZE: u32 = 64 << 20;

/// The value that the target XORs with the image base to get a new base for the rebase path.
///
/// The value keeps the 64 KiB alignment of the base.
const REBASE_DELTA: u64 = 0x1_0000;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = PeImage::parse(data) {
        exercise(&image);
        if mapped_image_size(&image) <= MAX_MAPPED_IMAGE_SIZE {
            map(&image);
        }
        if let Ok(rebuilt) = image.try_build() {
            let _ = PeImage::parse(&rebuilt);
        }
        rebuild_directories(&image);
    }
    if let Ok(file) = PeFile::parse(data) {
        check_file(data, file);
    }
});

/// Map `image` at its base and at a new base, and parse each mapped image.
fn map(image: &PeImage) {
    if let Ok(mapped) = image.to_mapped_image()
        && let Ok(mapped_image) = PeImage::parse_mapped(&mapped)
    {
        exercise(&mapped_image);
    }
    let rebased_base = image.runtime_image_base() ^ REBASE_DELTA;
    if let Ok(mapped) = image.to_mapped_image_at(rebased_base) {
        let _ = PeImage::parse_mapped(&mapped);
    }
}

/// Rebuild the supported directories of a copy of `image`.
///
/// If the rebuild succeeds, make sure that the result builds and parses.
fn rebuild_directories(image: &PeImage) {
    let mut rebuilt = image.clone();
    if rebuilt.rebuild_supported_directories(None).is_ok() {
        let bytes = rebuilt
            .try_build()
            .expect("rebuild_supported_directories returned Ok, but the image does not build");
        PeImage::parse(&bytes)
            .expect("rebuild_supported_directories returned Ok, but the image does not parse");
    }
}

/// Run the raw-file accessors, the round trip, the build and the normalization on `file`.
///
/// `data` is the input that `file` comes from.
fn check_file(data: &[u8], mut file: PeFile) {
    let _ = file.security();
    let _ = file.debug_info();
    if file.preserves_source_gaps() {
        let rebuilt = file
            .try_build()
            .expect("the file keeps its source gaps, but it does not build");
        assert!(
            rebuilt == data,
            "the file keeps its source gaps, but the unedited round trip changes the bytes"
        );
    }
    if let Ok(rebuilt) = file.try_build() {
        let _ = PeFile::parse(&rebuilt);
    }
    let original_layout = file
        .try_build()
        .ok()
        .and_then(|built| PeImage::parse(&built).ok())
        .map(|image| section_layout(&image));
    if file.normalize().is_ok() {
        let original_layout =
            original_layout.expect("normalize returned Ok, but the original did not build");
        let normalized = file
            .try_build()
            .expect("normalize returned Ok, but the normalized file does not build");
        let image = PeImage::parse(&normalized)
            .expect("normalize returned Ok, but the normalized file does not parse");
        assert_eq!(
            section_layout(&image),
            original_layout,
            "normalize changed the section RVAs or loader virtual sizes"
        );
    }
}

/// Return the `(VirtualAddress, loader virtual size)` pair of each section of `image`.
///
/// The loader virtual size is `VirtualSize`, or `SizeOfRawData` if `VirtualSize` is 0.
fn section_layout(image: &PeImage) -> Vec<(u32, u32)> {
    image
        .sections
        .iter()
        .map(|section| {
            let header = &section.header;
            let size = if header.virtual_size == 0 {
                header.size_of_raw_data
            } else {
                header.virtual_size
            };
            (header.virtual_address, size)
        })
        .collect()
}

/// Return the `SizeOfImage` that `to_mapped_image` uses for `image`.
///
/// The method makes a new layout, and that layout can have a larger `SizeOfImage` than the
/// parsed value. If no new layout is possible, it uses the parsed value.
fn mapped_image_size(image: &PeImage) -> u32 {
    let mut updated = image.clone();
    let parsed = image.optional_header.size_of_image();
    if updated.try_update_layout().is_ok() {
        parsed.max(updated.optional_header.size_of_image())
    } else {
        parsed
    }
}

/// Run the directory accessors and the validation on `image`.
fn exercise(image: &PeImage) {
    let _ = image.imports();
    let _ = image.exports();
    let _ = image.relocations();
    let _ = image.resources_with_data();
    let _ = image.tls();
    let _ = image.debug_info();
    let _ = image.bound_imports();
    let _ = image.delay_imports();
    let _ = image.exception_table();
    let _ = image.load_config();
    let _ = image.clr_metadata();
    let _ = image.rich_header();
    let _ = image.validate();
}
