//! Fuzz target that parses arbitrary bytes as PE files, and then runs the directory accessors,
//! the validation, the build paths and the normalization on the result.
//!
//! The target panics if `normalize` returns `Ok`, but the normalized file does not build or does
//! not parse. It also panics if the section RVAs and virtual sizes are different from those of
//! the built original.

#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::{PeFile, PeImage};

/// The largest mapped image that the target makes, in bytes.
///
/// A mapped image needs `SizeOfImage` bytes, and libFuzzer stops at 2 GiB of memory.
const MAX_MAPPED_IMAGE_SIZE: u32 = 64 << 20;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = PeImage::parse(data) {
        exercise(&image);
        if mapped_image_size(&image) <= MAX_MAPPED_IMAGE_SIZE
            && let Ok(mapped) = image.to_mapped_image()
            && let Ok(mapped_image) = PeImage::parse_mapped(&mapped)
        {
            exercise(&mapped_image);
        }
        if let Ok(rebuilt) = image.try_build() {
            let _ = PeImage::parse(&rebuilt);
        }
    }
    if let Ok(mut file) = PeFile::parse(data) {
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
});

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
