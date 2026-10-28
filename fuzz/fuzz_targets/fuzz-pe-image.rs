//! Fuzz target that parses arbitrary bytes as PE files, and then runs the directory accessors,
//! the validation and the build paths on the result.

#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::{PeFile, PeImage};

/// The largest `SizeOfImage` for which the target makes a mapped image.
///
/// A mapped image needs `SizeOfImage` bytes, and libFuzzer stops at 2 GiB of memory.
const MAX_MAPPED_IMAGE_SIZE: u32 = 64 << 20;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = PeImage::parse(data) {
        exercise(&image);
        if image.optional_header.size_of_image() <= MAX_MAPPED_IMAGE_SIZE
            && let Ok(mapped) = image.to_mapped_image()
            && let Ok(mapped_image) = PeImage::parse_mapped(&mapped)
        {
            exercise(&mapped_image);
        }
        if let Ok(rebuilt) = image.try_build() {
            let _ = PeImage::parse(&rebuilt);
        }
    }
    if let Ok(file) = PeFile::parse(data)
        && let Ok(rebuilt) = file.try_build()
    {
        let _ = PeFile::parse(&rebuilt);
    }
});

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
