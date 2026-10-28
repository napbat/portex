# Portex

Portex is a parser, editor and builder for PE executable images. It works with `no_std`.
Portex keeps raw files and loader-mapped images apart, because each layout translates an RVA to
a different source offset.

[![CI](https://github.com/napbat/portex/actions/workflows/ci.yml/badge.svg)](https://github.com/napbat/portex/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## What it supports

- Raw PE files, loader-mapped images, and mapped images that are relocated to a runtime base.
- PE32 and PE32+ headers, checked RVA/VA conversion, and section layout.
- Zero-filled virtual tails of sections, overlays, Authenticode certificate tables, and
  checksums.
- Imports, delay imports, bound imports, and exports (also sparse and aliased exports).
- Resources, base relocations, TLS, debug records, and the load configuration.
- Exception tables for x64, ARM and ARM64.
- A load configuration that is limited by its declared size, also with legacy prefixes. A
  partial field is an error. A field that is fully absent stays zero.
- Serialization of x64 unwind data with borrowed handler data for a different language, through
  `UnwindInfo::try_to_bytes_with_handler_data`.
- Rich headers, the CLR/CLI header of the PE image, and the raw metadata blob.
- Lossless round trips of raw files through `PeFile`. When the layout does not change, `PeFile`
  keeps noncanonical gaps, certificate bytes and overlays.
- Parsing of malformed input for PE tooling: headers that end early, overlapping header
  structures and garbage fields still parse, and `validate()` reports the problems. Fallible
  builders, with no panics on file data.
- Sequential I/O and positional I/O.
- `no_std + alloc` support. Sequential I/O uses
  [`nostdio`](https://github.com/coconutbird/nostdio). Positional `ReadAt` access is also
  available for mapped images and remote images.

Portex targets PE executable images, for example executables, DLLs, drivers and UEFI-style
images. Portex does not support standalone COFF object files or COFF symbol tables.

Portex does not parse CLR metadata streams or tables. To parse them, give
`PeImage::clr_metadata()` to a metadata crate, for example `clrmeta`.

## Installation

```toml
[dependencies]
portex = "0.5"
```

For `no_std + alloc`:

```toml
[dependencies]
portex = { version = "0.5", default-features = false }
```

Portex 0.5 requires Rust 1.88 or newer.

The default `std` feature adds filesystem helpers and `FileReader`. It also enables the `std`
feature of `nostdio`. Then the `nostdio` traits and `nostdio::IoError` are the `std::io` items,
so `std` files and streams work with the stream APIs directly.

Without `std`, parsing, building, mapped images, validation, in-memory readers and stream APIs
are still available. `nostdio` then supplies its own traits and error type. An I/O error is an
`ErrorKind::Io` in both builds.

## Core types

| Type | Use it for |
| --- | --- |
| `PeFile` | A full raw file. It keeps the certificates, gaps and overlay |
| `PeImage` | A normalized executable image, parsed from raw bytes or loader-mapped bytes |
| `PeHeaders` | The headers only. It does not load section data |
| `PeBuilder` | Building a new executable image |

## Quick start

```rust,no_run
use portex::PeFile;

let mut file = PeFile::from_file("example.exe")?;
let image = file.image();

println!("64-bit: {}", image.is_64bit());
println!("entry point RVA: {:#x}", image.entry_point());

for dll in &image.imports()?.dlls {
    println!("imports from {}", dll.name);
}

// Edits go through the normalized image while PeFile retains raw-only state.
let imports = file.image().imports()?;
file.image_mut().update_imports(&imports, None)?;
file.write_to_file("modified.exe")?;
# Ok::<(), portex::Error>(())
```

Use `PeImage::parse(raw_bytes)` if the rebuilt file does not need the overlays and
certificates. Use `PeFile::parse(raw_bytes)` if it needs them.

## Raw files versus mapped images

```rust,no_run
use portex::{ParseOptions, PeImage, SourceLayout};

# let raw_file_bytes: &[u8] = &[];
# let mapped_image: &[u8] = &[];
// Raw file: section payloads are addressed by PointerToRawData.
let raw = PeImage::parse(raw_file_bytes)?;

// Loader-mapped image: section payloads are addressed by RVA.
let mapped = PeImage::parse_mapped(mapped_image)?;

// Preserve the actual load base for VA-bearing directories such as TLS.
let relocated = PeImage::parse_mapped_at(mapped_image, 0x0000_7ff6_0000_0000)?;

// Explicit options also support missing/discarded mapped section pages.
let partial = PeImage::parse_with_options(
    mapped_image,
    ParseOptions::mapped().allow_missing_section_data(),
)?;

assert_eq!(raw.source_layout(), SourceLayout::File);
assert_eq!(mapped.source_layout(), SourceLayout::Mapped);
assert_eq!(relocated.runtime_image_base(), 0x0000_7ff6_0000_0000);
# Ok::<(), portex::Error>(())
```

`PeImage::to_mapped_image()` makes loader-style bytes at the preferred image base.
`to_mapped_image_at(base)` makes them at a different runtime base. It also applies the
supported base relocations.

For a remote process or a different random-access source, implement `ReadAt`. Then use one of
these functions:

```text
PeImage::read_from(&reader, source_offset, SourceLayout::Mapped)
PeImage::read_mapped_from(&reader, source_offset, runtime_image_base)
```

`PeHeaders::rva_to_source_offset` does the same layout-aware translation. It does not read all
sections.

## Sequential and positional I/O

`nostdio` supplies the `Read`, `Write` and `Seek` traits and the `Cursor` type. `portex::io`
re-exports them:

```rust,no_run
use portex::PeFile;
use portex::io::Cursor;

# let raw_file_bytes: &[u8] = &[];
let mut input = Cursor::new(raw_file_bytes);
let file = PeFile::from_stream(&mut input)?;

let mut output = Cursor::new(Vec::new());
file.write_to(&mut output)?;
# Ok::<(), portex::Error>(())
```

Portex also has the positional `ReadAt` abstraction. `ReadAt` is better for these sources:

- process memory
- sparse address spaces
- sources with concurrent callers
- sources that must not share cursor state

`SeekReader` adapts a `nostdio::Read + Seek` source to `ReadAt`.

## Building an image

```rust,no_run
use portex::section::characteristics;
use portex::{MachineType, PeBuilder, Subsystem};

let image = PeBuilder::new()
    .machine(MachineType::Amd64)
    .subsystem(Subsystem::WindowsCui)
    .entry_point(0x1000)
    .add_section(
        ".text",
        vec![0xcc; 256],
        characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
    )
    .try_build()?;

let raw_file = image.try_build()?;
assert!(!raw_file.is_empty());
# Ok::<(), portex::Error>(())
```

Directory builders and image update methods are fallible. If the input or the edits are not
fully trusted, use the `try_*` variants.

## Module layout

The facade modules contain the usual entry points:

| Module | Contents |
| --- | --- |
| `image` | `PeImage`, `PeFile`, `PeHeaders`, parsing options, and `PeBuilder` |
| `headers` | DOS, COFF image, optional, section, and data-directory header types |
| `directories` | Imports, exports, resources, relocations, TLS, exceptions, debug, security, CLR hand-off, and related builders |
| `io` | `nostdio` traits/types plus positional `ReadAt` readers |

Specialized modules, for example `import`, `resource`, `reloc`, `security` and `validation`,
are also public. Use them to import a specific area.

Nested modules use the `module.rs` and `module/child.rs` layout. Portex does not use the older
`module/mod.rs` form.

## Development

[`mise`](https://mise.jdx.dev/) manages the toolchain and the pre-commit hooks:

```bash
mise install
mise run precommit-install
mise run precommit
```

The hooks run rustfmt and Clippy on all targets of the crate. They do this with all features
and with `no_std + alloc`. They also lint the separate fuzz package.

CI runs the same checks. CI also runs the tests and rustdoc with both feature sets.

Each package manifest denies warnings, the Clippy pedantic group, missing docs and unsafe code.
The only unsafe code is `BaseAddressReader`. Direct Cargo commands thus apply the same policy.
The Rust examples in this README compile as doctests.

The fuzz targets are in `fuzz/`. Run them with `cargo-fuzz` on Linux, macOS or WSL:

```bash
cargo +nightly fuzz run fuzz-pe-headers
cargo +nightly fuzz run fuzz-pe-parse
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Portex by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
