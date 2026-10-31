//! Sequential streams and positional image readers.
//!
//! [`nostdio`] supplies the sequential [`Read`], [`Write`] and [`Seek`] traits, which also
//! work in `no_std` builds. The Portex [`ReadAt`] trait stays positional. Thus you can query
//! mapped or remote images without a shared stream cursor.
//!
//! This module re-exports only the `nostdio` items in this list. Other `nostdio` items are not
//! part of the Portex API.
//!
//! # Caution
//!
//! The `std` feature changes the types that this module re-exports from `nostdio`. Without
//! `std`, they are the `nostdio` types. With `std`, they are the `std::io` items, for example
//! `std::io::Error` for [`IoError`]. Cargo unifies features, so a different crate in the
//! dependency graph can enable `std` and change these types for your crate too. Thus code
//! that must compile in the two configurations must not use the items that only one of the
//! types has, for example the variants of the `no_std` [`IoError`]. Use [`is_unexpected_eof`]
//! and [`is_interrupted`] to examine an [`IoError`].

pub use nostdio::{
    BufRead, Cursor, IoError, Read, Seek, SeekFrom, Write, is_interrupted, is_unexpected_eof,
};

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use crate::reader::FileReader;
pub use crate::reader::{BaseAddressReader, ReadAt, SeekReader, SliceReader, VecReader};
