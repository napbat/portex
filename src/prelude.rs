//! The internal prelude. Each source file uses `use crate::prelude::*;` to get the `alloc`
//! types and macros that the code needs.
//!
//! With this prelude, the import header of each module is one line. It also keeps the
//! `no_std` imports in one location, so modules do not repeat `#[cfg]` blocks. All items
//! are `alloc` re-exports. Under the `std` feature, they shadow prelude items of the same
//! type, and this causes no problem.

pub use alloc::borrow::Cow;
pub use alloc::boxed::Box;
pub use alloc::collections::{BTreeMap, BTreeSet};
pub use alloc::format;
pub use alloc::string::{String, ToString};
pub use alloc::vec;
pub use alloc::vec::Vec;
