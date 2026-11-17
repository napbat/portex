//! Rich Header parsing and building.
//!
//! The Rich header is an undocumented structure. The Microsoft linker inserts it between the
//! DOS stub and the PE signature. It contains information about the build tools.

mod product;

use crate::parse_utils::u32_at;
use crate::prelude::*;
use crate::{Error, Result};

/// The end marker of the Rich header (`"Rich"`). The file stores it unencoded, followed by the
/// XOR key.
const RICH_MAGIC: u32 = 0x6863_6952; // "Rich"

/// The value of the `DanS` start marker before the XOR with the key.
const DANS_MAGIC: u32 = 0x536E_6144; // "DanS"

/// One entry of the Rich header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RichEntry {
    /// The product ID, which identifies the compiler or tool.
    pub product_id: u16,
    /// The build number of the tool.
    pub build_number: u16,
    /// The number of objects that the tool made.
    pub use_count: u32,
}

impl RichEntry {
    /// Create an entry from a raw `comp_id` value. The high 16 bits hold the product ID. The low
    /// 16 bits hold the build number.
    #[must_use]
    pub fn from_comp_id(comp_id: u32, use_count: u32) -> Self {
        let [build_lo, build_hi, product_lo, product_hi] = comp_id.to_le_bytes();
        Self {
            product_id: u16::from_le_bytes([product_lo, product_hi]),
            build_number: u16::from_le_bytes([build_lo, build_hi]),
            use_count,
        }
    }

    /// Convert the entry to a `comp_id` value. The high 16 bits hold the product ID. The low 16
    /// bits hold the build number.
    #[must_use]
    pub fn to_comp_id(self) -> u32 {
        (u32::from(self.product_id) << 16) | u32::from(self.build_number)
    }

    /// Return the name of the product from the published `prodid` table, or `"Unknown"`.
    ///
    /// The names come from the `prodid` enumeration of the Microsoft linker, without the
    /// `prodid` prefix. For example, `0x0102` is `"Linker1400"` and `0x0105` is
    /// `"Utc1900_CPP"` (the C++ compiler).
    #[must_use]
    pub fn product_name(self) -> &'static str {
        product::PRODUCT_NAMES
            .get(usize::from(self.product_id))
            .copied()
            .unwrap_or("Unknown")
    }
}

/// A parsed Rich header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RichHeader {
    /// The XOR key that encodes the header.
    pub key: u32,
    /// The tool entries.
    pub entries: Vec<RichEntry>,
    /// The file offset of the start of the Rich header (the `DanS` marker), after the DOS stub.
    pub offset: usize,
    /// The total size of the Rich header in bytes.
    pub size: usize,
}

impl RichHeader {
    /// Find and parse the Rich header in the DOS stub area.
    ///
    /// `data` must start at the beginning of the file. Returns `None` if there is no Rich header.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        // A Rich header lives between the fixed DOS header and the PE header.
        // Get the PE offset (`e_lfanew`) from the DOS header.
        let pe_offset = usize::try_from(u32_at(data, 0x3C)?).ok()?;
        if pe_offset.checked_add(4)? > data.len() || pe_offset < 0x40 + 24 {
            return None;
        }

        // Scan the 4-byte aligned offsets one time. Record each valid `DanS` block (marker and
        // three padding words that hold the key) by its key. Keep the last block for each
        // parity of the dword index, because the entries between `DanS` and `Rich` must be a
        // multiple of 8 bytes. A `Rich` marker followed by its key then needs one map look-up.
        // Older Portex versions incorrectly XORed the marker. Accept that form when you parse,
        // but never write it. The last match before the PE header wins.
        let last_rich = pe_offset.checked_sub(8)?;
        let mut dans_blocks: BTreeMap<u32, [Option<usize>; 2]> = BTreeMap::new();
        let mut found = None;
        let mut rich_offset: usize = 0x40 + 16;
        while rich_offset <= last_rich {
            let start = rich_offset.checked_sub(16)?;
            let pad_key = u32_at(data, start.checked_add(4)?)?;
            if u32_at(data, start)? ^ pad_key == DANS_MAGIC
                && u32_at(data, start.checked_add(8)?)? == pad_key
                && u32_at(data, start.checked_add(12)?)? == pad_key
            {
                dans_blocks.entry(pad_key).or_default()[(start / 4) % 2] = Some(start);
            }

            let value = u32_at(data, rich_offset)?;
            let key = u32_at(data, rich_offset.checked_add(4)?)?;
            if (value == RICH_MAGIC || value ^ key == RICH_MAGIC)
                && let Some(start) = dans_blocks
                    .get(&key)
                    .and_then(|slots| slots[(rich_offset / 4) % 2])
            {
                found = Some((start, rich_offset, key));
            }
            rich_offset = rich_offset.checked_add(4)?;
        }

        let (start_offset, rich_offset, key) = found?;
        let block = data.get(start_offset..rich_offset)?;
        let entry_bytes = block.get(16..)?;
        let chunks = entry_bytes.as_chunks::<8>().0;
        let mut entries = Vec::with_capacity(chunks.len());
        for &[c0, c1, c2, c3, n0, n1, n2, n3] in chunks {
            let comp_id = u32::from_le_bytes([c0, c1, c2, c3]) ^ key;
            let count = u32::from_le_bytes([n0, n1, n2, n3]) ^ key;
            if comp_id != 0 || count != 0 {
                entries.push(RichEntry::from_comp_id(comp_id, count));
            }
        }
        Some(Self {
            key,
            entries,
            offset: start_offset,
            size: block.len().checked_add(8)?,
        })
    }

    /// Build the bytes of the Rich header.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("Rich-header build failed: use try_build()")
    }

    /// Build a Rich header. Use checked arithmetic for the entry sizes.
    ///
    /// # Errors
    ///
    /// Returns a generic error if the encoded size overflows `usize`.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        // Size: DanS (4) + padding (12) + entries (8 each) + Rich (4) + key (4).
        let size = self
            .entries
            .len()
            .checked_mul(8)
            .and_then(|size| size.checked_add(24))
            .ok_or_else(|| Error::generic("Rich-header size overflow"))?;
        let mut buf = Vec::with_capacity(size);
        let key = self.key;

        // Write the DanS marker and the padding (3 dwords). XOR all of them with the key.
        buf.extend_from_slice(&(DANS_MAGIC ^ key).to_le_bytes());
        for _ in 0..3 {
            buf.extend_from_slice(&key.to_le_bytes());
        }

        // Write the entries.
        for entry in &self.entries {
            buf.extend_from_slice(&(entry.to_comp_id() ^ key).to_le_bytes());
            buf.extend_from_slice(&(entry.use_count ^ key).to_le_bytes());
        }

        // Write the Rich marker and the key.
        buf.extend_from_slice(&RICH_MAGIC.to_le_bytes());
        buf.extend_from_slice(&key.to_le_bytes());

        Ok(buf)
    }

    /// Calculate the checksum key of the Microsoft linker.
    ///
    /// `prefix` is all the file bytes before the `DanS` marker: the DOS header and the DOS stub.
    /// The length of `prefix` is the file offset of `DanS`. The key is that offset, plus
    /// `rotl(byte, i)` for each byte at offset `i` of `prefix` (the `e_lfanew` bytes at
    /// `0x3C..0x40` are not included), plus `rotl(comp_id, use_count & 31)` for each entry. All
    /// additions wrap at 32 bits.
    #[must_use]
    pub fn calculate_key(entries: &[RichEntry], prefix: &[u8]) -> u32 {
        // The offset is a u32 in the linker. Keep the low 32 bits.
        let length = prefix.len().to_le_bytes();
        let mut checksum = length
            .first_chunk::<4>()
            .map_or(0, |low| u32::from_le_bytes(*low));

        for (offset, &byte) in prefix.iter().enumerate() {
            if (0x3C..0x40).contains(&offset) {
                continue;
            }
            let rotation = u32::try_from(offset & 0x1F).unwrap_or(0);
            checksum = checksum.wrapping_add(u32::from(byte).rotate_left(rotation));
        }

        for entry in entries {
            let comp_id = entry.to_comp_id();
            checksum = checksum.wrapping_add(comp_id.rotate_left(entry.use_count & 0x1F));
        }

        checksum
    }

    /// Return `true` if the Rich header has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A builder for Rich headers.
///
/// The Microsoft linker inserts a Rich header with information about the build tools. This
/// builder creates Rich headers with the correct XOR encoding. Use
/// [`Self::try_build_with_dos_header`] to get the checksum key of the linker. Its input is all
/// the file bytes before the `DanS` marker.
///
/// # Example
///
/// ```
/// use portex::rich::{RichBuilder, RichEntry};
///
/// let mut builder = RichBuilder::new();
///
/// // Add build tool entries
/// builder.add_entry(RichEntry {
///     product_id: 0x0105,   // Utc1900_CPP (C++ compiler)
///     build_number: 30729,  // VS version
///     use_count: 5,
/// });
///
/// // Build with a specific key
/// let (data, size) = builder.build_with_key(0x12345678);
/// assert!(size > 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RichBuilder {
    entries: Vec<RichEntry>,
}

impl RichBuilder {
    /// Create an empty Rich builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder from an existing Rich header.
    #[must_use]
    pub fn from_header(header: &RichHeader) -> Self {
        Self {
            entries: header.entries.clone(),
        }
    }

    /// Add a build tool entry.
    pub fn add_entry(&mut self, entry: RichEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Add a build tool entry from its parts.
    pub fn add(&mut self, product_id: u16, build_number: u16, use_count: u32) -> &mut Self {
        self.entries.push(RichEntry {
            product_id,
            build_number,
            use_count,
        });
        self
    }

    /// Return the number of entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Calculate the size of the built Rich header.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(&self) -> usize {
        self.try_calculate_size()
            .expect("Rich-header size overflow: use try_calculate_size()")
    }

    /// Calculate the encoded size. Use checked arithmetic.
    ///
    /// # Errors
    ///
    /// Returns a generic error if the encoded size overflows `usize`.
    pub fn try_calculate_size(&self) -> Result<usize> {
        self.entries
            .len()
            .checked_mul(8)
            .and_then(|size| size.checked_add(24))
            .ok_or_else(|| Error::generic("Rich-header size overflow"))
    }

    /// Build the Rich header with a specific XOR key. Returns `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build_with_key`] fails.
    #[must_use]
    pub fn build_with_key(&self, key: u32) -> (Vec<u8>, u32) {
        self.try_build_with_key(key)
            .expect("Rich-header build failed: use try_build_with_key()")
    }

    /// Build the Rich header with a specific key. Check the encoded size. Returns `(data, size)`.
    ///
    /// # Errors
    ///
    /// Returns a generic error if the encoded size overflows `usize` or `u32`.
    pub fn try_build_with_key(&self, key: u32) -> Result<(Vec<u8>, u32)> {
        let size = self.try_calculate_size()?;
        let header = RichHeader {
            key,
            entries: self.entries.clone(),
            offset: 0,
            size,
        };
        let data = header.try_build()?;
        let size = u32::try_from(header.size)
            .map_err(|_| Error::generic("Rich-header size exceeds u32"))?;
        Ok((data, size))
    }

    /// Build the Rich header with the checksum key of the linker. Returns `(data, size)`.
    ///
    /// `prefix` is all the file bytes before the `DanS` marker. See
    /// [`RichHeader::calculate_key`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build_with_dos_header`] fails.
    #[must_use]
    pub fn build_with_dos_header(&self, prefix: &[u8]) -> (Vec<u8>, u32) {
        self.try_build_with_dos_header(prefix)
            .expect("Rich-header build failed: use try_build_with_dos_header()")
    }

    /// Build the Rich header with the checksum key of the linker. Check the encoded size.
    /// Returns `(data, size)`.
    ///
    /// `prefix` is all the file bytes before the `DanS` marker. Put the result at offset
    /// `prefix.len()`. See [`RichHeader::calculate_key`].
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_build_with_key`].
    pub fn try_build_with_dos_header(&self, prefix: &[u8]) -> Result<(Vec<u8>, u32)> {
        let key = RichHeader::calculate_key(&self.entries, prefix);
        self.try_build_with_key(key)
    }

    /// Build a [`RichHeader`] with a specific key.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_into_header`] fails.
    #[must_use]
    pub fn into_header(self, key: u32) -> RichHeader {
        self.try_into_header(key)
            .expect("Rich-header size overflow: use try_into_header()")
    }

    /// Build a [`RichHeader`] with a specific key. Check the encoded size.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`].
    pub fn try_into_header(self, key: u32) -> Result<RichHeader> {
        let size = self.try_calculate_size()?;
        Ok(RichHeader {
            key,
            entries: self.entries,
            offset: 0,
            size,
        })
    }
}

#[cfg(test)]
mod tests;
