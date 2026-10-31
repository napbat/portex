//! Rich Header parsing and building.
//!
//! The Rich header is an undocumented structure. The Microsoft linker inserts it between the
//! DOS stub and the PE signature. It contains information about the build tools.

mod product;

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
        let pe_offset = usize::try_from(read_u32(data, 0x3C)?).ok()?;
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
            let pad_key = read_u32(data, start.checked_add(4)?)?;
            if read_u32(data, start)? ^ pad_key == DANS_MAGIC
                && read_u32(data, start.checked_add(8)?)? == pad_key
                && read_u32(data, start.checked_add(12)?)? == pad_key
            {
                dans_blocks.entry(pad_key).or_default()[(start / 4) % 2] = Some(start);
            }

            let value = read_u32(data, rich_offset)?;
            let key = read_u32(data, rich_offset.checked_add(4)?)?;
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

/// Read a little-endian `u32` at `offset`, or return `None` if `data` is too short.
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..)?.first_chunk::<4>()?;
    Some(u32::from_le_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rich_entry_roundtrip() {
        let entry = RichEntry {
            product_id: 0x0104, // Utc1900_C
            build_number: 30729,
            use_count: 5,
        };

        let comp_id = entry.to_comp_id();
        let parsed = RichEntry::from_comp_id(comp_id, entry.use_count);
        assert_eq!(entry.product_id, parsed.product_id);
        assert_eq!(entry.build_number, parsed.build_number);
    }

    #[test]
    fn test_rich_header_build_parse() {
        let header = RichHeader {
            key: 0x1234_5678,
            entries: vec![
                RichEntry {
                    product_id: 0x0104,
                    build_number: 30729,
                    use_count: 5,
                },
                RichEntry {
                    product_id: 0x0105,
                    build_number: 30729,
                    use_count: 1,
                },
            ],
            offset: 0,
            size: 0,
        };

        let built = header.build();

        // Create a minimal PE structure to parse.
        let mut pe_data = vec![0u8; 0x200];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes()); // PE at 0x100

        // Insert the Rich header at 0x80.
        pe_data[0x80..0x80 + built.len()].copy_from_slice(&built);

        let parsed = RichHeader::parse(&pe_data).expect("Failed to parse Rich header");
        assert_eq!(parsed.key, header.key);
        assert_eq!(parsed.entries.len(), header.entries.len());
    }

    #[test]
    fn test_rich_builder() {
        let mut builder = RichBuilder::new();

        builder.add(0x0104, 30729, 5).add(0x0105, 30729, 1);

        assert_eq!(builder.entry_count(), 2);

        let (data, size) = builder.build_with_key(0xABCD_1234);
        assert!(size > 0);
        assert_eq!(data.len(), size as usize);
        assert_eq!(size as usize, builder.calculate_size());

        // Parse the result to verify it.
        let mut pe_data = vec![0u8; 0x200];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());
        pe_data[0x80..0x80 + data.len()].copy_from_slice(&data);

        let parsed = RichHeader::parse(&pe_data).unwrap();
        assert_eq!(parsed.key, 0xABCD_1234);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].product_id, 0x0104);
        assert_eq!(parsed.entries[1].product_id, 0x0105);
    }

    #[test]
    fn pe_image_parses_rich_header_from_its_dos_stub() {
        let mut image = crate::PeBuilder::new().try_build().unwrap();
        let (encoded, _) = RichBuilder::new()
            .add(0x0104, 30729, 5)
            .try_build_with_key(0x1234_5678)
            .unwrap();
        let start = image.dos_stub.len() - encoded.len();
        image.dos_stub[start..].copy_from_slice(&encoded);

        let parsed = image.rich_header().unwrap();
        assert_eq!(parsed.key, 0x1234_5678);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].product_id, 0x0104);
    }

    #[test]
    fn test_rich_builder_from_header() {
        let original = RichHeader {
            key: 0x1122_3344,
            entries: vec![RichEntry {
                product_id: 0x0104,
                build_number: 30729,
                use_count: 3,
            }],
            offset: 0,
            size: 0,
        };

        let builder = RichBuilder::from_header(&original);
        assert_eq!(builder.entry_count(), 1);

        let header = builder.into_header(0x5566_7788);
        assert_eq!(header.key, 0x5566_7788);
        assert_eq!(header.entries.len(), 1);
    }

    #[test]
    fn parse_is_linear_in_a_stub_full_of_rich_markers() {
        // Each aligned word is "Rich", so every offset is a candidate with the key "Rich". The
        // old nested search did about 2^38 steps for this stub. One scan needs 2^18 steps.
        let pe_offset = 0x10_0000usize;
        let mut data = b"Rich".repeat((pe_offset + 0x100) / 4);
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&u32::try_from(pe_offset).unwrap().to_le_bytes());
        assert_eq!(RichHeader::parse(&data), None);

        // A real header near the PE header is found in the same stub.
        let (encoded, _) = RichBuilder::new()
            .add(0x0105, 30729, 5)
            .try_build_with_key(0x1234_5678)
            .unwrap();
        let start = pe_offset - 0x40;
        data[start..start + encoded.len()].copy_from_slice(&encoded);
        let parsed = RichHeader::parse(&data).unwrap();
        assert_eq!(parsed.offset, start);
        assert_eq!(parsed.key, 0x1234_5678);
        assert_eq!(parsed.entries.len(), 1);
    }

    #[test]
    fn calculate_key_matches_the_linker_checksum() {
        let mut prefix = vec![0u8; 0x80];
        for (index, byte) in prefix.iter_mut().enumerate() {
            *byte = u8::try_from(index * 7 % 251).unwrap();
        }
        prefix[0..2].copy_from_slice(b"MZ");
        prefix[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());
        let entries = [
            RichEntry::from_comp_id(0x0105_7809, 37),
            RichEntry::from_comp_id(0x0102_7809, 1),
        ];

        // The spec formula, written out independently.
        let mut expected: u32 = 0x80;
        for index in 0..0x80u32 {
            if (0x3C..0x40).contains(&index) {
                continue;
            }
            let byte = u32::from(prefix[usize::try_from(index).unwrap()]);
            expected =
                expected.wrapping_add((byte << (index % 32)) | (byte >> ((32 - index % 32) % 32)));
        }
        expected = expected.wrapping_add(0x0105_7809u32.rotate_left(37 % 32));
        expected = expected.wrapping_add(0x0102_7809u32.rotate_left(1));
        assert_eq!(RichHeader::calculate_key(&entries, &prefix), expected);

        // The e_lfanew bytes have no effect on the key.
        let mut other = prefix.clone();
        other[0x3C..0x40].copy_from_slice(&0x200u32.to_le_bytes());
        assert_eq!(RichHeader::calculate_key(&entries, &other), expected);

        // The builder uses the same key, and the parser reads it back.
        let mut builder = RichBuilder::new();
        for entry in entries {
            builder.add_entry(entry);
        }
        let (encoded, _) = builder.try_build_with_dos_header(&prefix).unwrap();
        let mut data = prefix;
        data.extend_from_slice(&encoded);
        data.resize(0x100 + 4, 0);
        assert_eq!(RichHeader::parse(&data).unwrap().key, expected);
    }

    #[test]
    fn product_name_uses_the_published_prodid_table() {
        let name = |product_id| {
            RichEntry {
                product_id,
                build_number: 0,
                use_count: 0,
            }
            .product_name()
        };
        assert_eq!(name(0x0102), "Linker1400");
        assert_eq!(name(0x0104), "Utc1900_C");
        assert_eq!(name(0x0105), "Utc1900_CPP");
        assert_eq!(name(0x00FF), "Cvtres1400");
        assert_eq!(name(0x0101), "Implib1400");
        assert_eq!(name(0x0100), "Export1400");
        assert_eq!(name(0x00E3), "Utc1800_CVTCIL_CPP");
        assert_eq!(name(0x010F), "Unknown");
    }
}
