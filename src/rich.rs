//! Rich Header parsing and building.
//!
//! The Rich header is an undocumented structure. The Microsoft linker inserts it between the
//! DOS stub and the PE signature. It contains information about the build tools.

mod product;

use core::mem::{offset_of, size_of};

use crate::dos::{DosHeader, ImageDosHeader};
use crate::optional::ImageNtHeaders32;
use crate::parse_utils::{le_u32, put_u32, zero_extended};
use crate::prelude::*;
use crate::{Error, Result};

/// The end marker of the Rich header (`"Rich"`). The file stores it unencoded, followed by the
/// XOR key.
const RICH_MAGIC: u32 = 0x6863_6952; // "Rich"

/// The value of the `DanS` start marker before the XOR with the key.
const DANS_MAGIC: u32 = 0x536E_6144; // "DanS"

/// The layout of the `DanS` block that starts the Rich header.
///
/// The Rich header is not a `winnt.h` structure. Portex does not read the block through this
/// type. The type gives the offset and the width of each field.
#[repr(C)]
struct RichDansBlock {
    /// `DANS_MAGIC` XOR the key.
    dans: u32,
    /// Three words that each hold the key (zero XOR the key).
    padding: [u32; 3],
}

/// The layout of one Rich header entry. The file stores each field XOR the key.
///
/// Portex does not read the entry through this type. The type gives the offset and the width
/// of each field.
#[repr(C)]
struct RichEntryRecord {
    comp_id: u32,
    use_count: u32,
}

/// The layout of the end of the Rich header: the unencoded `Rich` marker and the key.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct RichTrailer {
    rich: u32,
    key: u32,
}

/// The size of the `DanS` block.
const DANS_BLOCK_SIZE: usize = size_of::<RichDansBlock>();
/// The size of one entry.
const ENTRY_SIZE: usize = size_of::<RichEntryRecord>();
/// The size of the `Rich` marker and the key.
const TRAILER_SIZE: usize = size_of::<RichTrailer>();
/// The size of a Rich header without entries.
const EMPTY_SIZE: usize = DANS_BLOCK_SIZE + TRAILER_SIZE;
/// The size of one word of the Rich header. The markers and the entries are word aligned.
const WORD_SIZE: usize = size_of::<u32>();
/// The file offset of `e_lfanew` in the DOS header.
const E_LFANEW: usize = offset_of!(ImageDosHeader, e_lfanew);
/// The size of `e_lfanew`, a `LONG`.
const E_LFANEW_SIZE: usize = size_of::<i32>();

const _: () = {
    assert!(DANS_BLOCK_SIZE == 16);
    assert!(ENTRY_SIZE == 8);
    assert!(TRAILER_SIZE == 8);
};

/// Return the size of a Rich header with `entry_count` entries.
///
/// # Errors
///
/// Returns a generic error if the size overflows `usize`.
fn encoded_size(entry_count: usize) -> Result<usize> {
    entry_count
        .checked_mul(ENTRY_SIZE)
        .and_then(|size| size.checked_add(EMPTY_SIZE))
        .ok_or_else(|| Error::generic("Rich-header size overflow"))
}

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
        let [product_id, build_number] =
            [comp_id >> 16, comp_id & 0xFFFF].map(|half| u16::try_from(half).unwrap_or_default());
        Self {
            product_id,
            build_number,
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
        let (dos, available) = zero_extended::<{ DosHeader::SIZE }>(data);
        if available < E_LFANEW + E_LFANEW_SIZE {
            return None;
        }
        let pe_offset = usize::try_from(le_u32::<{ DosHeader::SIZE }, E_LFANEW>(&dos)).ok()?;
        let signature_end = pe_offset.checked_add(offset_of!(ImageNtHeaders32, file_header))?;
        if signature_end > data.len() || pe_offset < DosHeader::SIZE + EMPTY_SIZE {
            return None;
        }

        // Scan the 4-byte aligned offsets one time. Record each valid `DanS` block (marker and
        // three padding words that hold the key) by its key. Keep the last block for each
        // parity of the dword index, because the entries between `DanS` and `Rich` must be a
        // multiple of 8 bytes. A `Rich` marker followed by its key then needs one map look-up.
        // Older Portex versions incorrectly XORed the marker. Accept that form when you parse,
        // but never write it. The last match before the PE header wins.
        let last_rich = pe_offset.checked_sub(TRAILER_SIZE)?;
        let mut dans_blocks: BTreeMap<u32, [Option<usize>; 2]> = BTreeMap::new();
        let mut found = None;
        let mut rich_offset: usize = DosHeader::SIZE + DANS_BLOCK_SIZE;
        while rich_offset <= last_rich {
            let start = rich_offset.checked_sub(DANS_BLOCK_SIZE)?;
            let block = data
                .get(start..)
                .and_then(<[u8]>::first_chunk::<DANS_BLOCK_SIZE>)?;
            let pad_key = le_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, padding) }>(block);
            if le_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, dans) }>(block) ^ pad_key
                == DANS_MAGIC
                && le_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, padding) + WORD_SIZE }>(
                    block,
                ) == pad_key
                && le_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, padding) + 2 * WORD_SIZE }>(
                    block,
                ) == pad_key
            {
                dans_blocks.entry(pad_key).or_default()[(start / WORD_SIZE) % 2] = Some(start);
            }

            let trailer = data
                .get(rich_offset..)
                .and_then(<[u8]>::first_chunk::<TRAILER_SIZE>)?;
            let value = le_u32::<TRAILER_SIZE, { offset_of!(RichTrailer, rich) }>(trailer);
            let key = le_u32::<TRAILER_SIZE, { offset_of!(RichTrailer, key) }>(trailer);
            if (value == RICH_MAGIC || value ^ key == RICH_MAGIC)
                && let Some(start) = dans_blocks
                    .get(&key)
                    .and_then(|slots| slots[(rich_offset / WORD_SIZE) % 2])
            {
                found = Some((start, rich_offset, key));
            }
            rich_offset = rich_offset.checked_add(WORD_SIZE)?;
        }

        let (start_offset, rich_offset, key) = found?;
        let block = data.get(start_offset..rich_offset)?;
        let entry_bytes = block.get(DANS_BLOCK_SIZE..)?;
        let records = entry_bytes.as_chunks::<ENTRY_SIZE>().0;
        let mut entries = Vec::with_capacity(records.len());
        for record in records {
            let comp_id =
                le_u32::<ENTRY_SIZE, { offset_of!(RichEntryRecord, comp_id) }>(record) ^ key;
            let count =
                le_u32::<ENTRY_SIZE, { offset_of!(RichEntryRecord, use_count) }>(record) ^ key;
            if comp_id != 0 || count != 0 {
                entries.push(RichEntry::from_comp_id(comp_id, count));
            }
        }
        Some(Self {
            key,
            entries,
            offset: start_offset,
            size: block.len().checked_add(TRAILER_SIZE)?,
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
        let size = encoded_size(self.entries.len())?;
        let mut buf = Vec::with_capacity(size);
        let key = self.key;

        // Write the DanS marker and the padding (3 dwords). XOR all of them with the key.
        let mut dans = [0u8; DANS_BLOCK_SIZE];
        put_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, dans) }>(
            &mut dans,
            DANS_MAGIC ^ key,
        );
        put_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, padding) }>(&mut dans, key);
        put_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, padding) + WORD_SIZE }>(
            &mut dans, key,
        );
        put_u32::<DANS_BLOCK_SIZE, { offset_of!(RichDansBlock, padding) + 2 * WORD_SIZE }>(
            &mut dans, key,
        );
        buf.extend_from_slice(&dans);

        // Write the entries.
        for entry in &self.entries {
            let mut record = [0u8; ENTRY_SIZE];
            put_u32::<ENTRY_SIZE, { offset_of!(RichEntryRecord, comp_id) }>(
                &mut record,
                entry.to_comp_id() ^ key,
            );
            put_u32::<ENTRY_SIZE, { offset_of!(RichEntryRecord, use_count) }>(
                &mut record,
                entry.use_count ^ key,
            );
            buf.extend_from_slice(&record);
        }

        // Write the Rich marker and the key.
        let mut trailer = [0u8; TRAILER_SIZE];
        put_u32::<TRAILER_SIZE, { offset_of!(RichTrailer, rich) }>(&mut trailer, RICH_MAGIC);
        put_u32::<TRAILER_SIZE, { offset_of!(RichTrailer, key) }>(&mut trailer, key);
        buf.extend_from_slice(&trailer);

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
        // `usize` has 32 bits on some targets, so the mask works on a `u64`.
        let mut checksum = u64::try_from(prefix.len())
            .ok()
            .and_then(|len| u32::try_from(len & u64::from(u32::MAX)).ok())
            .unwrap_or_default();

        for (offset, &byte) in prefix.iter().enumerate() {
            if (E_LFANEW..E_LFANEW + E_LFANEW_SIZE).contains(&offset) {
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
        encoded_size(self.entries.len())
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
