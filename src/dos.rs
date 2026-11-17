//! DOS header structure and parsing.

use core::mem::{offset_of, size_of};

use crate::parse_utils::{le_u16, le_u32, put_u16, put_u32};
use crate::prelude::*;
use crate::reader::ReadAt;
use crate::{Error, Result};

/// DOS "MZ" signature.
pub const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"

/// The layout of `IMAGE_DOS_HEADER`. `winnt.h` packs it to 2 bytes.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C, packed(2))]
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror the `e_*` members of IMAGE_DOS_HEADER"
)]
pub(crate) struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    pub(crate) e_lfanew: i32,
}

// Anchors from `winnt.h` that the layout must keep.
const _: () = {
    assert!(size_of::<ImageDosHeader>() == 0x40);
    assert!(offset_of!(ImageDosHeader, e_lfarlc) == 0x18);
    assert!(offset_of!(ImageDosHeader, e_res2) == 0x28);
    assert!(offset_of!(ImageDosHeader, e_lfanew) == 0x3c);
};

/// DOS Header (`IMAGE_DOS_HEADER`).
///
/// The DOS header is the first structure in a PE file. It starts at file offset 0.
/// It holds the DOS stub fields and the file offset of the PE header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror the `e_*` members of IMAGE_DOS_HEADER"
)]
pub struct DosHeader {
    /// Magic number ("MZ" = 0x5A4D).
    pub e_magic: u16,
    /// Bytes on last page of file.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Size of header in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial (relative) SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial (relative) CS value.
    pub e_cs: u16,
    /// File offset of the relocation table.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// Reserved words.
    pub e_res: [u16; 4],
    /// OEM identifier.
    pub e_oemid: u16,
    /// OEM information.
    pub e_oeminfo: u16,
    /// Reserved words.
    pub e_res2: [u16; 10],
    /// File offset of the new EXE header (the PE header).
    ///
    /// The value can be smaller than [`Self::SIZE`]. Then the NT headers overlap the DOS header,
    /// and the DOS header fields after `e_lfanew` are bytes of the NT headers.
    pub e_lfanew: i32,
}

impl DosHeader {
    /// Size of the DOS header in bytes.
    pub const SIZE: usize = size_of::<ImageDosHeader>();

    /// The smallest `e_lfanew`: the PE signature cannot overlap `e_magic`.
    ///
    /// The loader of executable images needs 4 or more, but the data-file loader accepts 2.
    pub(crate) const MIN_PE_OFFSET: usize = 2;

    /// The `e_lfanew` value that puts the NT headers directly after the DOS header.
    pub(crate) const END_AS_LFANEW: i32 = 0x40;

    /// Parse a DOS header from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `data` is shorter than [`Self::SIZE`],
    /// or an invalid-DOS-signature error if `e_magic` is not [`DOS_SIGNATURE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(raw) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        /// Return the `u16` at the offset of `$field` (plus `$index` words) in `ImageDosHeader`.
        macro_rules! word {
            ($field:ident) => {
                word!($field, 0)
            };
            ($field:ident, $index:literal) => {
                le_u16::<
                    { DosHeader::SIZE },
                    { offset_of!(ImageDosHeader, $field) + $index * size_of::<u16>() },
                >(raw)
            };
        }

        let e_magic = word!(e_magic);
        if e_magic != DOS_SIGNATURE {
            return Err(Error::invalid_dos_signature());
        }
        Ok(Self {
            e_magic,
            e_cblp: word!(e_cblp),
            e_cp: word!(e_cp),
            e_crlc: word!(e_crlc),
            e_cparhdr: word!(e_cparhdr),
            e_minalloc: word!(e_minalloc),
            e_maxalloc: word!(e_maxalloc),
            e_ss: word!(e_ss),
            e_sp: word!(e_sp),
            e_csum: word!(e_csum),
            e_ip: word!(e_ip),
            e_cs: word!(e_cs),
            e_lfarlc: word!(e_lfarlc),
            e_ovno: word!(e_ovno),
            e_res: [
                word!(e_res, 0),
                word!(e_res, 1),
                word!(e_res, 2),
                word!(e_res, 3),
            ],
            e_oemid: word!(e_oemid),
            e_oeminfo: word!(e_oeminfo),
            e_res2: [
                word!(e_res2, 0),
                word!(e_res2, 1),
                word!(e_res2, 2),
                word!(e_res2, 3),
                word!(e_res2, 4),
                word!(e_res2, 5),
                word!(e_res2, 6),
                word!(e_res2, 7),
                word!(e_res2, 8),
                word!(e_res2, 9),
            ],
            e_lfanew: le_u32::<{ Self::SIZE }, { offset_of!(ImageDosHeader, e_lfanew) }>(raw)
                .cast_signed(),
        })
    }

    /// Write the DOS header to a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `buf` is shorter than [`Self::SIZE`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let out = buf
            .first_chunk_mut::<{ Self::SIZE }>()
            .ok_or_else(|| Error::buffer_too_small(Self::SIZE, len))?;
        *out = self.encode();
        Ok(())
    }

    /// Encode the header into its on-disk little-endian layout.
    fn encode(&self) -> [u8; Self::SIZE] {
        /// Write the `u16` value at the offset of `$field` (plus `$index` words).
        macro_rules! put_word {
            ($raw:ident, $field:ident, $value:expr) => {
                put_word!($raw, $field, 0, $value)
            };
            ($raw:ident, $field:ident, $index:literal, $value:expr) => {
                put_u16::<
                    { DosHeader::SIZE },
                    { offset_of!(ImageDosHeader, $field) + $index * size_of::<u16>() },
                >(&mut $raw, $value)
            };
        }

        let mut raw = [0u8; Self::SIZE];
        put_word!(raw, e_magic, self.e_magic);
        put_word!(raw, e_cblp, self.e_cblp);
        put_word!(raw, e_cp, self.e_cp);
        put_word!(raw, e_crlc, self.e_crlc);
        put_word!(raw, e_cparhdr, self.e_cparhdr);
        put_word!(raw, e_minalloc, self.e_minalloc);
        put_word!(raw, e_maxalloc, self.e_maxalloc);
        put_word!(raw, e_ss, self.e_ss);
        put_word!(raw, e_sp, self.e_sp);
        put_word!(raw, e_csum, self.e_csum);
        put_word!(raw, e_ip, self.e_ip);
        put_word!(raw, e_cs, self.e_cs);
        put_word!(raw, e_lfarlc, self.e_lfarlc);
        put_word!(raw, e_ovno, self.e_ovno);
        let [r0, r1, r2, r3] = self.e_res;
        put_word!(raw, e_res, 0, r0);
        put_word!(raw, e_res, 1, r1);
        put_word!(raw, e_res, 2, r2);
        put_word!(raw, e_res, 3, r3);
        put_word!(raw, e_oemid, self.e_oemid);
        put_word!(raw, e_oeminfo, self.e_oeminfo);
        let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9] = self.e_res2;
        put_word!(raw, e_res2, 0, s0);
        put_word!(raw, e_res2, 1, s1);
        put_word!(raw, e_res2, 2, s2);
        put_word!(raw, e_res2, 3, s3);
        put_word!(raw, e_res2, 4, s4);
        put_word!(raw, e_res2, 5, s5);
        put_word!(raw, e_res2, 6, s6);
        put_word!(raw, e_res2, 7, s7);
        put_word!(raw, e_res2, 8, s8);
        put_word!(raw, e_res2, 9, s9);
        put_u32::<{ Self::SIZE }, { offset_of!(ImageDosHeader, e_lfanew) }>(
            &mut raw,
            self.e_lfanew.cast_unsigned(),
        );
        raw
    }

    /// Parse a DOS header from a positional reader at the file offset `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::SIZE`] bytes cannot be read at `offset`,
    /// or any error from [`Self::parse`].
    pub fn read_from<R: ReadAt>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Serialize the DOS header to a byte vector.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        self.encode().to_vec()
    }
}

#[cfg(test)]
mod tests;
