//! Fuzz target that reads arbitrary bytes with the raw views of `portex::raw`.
//!
//! The last bytes of the input are control bytes. They select the offsets, the sizes, the end
//! rules and the entry widths. The other bytes are the buffer. The target also parses the
//! buffer as PE headers, and reads the tables at the offsets of the data directories.
//!
//! The target panics in these conditions:
//!
//! - A cursor returns more records than the buffer can hold.
//! - The record offsets of a cursor do not increase.
//! - A cursor returns a record after it returned the end of the table.
//! - A record is different from a new parse at the offset of the record.
//! - `RawIter` returns records that are different from the records of `read_next`.
//! - `PeHeaders::from_slice_strict` succeeds, and `PeHeaders::from_slice` fails or returns
//!   different headers.
//! - A field at an offset from `PeHeaders::header_offsets` has a value that is different from
//!   the parsed headers.
//! - `PeHeaders::data_directory` is different from the data directory array.

#![no_main]

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use portex::exception::UNW_FLAG_CHAININFO;
use portex::raw::{
    HeaderOffsets, ImportTableEnd, RawAddressTable, RawCursor, RawExportDirectory, RawImportByName,
    RawImportDescriptor, RawImportDescriptors, RawLoadConfigDirectory, RawRelocationBlock,
    RawRelocationBlocks, RawResourceDataEntry, RawResourceDirectory, RawResourceEntry,
    RawRuntimeFunction, RawRuntimeFunctions, RawUnwindInfo,
};
use portex::{DataDirectoryType, OptionalHeader, PeHeaders, RelocationEntry, RelocationType};

/// The count of control bytes at the end of the input.
const CONTROL_SIZE: usize = 64;
/// The largest count of records of one table for which the target reads the nested tables.
const MAX_NESTED: usize = 32;
/// The largest count of resource directories that the target reads in one tree.
const MAX_RESOURCE_DIRECTORIES: usize = 512;
/// The largest count of chained `UNWIND_INFO` structures that the target follows.
const MAX_UNWIND_CHAIN: usize = 8;
/// The largest size of a hint/name entry that the target reads.
const MAX_NAME_SIZE: usize = 1024;
/// The value of the PE signature `PE\0\0` as a little-endian `u32`.
const PE_SIGNATURE: u32 = 0x0000_4550;

fuzz_target!(|input: &[u8]| {
    let split = input.len().saturating_sub(CONTROL_SIZE);
    let (data, control) = input.split_at(split);
    let mut control = Control { bytes: control };
    let loose = PeHeaders::from_slice(data);
    let strict = PeHeaders::from_slice_strict(data);
    if let Ok(strict) = &strict {
        let loose = loose
            .as_ref()
            .expect("from_slice_strict succeeds, but from_slice fails");
        assert_eq!(loose, strict, "from_slice and from_slice_strict differ");
    }
    if let Ok(headers) = &loose {
        check_headers(headers, data, strict.is_ok());
    }
    let headers = loose.as_ref().ok();
    let mut reader = Reader {
        data,
        mapper: Mapper {
            headers,
            file_layout: control.flag(),
        },
        is_64bit: headers.map_or_else(|| control.flag(), PeHeaders::is_64bit),
        control,
    };
    if let Some(headers) = headers {
        reader.read_directories(headers);
    }
    reader.read_arbitrary();
});

/// The control bytes of the input.
struct Control<'a> {
    /// The control bytes that remain. After the last byte, each value is zero.
    bytes: &'a [u8],
}

impl Control<'_> {
    /// Return the next control byte, or zero after the last byte.
    fn byte(&mut self) -> u8 {
        let Some((&first, rest)) = self.bytes.split_first() else {
            return 0;
        };
        self.bytes = rest;
        first
    }

    /// Return the next control bit.
    fn flag(&mut self) -> bool {
        self.byte() & 1 != 0
    }

    /// Return a little-endian `u32` from the next four control bytes.
    fn word(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    /// Return an offset for a buffer of `len` bytes.
    ///
    /// Most offsets are in the buffer or just after it. Some are near `usize::MAX`, to test
    /// the overflow checks.
    fn offset(&mut self, len: usize) -> usize {
        match self.byte() % 8 {
            0 => usize::MAX - usize::from(self.byte()),
            1 => len.saturating_sub(usize::from(self.byte())),
            _ => usize::try_from(self.word()).map_or(0, |value| value % (len + 1)),
        }
    }

    /// Return a table size for a buffer of `len` bytes.
    fn size(&mut self, len: usize) -> usize {
        match self.byte() % 8 {
            0 => usize::MAX,
            1 => 0,
            _ => usize::try_from(self.word())
                .map_or(0, |value| value % len.saturating_mul(2).saturating_add(64)),
        }
    }

    /// Return an end rule for a list of import descriptors.
    fn end_rule(&mut self) -> ImportTableEnd {
        match self.byte() % 3 {
            0 => ImportTableEnd::ZeroNameOrFirstThunk,
            1 => ImportTableEnd::NullDescriptor,
            _ => ImportTableEnd::ZeroOriginalFirstThunk,
        }
    }
}

/// The conversion from an RVA to a buffer offset.
struct Mapper<'h> {
    /// The parsed headers, if the buffer has headers.
    headers: Option<&'h PeHeaders>,
    /// `true` to use the file layout of the headers, `false` to use the RVA as the offset.
    file_layout: bool,
}

impl Mapper<'_> {
    /// Return the buffer offset of `rva`, or `None` if no offset agrees.
    fn offset(&self, rva: u64) -> Option<usize> {
        let rva = u32::try_from(rva).ok()?;
        let offset = match self.headers {
            Some(headers) if self.file_layout => headers.rva_to_offset(rva)?,
            _ => rva,
        };
        usize::try_from(offset).ok()
    }

    /// Return the buffer offset of the VA `va`, or `None` if no offset agrees.
    fn va_offset(&self, va: u64) -> Option<usize> {
        let image_base = self.headers.map_or(0, PeHeaders::image_base);
        self.offset(va.checked_sub(image_base)?)
    }
}

/// Read all records of `cursor` in `data`, once with `read_next` and once with `RawIter`.
///
/// Make sure that both ways return the same records, that the record offsets increase, and
/// that the cursor returns no record after the end. Return the records.
fn drain<C>(cursor: C, data: &[u8], offset_of: impl Fn(&C::Item) -> usize) -> Vec<C::Item>
where
    C: RawCursor + Clone,
    C::Item: PartialEq + Debug,
{
    // Each record has 2 bytes or more, and its offset increases.
    let cap = data.len() / 2 + 2;
    let mut iter = cursor.clone().iter(data);
    let mut by_iter = Vec::new();
    while let Some(Ok(item)) = iter.next() {
        by_iter.push(item);
        assert!(by_iter.len() <= cap, "RawIter returns too many records");
    }
    assert!(
        iter.next().is_none(),
        "RawIter returns a record after its end"
    );

    let mut cursor = cursor;
    let mut items: Vec<C::Item> = Vec::new();
    loop {
        match cursor.read_next(data) {
            Ok(Some(item)) => {
                if let Some(previous) = items.last() {
                    assert!(
                        offset_of(&item) > offset_of(previous),
                        "the record offsets do not increase"
                    );
                }
                items.push(item);
                assert!(items.len() <= cap, "read_next returns too many records");
            }
            Ok(None) => {
                assert!(
                    matches!(cursor.read_next(data), Ok(None)),
                    "read_next returns a record after the end"
                );
                break;
            }
            Err(_) => break,
        }
    }
    assert_eq!(items, by_iter, "RawIter and read_next differ");
    items
}

/// Make sure that the headers agree with the bytes at their offsets.
///
/// `PeHeaders::from_slice` reads the bytes after the end of `data` as zeros, so the check does
/// the same. If `strict` is `true`, all header bytes must be in `data`.
fn check_headers(headers: &PeHeaders, data: &[u8], strict: bool) {
    for kind in DataDirectoryType::all() {
        assert_eq!(
            headers.data_directory(kind),
            headers
                .optional_header
                .data_directories()
                .get(kind.as_index()),
            "data_directory is different from the data directory array"
        );
    }
    let offsets = headers
        .header_offsets()
        .expect("the headers parse, but their offsets overflow");
    let coff = &headers.coff_header;
    let optional = &headers.optional_header;
    let (magic, check_sum) = match optional {
        OptionalHeader::Pe32(header) => (header.magic, header.check_sum),
        OptionalHeader::Pe32Plus(header) => (header.magic, header.check_sum),
    };
    let image_base_size = if headers.is_64bit() { 8 } else { 4 };
    let mut fields: Vec<HeaderField> = vec![
        (offsets.nt_headers, 4, u64::from(PE_SIGNATURE), "Signature"),
        (offsets.coff_header, 2, u64::from(coff.machine), "Machine"),
        (
            offsets.time_date_stamp,
            4,
            u64::from(coff.time_date_stamp),
            "TimeDateStamp",
        ),
        (offsets.optional_header, 2, u64::from(magic), "Magic"),
        (
            offsets.image_base,
            image_base_size,
            optional.image_base(),
            "ImageBase",
        ),
        (
            offsets.size_of_image,
            4,
            u64::from(optional.size_of_image()),
            "SizeOfImage",
        ),
        (
            offsets.size_of_headers,
            4,
            u64::from(optional.size_of_headers()),
            "SizeOfHeaders",
        ),
        (offsets.check_sum, 4, u64::from(check_sum), "CheckSum"),
    ];
    for (index, directory) in optional.data_directories().iter().enumerate() {
        let offset = offsets
            .data_directory(index)
            .expect("a data directory offset overflows");
        let size_offset = offset.checked_add(4).expect("a directory offset overflows");
        fields.push((offset, 4, u64::from(directory.virtual_address), "an RVA"));
        fields.push((size_offset, 4, u64::from(directory.size), "a size"));
    }
    fields.extend(section_fields(headers, &offsets));
    for (offset, size, expected, name) in fields {
        let end = offset.checked_add(size).expect("a field end overflows");
        assert!(
            !strict || end <= data.len(),
            "the strict parse succeeds, but {name} is not in the buffer"
        );
        let bytes = data
            .get(offset.min(data.len())..end.min(data.len()))
            .unwrap_or_default();
        let mut value = [0; 8];
        value[..bytes.len()].copy_from_slice(bytes);
        assert_eq!(u64::from_le_bytes(value), expected, "{name} is different");
    }
}

/// A header field to check: its offset, its size in bytes, its parsed value and its name.
type HeaderField = (usize, usize, u64, &'static str);

/// Return the fields of each section header of `headers` at the offsets of `offsets`.
fn section_fields(headers: &PeHeaders, offsets: &HeaderOffsets) -> Vec<HeaderField> {
    let mut fields = Vec::new();
    for (index, section) in headers.section_headers.iter().enumerate() {
        let offset = offsets
            .section_header(index)
            .expect("a section header offset overflows");
        let field = |delta: usize| offset.checked_add(delta).expect("a field offset overflows");
        fields.extend([
            (offset, 8, u64::from_le_bytes(section.name), "Name"),
            (field(8), 4, u64::from(section.virtual_size), "VirtualSize"),
            (
                field(12),
                4,
                u64::from(section.virtual_address),
                "VirtualAddress",
            ),
            (
                field(16),
                4,
                u64::from(section.size_of_raw_data),
                "SizeOfRawData",
            ),
            (
                field(20),
                4,
                u64::from(section.pointer_to_raw_data),
                "PointerToRawData",
            ),
            (
                field(36),
                4,
                u64::from(section.characteristics),
                "Characteristics",
            ),
        ]);
    }
    fields
}

/// Read the little-endian `u32` at `offset` as a raw field, or `None` if it is not in `data`.
fn read_u32(data: &[u8], offset: usize) -> Option<portex::raw::RawField<u32>> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    let value = u32::from_le_bytes(bytes.try_into().ok()?);
    Some(portex::raw::RawField { offset, value })
}

/// Read the little-endian `u16` at `offset`, or `None` if it is not in `data`.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

/// Read the little-endian `u64` at `offset`, or `None` if it is not in `data`.
fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// The state that the table readers share.
struct Reader<'a> {
    /// The buffer.
    data: &'a [u8],
    /// The conversion from an RVA to a buffer offset.
    mapper: Mapper<'a>,
    /// `true` to read 64-bit address entries.
    is_64bit: bool,
    /// The control bytes.
    control: Control<'a>,
}

impl Reader<'_> {
    /// Read the tables at the offsets of the data directories.
    fn read_directories(&mut self, headers: &PeHeaders) {
        for kind in DataDirectoryType::all() {
            let Some(directory) = headers.data_directory(kind) else {
                continue;
            };
            if directory.virtual_address == 0 {
                continue;
            }
            let Some(offset) = self.mapper.offset(u64::from(directory.virtual_address)) else {
                continue;
            };
            let Ok(size) = usize::try_from(directory.size) else {
                continue;
            };
            match kind {
                DataDirectoryType::Export => self.export_directory(offset),
                DataDirectoryType::Import => {
                    let end = self.control.end_rule();
                    self.import_descriptors(offset, size, end);
                }
                DataDirectoryType::Resource => self.resource_tree(offset),
                DataDirectoryType::Exception => self.runtime_functions(offset, size),
                DataDirectoryType::BaseReloc => self.relocation_blocks(offset, size),
                DataDirectoryType::LoadConfig => self.load_config(offset, self.is_64bit),
                DataDirectoryType::Iat => {
                    self.address_table(RawAddressTable::zero_terminated(
                        offset,
                        size,
                        self.is_64bit,
                    ));
                }
                _ => {}
            }
        }
    }

    /// Read each table at offsets and sizes from the control bytes.
    fn read_arbitrary(&mut self) {
        let len = self.data.len();
        let (offset, size, end) = (
            self.control.offset(len),
            self.control.size(len),
            self.control.end_rule(),
        );
        self.import_descriptors(offset, size, end);
        let (offset, size, is_64bit) = (
            self.control.offset(len),
            self.control.size(len),
            self.control.flag(),
        );
        self.address_table(RawAddressTable::zero_terminated(offset, size, is_64bit));
        let (offset, count, is_64bit) = (
            self.control.offset(len),
            self.control.size(len),
            self.control.flag(),
        );
        self.address_table(RawAddressTable::counted(offset, count, is_64bit));
        let offset = self.control.offset(len);
        self.export_directory(offset);
        let (offset, size) = (self.control.offset(len), self.control.size(len));
        self.relocation_blocks(offset, size);
        let (offset, size) = (self.control.offset(len), self.control.size(len));
        self.runtime_functions(offset, size);
        let offset = self.control.offset(len);
        self.unwind_chain(offset);
        let (offset, is_64bit) = (self.control.offset(len), self.control.flag());
        self.load_config(offset, is_64bit);
        let offset = self.control.offset(len);
        self.resource_tree(offset);
        let (offset, size) = (self.control.offset(len), self.control.size(len));
        self.import_by_name(offset, size);
    }

    /// Read the import descriptors at `offset`, and their nested tables.
    fn import_descriptors(&mut self, offset: usize, size: usize, end: ImportTableEnd) {
        let data = self.data;
        let descriptors = drain(RawImportDescriptors::new(offset, size, end), data, |item| {
            item.offset
        });
        if let Some(first) = descriptors.first() {
            assert_eq!(
                first.offset, offset,
                "the first descriptor is not at the offset"
            );
        }
        for descriptor in descriptors.iter().take(MAX_NESTED) {
            assert_eq!(
                RawImportDescriptor::parse(data, descriptor.offset)
                    .ok()
                    .as_ref(),
                Some(descriptor),
                "a descriptor is different from a new parse"
            );
            assert_eq!(descriptor.is_null(), descriptor.descriptor().is_null());
            for rva in [
                descriptor.original_first_thunk.value,
                descriptor.first_thunk.value,
            ] {
                let Some(table) = self.mapper.offset(u64::from(rva)) else {
                    continue;
                };
                let size = self.control.size(data.len());
                let entries = self.address_table(RawAddressTable::zero_terminated(
                    table,
                    size,
                    self.is_64bit,
                ));
                let ordinal_flag = if self.is_64bit { 1 << 63 } else { 1 << 31 };
                for entry in entries.iter().take(MAX_NESTED) {
                    if entry.value & ordinal_flag != 0 {
                        continue;
                    }
                    if let Some(name) = self.mapper.offset(entry.value) {
                        let size = self.control.size(data.len());
                        self.import_by_name(name, size);
                    }
                }
            }
        }
    }

    /// Read the address table of `cursor`, and check each entry. Return the entries.
    fn address_table(&self, cursor: RawAddressTable) -> Vec<portex::raw::RawField<u64>> {
        let data = self.data;
        let entry_size = cursor.entry_size();
        let entries = drain(cursor, data, |entry| entry.offset);
        for entry in &entries {
            let value = if entry_size == 8 {
                read_u64(data, entry.offset)
            } else {
                read_u32(data, entry.offset).map(|field| u64::from(field.value))
            };
            assert_eq!(value, Some(entry.value), "an address entry is different");
        }
        entries
    }

    /// Read the hint/name entry at `offset`, and check its name.
    fn import_by_name(&self, offset: usize, size: usize) {
        let data = self.data;
        let size = size.min(MAX_NAME_SIZE);
        let Ok(Some(entry)) = RawImportByName::parse(data, offset, size) else {
            return;
        };
        assert_eq!(entry.offset, offset);
        assert_eq!(Some(entry.name_offset), offset.checked_add(2));
        assert_eq!(read_u16(data, offset), Some(entry.hint.value));
        let name = entry
            .name(data)
            .expect("the name of a parsed entry is not in the buffer");
        assert_eq!(name.len(), entry.name_len);
        assert!(!name.contains(&0), "the name contains a zero byte");
        let terminator = entry
            .name_offset
            .checked_add(entry.name_len)
            .expect("the name end overflows");
        assert_eq!(data.get(terminator), Some(&0), "no zero byte ends the name");
        let entry_size = entry.size().expect("the entry size overflows");
        assert_eq!(entry_size, entry.name_len + 3);
        assert!(
            entry_size <= size,
            "the entry is larger than its size limit"
        );
    }

    /// Read the export directory at `offset`, and its address tables.
    fn export_directory(&mut self, offset: usize) {
        let data = self.data;
        let Ok(directory) = RawExportDirectory::parse(data, offset) else {
            return;
        };
        let values = directory.directory();
        assert_eq!(
            values.number_of_functions,
            directory.number_of_functions.value
        );
        assert_eq!(
            directory.address_table_size(),
            directory.number_of_functions.value.checked_mul(4)
        );
        assert_eq!(
            directory.name_table_size(),
            directory.number_of_names.value.checked_mul(4)
        );
        assert_eq!(
            directory.ordinal_table_size(),
            directory.number_of_names.value.checked_mul(2)
        );
        assert_eq!(
            read_u32(data, offset.saturating_add(20)),
            Some(directory.number_of_functions),
            "NumberOfFunctions is not at its offset"
        );
        let tables = [
            (
                directory.address_of_functions.value,
                directory.number_of_functions.value,
            ),
            (
                directory.address_of_names.value,
                directory.number_of_names.value,
            ),
        ];
        for (rva, count) in tables {
            let (Some(table), Ok(count)) =
                (self.mapper.offset(u64::from(rva)), usize::try_from(count))
            else {
                continue;
            };
            let names = self.address_table(RawAddressTable::counted(table, count, false));
            assert!(names.len() <= count, "the cursor reads more than the count");
        }
    }

    /// Read the base relocation blocks at `offset`, and their entries.
    fn relocation_blocks(&mut self, offset: usize, size: usize) {
        let data = self.data;
        let blocks = drain(RawRelocationBlocks::new(offset, size), data, |block| {
            block.offset
        });
        let mut expected = offset;
        let mut total = 0usize;
        for block in &blocks {
            assert_eq!(
                block.offset, expected,
                "a block does not follow the previous block"
            );
            assert_eq!(
                RawRelocationBlock::parse(data, block.offset).as_ref().ok(),
                Some(block)
            );
            let block_size = usize::try_from(block.size_of_block.value).expect("a block size");
            assert!(
                block_size >= RawRelocationBlock::HEADER_SIZE,
                "a block is too small"
            );
            total = total
                .checked_add(block_size)
                .expect("the block sizes overflow");
            assert!(total <= size, "the blocks are larger than the table");
            expected = block.offset.saturating_add(block_size);
        }
        for block in blocks.iter().take(MAX_NESTED) {
            let words = (usize::try_from(block.size_of_block.value).unwrap_or(usize::MAX)
                - RawRelocationBlock::HEADER_SIZE)
                / 2;
            let entries = drain(block.entries(), data, |entry| entry.offset);
            let mut used = 0usize;
            for entry in &entries {
                let word = read_u16(data, entry.offset).expect("an entry is not in the buffer");
                assert_eq!(entry.entry, RelocationEntry::from_u16(word));
                used += 1;
                if let Some(parameter) = entry.parameter {
                    assert_eq!(entry.entry.reloc_type, RelocationType::HighAdj);
                    assert_eq!(Some(parameter.offset), entry.offset.checked_add(2));
                    assert_eq!(read_u16(data, parameter.offset), Some(parameter.value));
                    used += 1;
                }
            }
            assert!(used <= words, "the entries are larger than the block");
        }
    }

    /// Read the `RUNTIME_FUNCTION` records at `offset`, and their `UNWIND_INFO`.
    fn runtime_functions(&mut self, offset: usize, size: usize) {
        let data = self.data;
        let cursor = RawRuntimeFunctions::new(offset, size);
        assert_eq!(cursor.len(), size / RawRuntimeFunction::SIZE);
        assert_eq!(cursor.is_empty(), size < RawRuntimeFunction::SIZE);
        let count = cursor.len();
        let functions = drain(cursor, data, |function| function.offset);
        assert!(
            functions.len() <= count,
            "the cursor reads more than the count"
        );
        for function in functions.iter().take(MAX_NESTED) {
            assert_eq!(
                RawRuntimeFunction::parse(data, function.offset)
                    .as_ref()
                    .ok(),
                Some(function)
            );
            let values = function.function();
            assert_eq!(
                values.unwind_info_address,
                function.unwind_info_address.value
            );
            if let Some(unwind) = self
                .mapper
                .offset(u64::from(function.unwind_info_address.value))
            {
                self.unwind_chain(unwind);
            }
        }
    }

    /// Read the `UNWIND_INFO` at `offset`, and follow its chained functions.
    fn unwind_chain(&self, offset: usize) {
        let data = self.data;
        let mut offset = offset;
        for _ in 0..MAX_UNWIND_CHAIN {
            let Ok(info) = RawUnwindInfo::parse(data, offset) else {
                return;
            };
            assert_eq!(info.version(), info.version_and_flags.value & 0x07);
            assert_eq!(info.flags(), info.version_and_flags.value >> 3);
            let slots = usize::from(info.count_of_codes.value);
            let size = info.size_without_trailer();
            assert_eq!(size, RawUnwindInfo::HEADER_SIZE + 4 * slots.div_ceil(2));
            assert_eq!(
                size % 4,
                0,
                "the unwind codes do not end at a multiple of 4"
            );
            assert_eq!(info.trailer_offset(), offset.checked_add(size));
            if info.flags() & UNW_FLAG_CHAININFO == 0 {
                return;
            }
            assert!(info.has_trailer(), "a chained UNWIND_INFO has no trailer");
            let Some(Ok(chained)) = info
                .trailer_offset()
                .map(|trailer| RawRuntimeFunction::parse(data, trailer))
            else {
                return;
            };
            let Some(next) = self
                .mapper
                .offset(u64::from(chained.unwind_info_address.value))
            else {
                return;
            };
            offset = next;
        }
    }

    /// Read the load configuration at `offset`, and its lock prefix table.
    fn load_config(&mut self, offset: usize, is_64bit: bool) {
        let data = self.data;
        let Ok(config) = RawLoadConfigDirectory::parse(data, offset, is_64bit) else {
            return;
        };
        assert_eq!(config.offset, offset);
        assert_eq!(config.size.offset, offset);
        assert_eq!(read_u32(data, offset), Some(config.size));
        assert_eq!(read_u32(data, offset + 4), Some(config.time_date_stamp));
        let lock_prefix = if is_64bit {
            assert_eq!(config.lock_prefix_table.offset, offset + 40);
            read_u64(data, offset + 40)
        } else {
            assert_eq!(config.lock_prefix_table.offset, offset + 32);
            read_u32(data, offset + 32).map(|field| u64::from(field.value))
        };
        assert_eq!(lock_prefix, Some(config.lock_prefix_table.value));
        if let Some(table) = self.mapper.va_offset(config.lock_prefix_table.value) {
            let size = self.control.size(data.len());
            self.address_table(RawAddressTable::zero_terminated(table, size, is_64bit));
        }
    }

    /// Read the resource tree with the root directory at `root`.
    fn resource_tree(&self, root: usize) {
        let data = self.data;
        let mut pending = vec![root];
        let mut visited = 0;
        while let Some(offset) = pending.pop() {
            visited += 1;
            if visited > MAX_RESOURCE_DIRECTORIES {
                return;
            }
            let Ok(directory) = RawResourceDirectory::parse(data, offset) else {
                continue;
            };
            assert_eq!(
                directory.entry_count(),
                usize::from(directory.number_of_named_entries.value)
                    + usize::from(directory.number_of_id_entries.value)
            );
            assert_eq!(
                directory.entries_offset(),
                offset.checked_add(RawResourceDirectory::SIZE)
            );
            let Some(first) = directory.entries_offset() else {
                continue;
            };
            for index in 0..directory.entry_count() {
                let Some(entry_offset) = index
                    .checked_mul(RawResourceEntry::SIZE)
                    .and_then(|delta| first.checked_add(delta))
                else {
                    break;
                };
                let Ok(entry) = RawResourceEntry::parse(data, entry_offset) else {
                    break;
                };
                check_resource_entry(&entry);
                let Some(child) = usize::try_from(entry.child_offset())
                    .ok()
                    .and_then(|delta| root.checked_add(delta))
                else {
                    continue;
                };
                if entry.is_directory() {
                    pending.push(child);
                } else if let Ok(leaf) = RawResourceDataEntry::parse(data, child) {
                    assert_eq!(read_u32(data, child), Some(leaf.offset_to_data));
                    assert_eq!(read_u32(data, child + 4), Some(leaf.size));
                    assert_eq!(read_u32(data, child + 8), Some(leaf.code_page));
                    assert_eq!(read_u32(data, child + 12), Some(leaf.reserved));
                }
            }
        }
    }
}

/// Make sure that the helpers of `entry` agree with its fields.
fn check_resource_entry(entry: &RawResourceEntry) {
    const HIGH_BIT: u32 = 0x8000_0000;
    assert_eq!(entry.is_named(), entry.name_or_id.value & HIGH_BIT != 0);
    assert_eq!(
        entry.is_directory(),
        entry.offset_to_data.value & HIGH_BIT != 0
    );
    assert_eq!(entry.name_offset(), entry.name_or_id.value & !HIGH_BIT);
    assert_eq!(entry.child_offset(), entry.offset_to_data.value & !HIGH_BIT);
    assert_eq!(
        Some(entry.offset_to_data.offset),
        entry.offset.checked_add(4)
    );
}
