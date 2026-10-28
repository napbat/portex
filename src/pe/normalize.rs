mod view;

pub(crate) use view::LoaderView;

use super::PeImage;
use crate::data_dir::{DataDirectory, DataDirectoryType};
use crate::dos::DosHeader;
use crate::optional::{OptionalHeader, PE32_MAGIC, PE32PLUS_MAGIC};
use crate::prelude::*;

/// The page size of the loader. If `SectionAlignment` is smaller, the loader maps the file as
/// it is (low alignment).
const PAGE_SIZE: u32 = 0x1000;

/// The `FileAlignment` that normalization uses in place of an invalid value.
const NORMAL_FILE_ALIGNMENT: u32 = 0x200;

/// The largest valid `FileAlignment`.
const MAX_FILE_ALIGNMENT: u32 = 0x1_0000;

/// The result of [`PeFile::normalize`](crate::PeFile::normalize).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Normalization {
    /// The field changes, in header order.
    pub changes: Vec<NormalizeChange>,
    /// The problems that `normalize` does not fix, because the fix changes the loader view or
    /// cannot be built.
    pub kept: Vec<NormalizeKept>,
}

/// A field change that [`PeFile::normalize`](crate::PeFile::normalize) makes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NormalizeChange {
    /// The NT headers moved out of the DOS header, so `e_lfanew` changed.
    NtHeadersOffset {
        /// The old `e_lfanew`.
        old: i32,
        /// The new `e_lfanew`.
        new: i32,
    },
    /// `SizeOfOptionalHeader` grew to the size of the optional header. The section table then
    /// follows the optional header.
    SizeOfOptionalHeader {
        /// The old value.
        old: u16,
        /// The new value.
        new: u16,
    },
    /// The optional-header `Magic` was not PE32 or PE32+. The new value is the magic of the
    /// layout that the parser used.
    Magic {
        /// The old value.
        old: u16,
        /// The new value.
        new: u16,
    },
    /// `SizeOfCode`, `SizeOfInitializedData`, `SizeOfUninitializedData`, `BaseOfCode` or
    /// `BaseOfData` changed to the value that the sections give.
    CodeAndDataFields,
    /// `SectionAlignment` was invalid. The new value keeps all section RVAs.
    SectionAlignment {
        /// The old value.
        old: u32,
        /// The new value.
        new: u32,
    },
    /// `FileAlignment` was invalid.
    FileAlignment {
        /// The old value.
        old: u32,
        /// The new value.
        new: u32,
    },
    /// `SizeOfImage` changed to the end of the last section.
    SizeOfImage {
        /// The old value.
        old: u32,
        /// The new value.
        new: u32,
    },
    /// `SizeOfHeaders` changed to the aligned size of the header data.
    SizeOfHeaders {
        /// The old value.
        old: u32,
        /// The new value.
        new: u32,
    },
    /// The stored nonzero checksum does not match the normalized file.
    Checksum {
        /// The old value.
        old: u32,
        /// The new value.
        new: u32,
    },
    /// `NumberOfRvaAndSizes` changed to the number of entries that the loader reads.
    NumberOfRvaAndSizes {
        /// The old value.
        old: u32,
        /// The new value.
        new: u32,
    },
    /// A data directory entry changed:
    ///
    /// - The reserved entries `Architecture` and `Reserved` become zero, and the `GlobalPtr`
    ///   size becomes zero. The loader does not use these values.
    /// - `BoundImport` becomes zero if the dropped header tail holds the bound import table.
    DataDirectory(DataDirectoryType),
    /// A section header field changed:
    ///
    /// - `PointerToRawData` and `SizeOfRawData` follow the new file layout.
    /// - A `VirtualSize` of 0 becomes the old `SizeOfRawData`, which is the size that the
    ///   loader uses for 0.
    Section {
        /// The index of the section in the section table.
        index: usize,
    },
    /// The section table grows into the header bytes after it, so the build drops them. This is
    /// allowed only for a bound import table, which the loader can do without.
    HeaderTail,
    /// The build rebased the `PointerToRawData` file offsets of the `IMAGE_DEBUG_DIRECTORY`
    /// entries.
    DebugPointers,
}

/// A problem that [`PeFile::normalize`](crate::PeFile::normalize) does not fix, because the fix
/// changes the loader view or cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NormalizeKept {
    /// A fix changes header bytes that the loader view uses: the bytes at the entry point or
    /// at a data directory, or a nonzero byte after the section table. The fix is not made.
    HeaderBytesInUse,
    /// A fix changes the section bytes that the loader maps.
    SectionData,
    /// A fix changes a section RVA, virtual size or characteristics, or the aligned size of the
    /// headers.
    SectionAddresses,
    /// `SectionAlignment` is smaller than a page, so the loader maps the file as it is. The
    /// file layout stays.
    LowAlignment,
    /// `SectionAlignment` is invalid, and no valid value keeps all section RVAs.
    Alignment,
    /// The layout update fails with this error message, for example on an overflow.
    Layout(String),
    /// The build of a fixed copy fails, or the built file does not parse. The value is the
    /// error message.
    Build(String),
    /// The checksum fix would change the loader view. A wrong checksum then stays wrong. A
    /// candidate that would make a valid checksum wrong is not used.
    Checksum,
}

impl PeImage {
    /// Return the normalized copies of this image, in the order of preference, and the reasons
    /// why a fix is not in them.
    ///
    /// The first copy has normal header fields and a new file layout, if a new layout keeps the
    /// RVA, the virtual size, the characteristics and the data of each section. The last copy
    /// has only the normal header fields. The caller must check the loader view of each copy.
    pub(crate) fn normalize_candidates(&self) -> (Vec<Self>, Vec<NormalizeKept>) {
        let mut fields = self.clone();
        fields.normalize_fields();
        match fields.normalized_layout(self) {
            Ok(layout) => (vec![layout, fields], Vec::new()),
            Err(reason) => (vec![fields], vec![reason]),
        }
    }

    /// Set the fields that the loader does not read to their normal values.
    fn normalize_fields(&mut self) {
        let length = u32::try_from(self.optional_header.data_directories().len()).unwrap_or(0);
        let (magic, count) = match &mut self.optional_header {
            OptionalHeader::Pe32(header) => (
                (&mut header.magic, PE32_MAGIC),
                &mut header.number_of_rva_and_sizes,
            ),
            OptionalHeader::Pe32Plus(header) => (
                (&mut header.magic, PE32PLUS_MAGIC),
                &mut header.number_of_rva_and_sizes,
            ),
        };
        *magic.0 = magic.1;
        // The parser keeps at most the number of entries that the loader reads.
        *count = (*count).min(length);

        let directories = self.optional_header.data_directories_mut();
        for dir_type in [DataDirectoryType::Architecture, DataDirectoryType::Reserved] {
            if let Some(entry) = directories.get_mut(dir_type.as_index()) {
                *entry = DataDirectory::default();
            }
        }
        if let Some(entry) = directories.get_mut(DataDirectoryType::GlobalPtr.as_index()) {
            entry.size = 0;
        }
    }

    /// Return a copy of this image with a new file layout, if the copy keeps the sections of
    /// `original`. Otherwise return the reason.
    fn normalized_layout(&self, original: &Self) -> Result<Self, NormalizeKept> {
        let section_alignment = self.optional_header.section_alignment();
        if section_alignment.is_power_of_two() && section_alignment < PAGE_SIZE {
            return Err(NormalizeKept::LowAlignment);
        }
        let (file_alignment, section_alignment) =
            self.normal_alignments().ok_or(NormalizeKept::Alignment)?;

        let mut candidate = self.clone();
        match &mut candidate.optional_header {
            OptionalHeader::Pe32(header) => {
                header.file_alignment = file_alignment;
                header.section_alignment = section_alignment;
            }
            OptionalHeader::Pe32Plus(header) => {
                header.file_alignment = file_alignment;
                header.section_alignment = section_alignment;
            }
        }
        // `PeHeaders::read_from` rejects a negative `e_lfanew`, so only a small value is left.
        if usize::try_from(candidate.dos_header.e_lfanew)
            .is_ok_and(|offset| offset < DosHeader::SIZE)
        {
            candidate.dos_header.e_lfanew = 0x40;
        }
        if let Err(error) = candidate.try_update_layout() {
            return Err(NormalizeKept::Layout(error.to_string()));
        }
        if !candidate.keeps_sections_of(original) {
            return Err(NormalizeKept::SectionAddresses);
        }
        Ok(candidate)
    }

    /// Return valid `(FileAlignment, SectionAlignment)` values that keep all section RVAs.
    ///
    /// The method keeps each valid value. It uses a page for an invalid `SectionAlignment`, and
    /// 0x200 for an invalid `FileAlignment`. The result is `None` if a section RVA is not a
    /// multiple of a new `SectionAlignment`.
    fn normal_alignments(&self) -> Option<(u32, u32)> {
        let file = self.optional_header.file_alignment();
        let section = self.optional_header.section_alignment();
        let section = if section.is_power_of_two() && section >= PAGE_SIZE {
            section
        } else if self
            .sections
            .iter()
            .all(|item| item.header.virtual_address.is_multiple_of(PAGE_SIZE))
        {
            PAGE_SIZE
        } else {
            return None;
        };
        let file = if file.is_power_of_two()
            && (NORMAL_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&file)
            && file <= section
        {
            file
        } else {
            NORMAL_FILE_ALIGNMENT
        };
        Some((file, section))
    }

    /// Return `true` if each section has the RVA, the virtual size, the characteristics and
    /// the data of the same section in `original`.
    fn keeps_sections_of(&self, original: &Self) -> bool {
        self.sections.len() == original.sections.len()
            && self
                .sections
                .iter()
                .zip(&original.sections)
                .all(|(section, old)| {
                    section.header.virtual_address == old.header.virtual_address
                        && section.header.characteristics == old.header.characteristics
                        && loader_virtual_size(&section.header) == loader_virtual_size(&old.header)
                        && section.data == old.data
                })
    }
}

/// Return the virtual size that the loader uses for a section: `VirtualSize`, or
/// `SizeOfRawData` if `VirtualSize` is 0.
fn loader_virtual_size(header: &crate::section::SectionHeader) -> u32 {
    if header.virtual_size == 0 {
        header.size_of_raw_data
    } else {
        header.virtual_size
    }
}

/// Return the changes from `old` to `new`, in header order.
pub(crate) fn normalize_changes(old: &PeImage, new: &PeImage) -> Vec<NormalizeChange> {
    let mut changes = Vec::new();
    if old.dos_header.e_lfanew != new.dos_header.e_lfanew {
        changes.push(NormalizeChange::NtHeadersOffset {
            old: old.dos_header.e_lfanew,
            new: new.dos_header.e_lfanew,
        });
    }
    let (old_size, new_size) = (
        old.coff_header.size_of_optional_header,
        new.coff_header.size_of_optional_header,
    );
    if old_size != new_size {
        changes.push(NormalizeChange::SizeOfOptionalHeader {
            old: old_size,
            new: new_size,
        });
    }

    let (before, after) = (
        Fields::of(&old.optional_header),
        Fields::of(&new.optional_header),
    );
    if before.magic != after.magic {
        changes.push(NormalizeChange::Magic {
            old: before.magic,
            new: after.magic,
        });
    }
    if before.code_and_data != after.code_and_data {
        changes.push(NormalizeChange::CodeAndDataFields);
    }
    let fields: [(u32, u32, FieldChange); 6] = [
        (
            before.section_alignment,
            after.section_alignment,
            |old, new| NormalizeChange::SectionAlignment { old, new },
        ),
        (before.file_alignment, after.file_alignment, |old, new| {
            NormalizeChange::FileAlignment { old, new }
        }),
        (before.size_of_image, after.size_of_image, |old, new| {
            NormalizeChange::SizeOfImage { old, new }
        }),
        (before.size_of_headers, after.size_of_headers, |old, new| {
            NormalizeChange::SizeOfHeaders { old, new }
        }),
        (before.check_sum, after.check_sum, |old, new| {
            NormalizeChange::Checksum { old, new }
        }),
        (
            before.number_of_rva_and_sizes,
            after.number_of_rva_and_sizes,
            |old, new| NormalizeChange::NumberOfRvaAndSizes { old, new },
        ),
    ];
    for (old_value, new_value, change) in fields {
        if old_value != new_value {
            changes.push(change(old_value, new_value));
        }
    }

    let old_directories = old.optional_header.data_directories();
    for (index, directory) in new.optional_header.data_directories().iter().enumerate() {
        if old_directories.get(index) != Some(directory)
            && let Some(dir_type) = DataDirectoryType::from_index(index)
        {
            changes.push(NormalizeChange::DataDirectory(dir_type));
        }
    }
    for (index, (section, old_section)) in new.sections.iter().zip(&old.sections).enumerate() {
        if section.header != old_section.header {
            changes.push(NormalizeChange::Section { index });
        }
    }
    if !old.header_tail.bytes.is_empty() && new.header_tail.bytes.is_empty() {
        changes.push(NormalizeChange::HeaderTail);
    }
    changes
}

/// A constructor of a [`NormalizeChange`] that holds an old and a new `u32` value.
type FieldChange = fn(u32, u32) -> NormalizeChange;

/// The optional-header fields that normalization can change.
struct Fields {
    magic: u16,
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    number_of_rva_and_sizes: u32,
    code_and_data: [u32; 5],
}

impl Fields {
    fn of(header: &OptionalHeader) -> Self {
        match header {
            OptionalHeader::Pe32(h) => Self {
                magic: h.magic,
                section_alignment: h.section_alignment,
                file_alignment: h.file_alignment,
                size_of_image: h.size_of_image,
                size_of_headers: h.size_of_headers,
                check_sum: h.check_sum,
                number_of_rva_and_sizes: h.number_of_rva_and_sizes,
                code_and_data: [
                    h.size_of_code,
                    h.size_of_initialized_data,
                    h.size_of_uninitialized_data,
                    h.base_of_code,
                    h.base_of_data,
                ],
            },
            OptionalHeader::Pe32Plus(h) => Self {
                magic: h.magic,
                section_alignment: h.section_alignment,
                file_alignment: h.file_alignment,
                size_of_image: h.size_of_image,
                size_of_headers: h.size_of_headers,
                check_sum: h.check_sum,
                number_of_rva_and_sizes: h.number_of_rva_and_sizes,
                code_and_data: [
                    h.size_of_code,
                    h.size_of_initialized_data,
                    h.size_of_uninitialized_data,
                    h.base_of_code,
                    0,
                ],
            },
        }
    }
}

/// Return the `CheckSum` field of an optional header.
pub(crate) fn check_sum(header: &OptionalHeader) -> u32 {
    match header {
        OptionalHeader::Pe32(h) => h.check_sum,
        OptionalHeader::Pe32Plus(h) => h.check_sum,
    }
}

/// Set the `CheckSum` field of an optional header.
pub(crate) fn set_check_sum(header: &mut OptionalHeader, value: u32) {
    match header {
        OptionalHeader::Pe32(h) => h.check_sum = value,
        OptionalHeader::Pe32Plus(h) => h.check_sum = value,
    }
}
