use super::{HeaderTail, PeImage};
use crate::coff::{CoffHeader, PE_SIGNATURE};
use crate::dos::DosHeader;
use crate::layout;
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::section::SectionHeader;
use crate::{Error, Result};

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::path::Path;

impl PeImage {
    /// Build the PE file as a byte vector.
    ///
    /// This method does not change `self`. It computes the layout on a clone.
    ///
    /// For untrusted or hand-built structures, use [`Self::try_build`]. It returns an error for a
    /// structural problem and does not panic.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] returns an error.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("PE build failed: use PeImage::try_build() to handle invalid structures")
    }

    /// Build the PE file, or return an error for an invalid offset, size or header relationship.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The layout update fails.
    /// - `e_lfanew`, the DOS stub, the optional header or the raw ranges of the sections are not
    ///   consistent, or they overflow.
    /// - The allocation of the output buffer fails.
    ///
    /// The build rebases the `PointerToRawData` field of each debug directory entry that it can
    /// read. The loader does not use the debug directory, so a malformed one does not stop the
    /// build.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let mut pe = self.clone();
        pe.try_update_layout()?;
        pe.try_build_updated_layout()
    }

    /// Serialize the image after a call to [`Self::try_update_layout`].
    ///
    /// The method rebases the debug file offsets in `self`, and returns each error.
    pub(crate) fn try_build_updated_layout(&mut self) -> Result<Vec<u8>> {
        self.synchronize_file_offsets();
        let headers = self.build_headers()?;
        self.try_write_bytes(&headers, None)
    }

    /// Serialize the image with the current raw file offsets, and do not recompute the layout.
    ///
    /// [`crate::PeFile`] uses this method to keep intentional file gaps when the parsed layout
    /// does not change otherwise. The result is `None` if the current raw layout cannot hold the
    /// headers and the section data, or if the headers do not fit the current layout. Then the
    /// caller can make a new layout.
    ///
    /// `source_end` is the length of a source whose headers or raw section data go past its end.
    /// Then the output keeps that length, and does not hold the zero padding after it.
    pub(crate) fn try_build_current_layout(
        &self,
        source_end: Option<usize>,
    ) -> Result<Option<Vec<u8>>> {
        if !self.current_layout_can_hold() {
            return Ok(None);
        }
        let mut pe = self.clone();
        pe.synchronize_file_offsets();
        let Ok(headers) = pe.build_headers() else {
            return Ok(None);
        };
        let output = pe.try_write_bytes(&headers, source_end)?;
        Ok(pe.output_holds_data(&output, &headers).then_some(output))
    }

    /// Check the sizes of the current raw layout against the section data.
    ///
    /// File ranges can overlap here, and the header table can extend past `SizeOfHeaders`.
    /// [`Self::output_holds_data`] checks the overlapping bytes.
    fn current_layout_can_hold(&self) -> bool {
        self.sections.iter().all(|section| {
            let start = section.header.pointer_to_raw_data;
            let size = section.header.size_of_raw_data as usize;
            if size == 0 {
                return section.data.is_empty() || section.preserved_raw_size() == Some(0);
            }
            start != 0 && section.data.len() <= size
        })
    }

    /// Return `true` if `output` holds the headers and the data of each section at its file
    /// range.
    ///
    /// Packed files can declare headers and sections that share file bytes. Such a layout is
    /// correct only if the shared bytes agree. Otherwise one write replaces part of another.
    fn output_holds_data(&self, output: &[u8], headers: &[u8]) -> bool {
        let mut ranges = Vec::with_capacity(self.sections.len() + 1);
        ranges.push(0..headers.len());
        for section in &self.sections {
            let start = section.header.pointer_to_raw_data as usize;
            let size = section.header.size_of_raw_data as usize;
            if start != 0 && size != 0 {
                ranges.push(start..start.saturating_add(size));
            }
        }
        ranges.sort_unstable_by_key(|range| range.start);
        if ranges.windows(2).all(|pair| pair[0].end <= pair[1].start) {
            return true;
        }

        // Some ranges overlap. Compare each component with the bytes in the output.
        if output.get(..headers.len()) != Some(headers) {
            return false;
        }
        self.sections.iter().all(|section| {
            let start = section.header.pointer_to_raw_data as usize;
            let size = section.header.size_of_raw_data as usize;
            if start == 0 || size == 0 {
                return true;
            }
            // The output can end before the raw range, after the data of the section.
            let end = start.saturating_add(size).min(output.len());
            let written = &output[start.min(end)..end];
            let data_len = section.data.len().min(size);
            if data_len > written.len() {
                return false;
            }
            let (data, padding) = written.split_at(data_len);
            data == &section.data[..data_len] && padding.iter().all(|byte| *byte == 0)
        })
    }

    /// Make a loader-style memory image of this normalized image at its current runtime base.
    ///
    /// # Errors
    ///
    /// Returns an error for the same conditions as [`Self::to_mapped_image_at`].
    pub fn to_mapped_image(&self) -> Result<Vec<u8>> {
        self.to_mapped_image_at(self.runtime_image_base())
    }

    /// Make a loader-style memory image at `runtime_image_base`.
    ///
    /// `runtime_image_base` is the VA of the image in memory. If it is different from the current
    /// base of the bytes, the method applies the base relocation table.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The layout update or the header serialization fails.
    /// - A section extends past `SizeOfImage`.
    /// - The allocation of the image buffer fails.
    /// - A rebase is necessary, but the base relocation table is missing or malformed, or it
    ///   targets bytes outside the image.
    pub fn to_mapped_image_at(&self, runtime_image_base: u64) -> Result<Vec<u8>> {
        let mut pe = self.clone();
        pe.try_update_layout()?;

        // The loader maps the headers as they are in the file. If the layout update keeps the
        // section RVAs, map the headers of `self`: the update can change header fields that also
        // hold code or data, for example in an image with overlapping headers. The image then has
        // the larger `SizeOfImage`, and all the header bytes.
        let source_size = pe
            .optional_header
            .size_of_image()
            .max(self.optional_header.size_of_image());
        let keeps_source_headers = pe.has_section_rvas_of(self)
            && self
                .sections
                .iter()
                .all(|section| super::inspect::section_end(section) <= u64::from(source_size));
        let (source, image_size) = if keeps_source_headers {
            (self, source_size)
        } else {
            (&pe, pe.optional_header.size_of_image())
        };
        let mut mapped = try_zeroed_buffer(image_size as usize, "mapped image")?;
        let headers = source.build_headers()?;
        let header_limit = if keeps_source_headers {
            headers.len()
        } else {
            pe.optional_header.size_of_headers() as usize
        };
        let header_count = headers.len().min(header_limit).min(mapped.len());
        mapped[..header_count].copy_from_slice(&headers[..header_count]);

        for section in &pe.sections {
            let start = section.header.virtual_address as usize;
            let mapped_size = section
                .header
                .virtual_size
                .max(section.header.size_of_raw_data) as usize;
            let end = start
                .checked_add(mapped_size)
                .ok_or_else(|| Error::invalid_section("mapped section range overflow"))?;
            if end > mapped.len() {
                return Err(Error::invalid_section(format!(
                    "section '{}' exceeds SizeOfImage",
                    section.name()
                )));
            }
            let count = section.data.len().min(mapped_size);
            mapped[start..start + count].copy_from_slice(&section.data[..count]);
        }

        let current_base = pe.runtime_image_base();
        if runtime_image_base != current_base {
            let relocations = pe.relocations()?;
            if relocations.is_empty() {
                return Err(Error::invalid_data_directory(format!(
                    "cannot move image from {current_base:#x} to {runtime_image_base:#x} without base relocations"
                )));
            }
            let delta = i128::from(runtime_image_base) - i128::from(current_base);
            relocations.try_apply(&mut mapped, delta, pe.is_64bit())?;
        }

        Ok(mapped)
    }

    /// Return `true` if this image has the section RVAs of `other`.
    fn has_section_rvas_of(&self, other: &PeImage) -> bool {
        self.sections.len() == other.sections.len()
            && self
                .sections
                .iter()
                .zip(&other.sections)
                .all(|(section, other)| {
                    section.header.virtual_address == other.header.virtual_address
                })
    }

    /// Update the `PointerToRawData` field of each debug directory entry after a change to the
    /// section layout.
    ///
    /// The loader does not use the debug directory, so a malformed directory does not stop the
    /// build. The method rebases each complete entry that it can read and write, and keeps the
    /// other bytes.
    fn synchronize_file_offsets(&mut self) {
        use crate::data_dir::DataDirectoryType;
        use crate::debug::DebugDirectory;

        let Some(directory) = self
            .data_directory(DataDirectoryType::Debug)
            .copied()
            .filter(|dir| dir.is_present())
        else {
            return;
        };
        // Read all complete entries at once. The zero budget of `read_rva` limits the size.
        let count = directory.size as usize / DebugDirectory::SIZE;
        let Some(table) = self.read_rva(directory.virtual_address, count * DebugDirectory::SIZE)
        else {
            return;
        };
        let (entries, _) = table.as_chunks::<{ DebugDirectory::SIZE }>();
        for (index, bytes) in entries.iter().enumerate() {
            let Ok(entry) = DebugDirectory::parse(bytes) else {
                continue;
            };
            let Some(file_offset) = (entry.address_of_raw_data != 0)
                .then(|| self.rva_to_offset(entry.address_of_raw_data))
                .flatten()
            else {
                continue;
            };
            let Some(field_rva) = u32::try_from(index * DebugDirectory::SIZE + 24)
                .ok()
                .and_then(|relative| directory.virtual_address.checked_add(relative))
            else {
                continue;
            };
            // The field can be outside the section data, for example in the zero tail. Then the
            // write fails, and the entry keeps its value.
            let _ = self.write_at_rva(field_rva, &file_offset.to_le_bytes());
        }
    }

    /// Serialize the DOS header, the DOS stub, the NT headers and the header tail.
    ///
    /// The method writes the structures in file order. As the loader allows, they can overlap:
    ///
    /// - The NT headers can start inside the DOS header (`e_lfanew` from 4 to 63).
    /// - The optional header can be longer than `SizeOfOptionalHeader`, so that the section
    ///   table overlaps it.
    ///
    /// A later structure replaces the shared bytes of an earlier one. Then the method makes sure
    /// that the shared bytes still give `e_lfanew` and the optional header.
    pub(super) fn build_headers(&self) -> Result<Vec<u8>> {
        let written = self.write_header_structures()?;
        if !self.keeps_e_lfanew(&written.bytes) {
            return Err(Error::invalid_section(
                "the NT headers overlap the DOS header and change e_lfanew",
            ));
        }
        if written.table_overlaps_optional_header
            && OptionalHeader::parse(&written.bytes[written.optional_offset..])?
                != self.optional_header
        {
            return Err(Error::invalid_section(
                "the section table overlaps the optional header and changes it",
            ));
        }
        Ok(written.bytes)
    }

    /// Return `true` if the NT headers keep the value of `e_lfanew` in a DOS header that they
    /// overlap.
    pub(super) fn nt_headers_keep_e_lfanew(&self) -> bool {
        self.write_header_structures()
            .is_ok_and(|written| self.keeps_e_lfanew(&written.bytes))
    }

    /// Return `true` if the header `bytes` give the `e_lfanew` of this image.
    fn keeps_e_lfanew(&self, bytes: &[u8]) -> bool {
        DosHeader::parse(bytes).is_ok_and(|dos| dos.e_lfanew == self.dos_header.e_lfanew)
    }

    /// Write the header structures in file order, without the checks of [`Self::build_headers`].
    fn write_header_structures(&self) -> Result<WrittenHeaders> {
        let pe_offset = usize::try_from(self.dos_header.e_lfanew).map_err(|_| {
            Error::invalid_section("e_lfanew is negative and cannot locate a PE header")
        })?;
        if pe_offset < DosHeader::MIN_PE_OFFSET {
            return Err(Error::invalid_section(format!(
                "e_lfanew {pe_offset:#x} is smaller than {:#x}, the minimum of the loader",
                DosHeader::MIN_PE_OFFSET
            )));
        }

        let stub_end = DosHeader::SIZE
            .checked_add(self.dos_stub.len())
            .ok_or_else(|| Error::invalid_section("DOS stub size overflow"))?;
        if !self.dos_stub.is_empty() && stub_end > pe_offset {
            return Err(Error::invalid_section(format!(
                "DOS stub ends at {stub_end:#x}, after e_lfanew {pe_offset:#x}"
            )));
        }

        let coff_offset = pe_offset
            .checked_add(4)
            .ok_or_else(|| Error::invalid_section("COFF header offset overflow"))?;
        let optional_offset = coff_offset
            .checked_add(CoffHeader::SIZE)
            .ok_or_else(|| Error::invalid_section("optional-header offset overflow"))?;
        let optional_end = optional_offset
            .checked_add(self.optional_header.size())
            .ok_or_else(|| Error::invalid_section("optional-header size overflow"))?;
        let sections_offset = optional_offset
            .checked_add(usize::from(self.coff_header.size_of_optional_header))
            .ok_or_else(|| Error::invalid_section("section-table offset overflow"))?;
        let table_end = self
            .sections
            .len()
            .checked_mul(SectionHeader::SIZE)
            .and_then(|size| sections_offset.checked_add(size))
            .ok_or_else(|| Error::invalid_section("header size overflow"))?;
        let header_end = table_end.max(optional_end);

        // Keep the header tail inside `SizeOfHeaders`, so that it cannot overlap section data.
        let tail = self.header_tail_after(header_end).and_then(|tail| {
            let limit = self.optional_header.size_of_headers() as usize;
            let end = tail.end()?.min(limit);
            (end > tail.offset).then(|| (tail.offset, &tail.bytes[..end - tail.offset]))
        });
        let output_len = tail
            .map_or(header_end, |(offset, bytes)| offset + bytes.len())
            .max(DosHeader::SIZE);

        // Each range below ends at or before `output_len`, which is `output.len()`.
        let mut output = try_zeroed_buffer(output_len, "PE headers")?;
        self.dos_header.write(&mut output[..DosHeader::SIZE])?;
        output[DosHeader::SIZE..stub_end].copy_from_slice(&self.dos_stub);
        output[pe_offset..coff_offset].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        self.coff_header
            .write(&mut output[coff_offset..optional_offset])?;
        self.optional_header
            .write(&mut output[optional_offset..optional_end])?;

        let (section_table, _) =
            output[sections_offset..table_end].as_chunks_mut::<{ SectionHeader::SIZE }>();
        for (section, slot) in self.sections.iter().zip(section_table) {
            section.header.write(slot)?;
        }
        if let Some((offset, bytes)) = tail {
            output[offset..offset + bytes.len()].copy_from_slice(bytes);
        }

        Ok(WrittenHeaders {
            bytes: output,
            optional_offset,
            table_overlaps_optional_header: optional_end > sections_offset
                && !self.sections.is_empty(),
        })
    }

    /// Return the end of the NT headers: after the section table or after the optional header,
    /// whichever is later.
    pub(crate) fn nt_headers_end(&self) -> Option<usize> {
        layout::nt_headers_end(
            usize::try_from(self.dos_header.e_lfanew).ok()?,
            self.sections.len(),
            usize::from(self.coff_header.size_of_optional_header),
            self.optional_header.size(),
        )
    }

    /// Return the header tail if the header table ends at or before it.
    ///
    /// `table_end` is the end of the section table. If the header table grows into the tail,
    /// the header table replaces the tail.
    pub(super) fn header_tail_after(&self, table_end: usize) -> Option<&HeaderTail> {
        let tail = &self.header_tail;
        (!tail.bytes.is_empty() && tail.offset >= table_end).then_some(tail)
    }

    /// Return the end of the header data for a section table that ends at `table_end`.
    ///
    /// This is the end of the header tail, or `table_end` if no header tail follows the table.
    pub(super) fn header_data_end(&self, table_end: usize) -> Option<usize> {
        self.header_tail_after(table_end)
            .map_or(Some(table_end), HeaderTail::end)
    }

    /// Write the PE bytes with the serialized `headers`, and do not update the layout.
    ///
    /// Use this method after a call to `update_layout()` to prevent repeated work. For
    /// `source_end`, see [`Self::try_build_current_layout`].
    fn try_write_bytes(&self, headers: &[u8], source_end: Option<usize>) -> Result<Vec<u8>> {
        if usize::from(self.coff_header.number_of_sections) != self.sections.len() {
            return Err(Error::invalid_section(format!(
                "COFF declares {} sections, but {} section records are present",
                self.coff_header.number_of_sections,
                self.sections.len()
            )));
        }

        // Calculate the total file size. The loader ignores `PointerToRawData` if
        // `SizeOfRawData` is zero. For a source that ends early, only the section data counts:
        // the source has no bytes for the rest of the raw range.
        let mut file_size = source_end.unwrap_or(self.optional_header.size_of_headers() as usize);
        for section in &self.sections {
            let start = section.header.pointer_to_raw_data as usize;
            let size = section.header.size_of_raw_data as usize;
            let written = if source_end.is_some() {
                section.data.len().min(size)
            } else {
                size
            };
            if start == 0 || written == 0 {
                continue;
            }
            let end = start
                .checked_add(written)
                .ok_or_else(|| Error::invalid_section("section file range overflow"))?;
            file_size = file_size.max(end);
        }

        file_size = file_size.max(headers.len());
        let mut output = try_zeroed_buffer(file_size, "raw PE image")?;
        output[..headers.len()].copy_from_slice(headers);

        // Write the section data.
        for section in &self.sections {
            let start = section.header.pointer_to_raw_data as usize;
            let size = section.header.size_of_raw_data as usize;
            let data_len = section.data.len().min(size);
            if start > 0
                && size > 0
                && start
                    .checked_add(data_len)
                    .is_some_and(|end| end <= output.len())
            {
                output[start..start + data_len].copy_from_slice(&section.data[..data_len]);
                // The padding is already zero.
            } else if !section.data.is_empty() && section.preserved_raw_size() != Some(0) {
                return Err(Error::invalid_section(format!(
                    "section '{}' has data but no writable raw-file range",
                    section.name()
                )));
            }
        }

        // Header bytes past the end of a short source are zeros for the loader. Drop them, so
        // that the output keeps the length of the source.
        if let Some(end) = source_end
            && output
                .get(end..)
                .is_some_and(|tail| tail.iter().all(|byte| *byte == 0))
        {
            output.truncate(end);
        }
        Ok(output)
    }

    /// Write the PE file to disk.
    ///
    /// This method does not change `self`. It computes the layout on a clone.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails, or if the creation of the file or the write
    /// fails.
    #[cfg(feature = "std")]
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.write_to(&mut File::create(path)?)
    }

    /// Serialize this normalized image to a `nostdio` stream.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails or the stream write fails.
    pub fn write_to<W: nostdio::Write>(&self, stream: &mut W) -> Result<()> {
        stream.write_all(&self.try_build()?)?;
        Ok(())
    }
}

fn try_zeroed_buffer(size: usize, context: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Error::generic(format!("{context} is too large to allocate")))?;
    bytes.resize(size, 0);
    Ok(bytes)
}

/// The output of [`PeImage::write_header_structures`].
struct WrittenHeaders {
    /// The header bytes.
    bytes: Vec<u8>,
    /// The file offset of the optional header.
    optional_offset: usize,
    /// `true` if the section table overlaps the optional header.
    table_overlaps_optional_header: bool,
}
