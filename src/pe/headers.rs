use super::{PeHeaders, SourceLayout};
use crate::coff::{CoffHeader, verify_pe_signature};
use crate::dos::DosHeader;
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::raw::HeaderOffsets;
use crate::reader::{ReadAt, SliceReader, ZeroPadded};
use crate::section::SectionHeader;
use crate::{Error, Result};

#[cfg(feature = "std")]
use crate::reader::FileReader;
#[cfg(feature = "std")]
use std::path::Path;

impl PeHeaders {
    /// Read PE headers from any [`ReadAt`] implementation.
    ///
    /// `base_offset` is the source offset of the DOS header (`IMAGE_DOS_HEADER`).
    ///
    /// The method reads malformed headers as far as it can, so that tools can examine them:
    ///
    /// - The headers can end after the end of the source. If the source reports its size, the
    ///   method reads the missing bytes as zeros, as the data-file loader of Windows does.
    /// - An unknown `Magic` in the optional header does not stop the parse. The method then uses
    ///   the PE32+ layout for a 64-bit `Machine`, and the PE32 layout for all other values.
    ///
    /// [`PeImage::validate`](crate::PeImage::validate) reports such problems.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    ///
    /// - The DOS header, PE signature, COFF header, optional header, or section table cannot
    ///   be read or is invalid.
    /// - `e_lfanew` is negative or smaller than 2, so that the PE signature overlaps `e_magic`.
    ///   A value from 2 to 63 is valid: then the NT headers overlap the DOS header.
    /// - The calculation of a header offset overflows.
    ///
    /// Each read error names the structure and its file offset in its context.
    #[must_use = "parsing returns PE headers that should be used"]
    pub fn read_from<R: ReadAt>(reader: &R, base_offset: u64) -> Result<Self> {
        Self::read_headers(&ZeroPadded::new(reader), base_offset)
    }

    /// Read PE headers from any [`ReadAt`] implementation, and reject headers that end after
    /// the end of the source.
    ///
    /// This method does not read missing bytes as zeros. Use it to follow a tool that reads
    /// the headers directly from the file buffer, for example `msdelta.dll`. All other rules
    /// of [`Self::read_from`] apply.
    ///
    /// # Errors
    ///
    /// Returns a read error if a header structure ends after the end of the source. Also
    /// returns an error for each condition that [`Self::read_from`] lists.
    #[must_use = "parsing returns PE headers that should be used"]
    pub fn read_from_strict<R: ReadAt>(reader: &R, base_offset: u64) -> Result<Self> {
        Self::read_headers(reader, base_offset)
    }

    /// Read the headers from `reader`. The caller selects how the reader handles its end.
    fn read_headers<R: ReadAt>(reader: &R, base_offset: u64) -> Result<Self> {
        // Parse the DOS header.
        let dos_header = DosHeader::read_from(reader, base_offset).map_err(|error| {
            error
                .in_structure("IMAGE_DOS_HEADER")
                .at_offset(base_offset)
        })?;

        // Get the offset of the PE header.
        let relative_pe_offset = u64::try_from(dos_header.e_lfanew)
            .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
        if relative_pe_offset < DosHeader::MIN_PE_OFFSET as u64 {
            return Err(Error::invalid_section(format!(
                "e_lfanew {relative_pe_offset:#x} is smaller than {:#x}: the PE signature overlaps e_magic",
                DosHeader::MIN_PE_OFFSET
            )));
        }
        let pe_offset = base_offset
            .checked_add(relative_pe_offset)
            .ok_or_else(|| Error::invalid_section("PE header offset overflow"))?;

        // Check the PE signature.
        verify_pe_signature(reader, pe_offset)
            .map_err(|error| error.in_structure("PE signature").at_offset(pe_offset))?;

        // Parse the COFF header. It starts 4 bytes after the PE signature.
        let coff_offset = pe_offset
            .checked_add(4)
            .ok_or_else(|| Error::invalid_section("COFF header offset overflow"))?;
        let coff_header = CoffHeader::read_from(reader, coff_offset).map_err(|error| {
            error
                .in_structure("IMAGE_FILE_HEADER")
                .at_offset(coff_offset)
        })?;

        // Parse the optional header. As the loader does, read all of its fields, also if
        // `SizeOfOptionalHeader` is smaller. Then the section table overlaps the optional header.
        let optional_offset = coff_offset
            .checked_add(CoffHeader::SIZE as u64)
            .ok_or_else(|| Error::invalid_section("optional-header offset overflow"))?;
        let optional_header =
            OptionalHeader::read_for_machine(reader, optional_offset, coff_header.machine)
                .map_err(|error| {
                    error
                        .in_structure("optional header")
                        .at_offset(optional_offset)
                })?;

        // Parse the section headers. `SizeOfOptionalHeader` is the distance from the start of the
        // optional header to the section table.
        let sections_offset = optional_offset
            .checked_add(u64::from(coff_header.size_of_optional_header))
            .ok_or_else(|| Error::invalid_section("section-table offset overflow"))?;
        let section_headers = SectionHeader::read_sections(
            reader,
            sections_offset,
            usize::from(coff_header.number_of_sections),
        )
        .map_err(|error| {
            error
                .in_structure("section table")
                .at_offset(sections_offset)
        })?;

        Ok(Self {
            dos_header,
            coff_header,
            optional_header,
            section_headers,
            pe_offset,
        })
    }

    /// Read the headers from a file on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or read. Also returns an error for each
    /// condition that [`Self::read_from`] lists.
    #[cfg(feature = "std")]
    #[must_use = "loading returns PE headers that should be used"]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = FileReader::open(path)?;
        Self::read_from(&reader, 0)
    }

    /// Read the headers from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error for each condition that [`Self::read_from`] lists.
    #[must_use = "parsing returns PE headers that should be used"]
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from(&reader, 0)
    }

    /// Read the headers from a byte slice, and reject headers that end after the slice.
    ///
    /// # Errors
    ///
    /// Returns an error for each condition that [`Self::read_from_strict`] lists.
    #[must_use = "parsing returns PE headers that should be used"]
    pub fn from_slice_strict(data: &[u8]) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from_strict(&reader, 0)
    }

    /// Return the source offsets of the header fields that a tool rewrites in place.
    ///
    /// The offsets use the same base as [`Self::pe_offset`]. The optional header layout
    /// (PE32 or PE32+) of [`Self::optional_header`] selects the field offsets.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) error
    /// if an offset does not fit in `usize`.
    pub fn header_offsets(&self) -> Result<HeaderOffsets> {
        let too_large = || Error::offset_out_of_bounds(usize::MAX, 0);
        let nt_headers = usize::try_from(self.pe_offset).map_err(|_| too_large())?;
        HeaderOffsets::new(
            nt_headers,
            self.coff_header.size_of_optional_header,
            self.is_64bit(),
        )
        .ok_or_else(too_large)
    }

    /// Return `true` if this is a 64-bit (PE32+) image.
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_pe32plus()
    }

    /// Return `true` if this image is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Return the section header (`IMAGE_SECTION_HEADER`) with the given name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|s| s.name_str() == name)
    }

    /// Convert an RVA to a source offset for the given layout.
    ///
    /// The offset is relative to the start of the image. If you called [`Self::read_from`]
    /// with a nonzero `base_offset`, add that base to the offset before you read from the
    /// original source. In the file layout, the offset is where the loader reads the byte: the
    /// loader rounds `PointerToRawData` down to a multiple of 0x200 if `FileAlignment` is 0x200 or
    /// more.
    #[must_use]
    pub fn rva_to_source_offset(&self, rva: u32, layout: SourceLayout) -> Option<u32> {
        if rva >= self.optional_header.size_of_image() {
            return None;
        }

        match layout {
            SourceLayout::Mapped => Some(rva),
            SourceLayout::File => {
                if rva < self.optional_header.size_of_headers() {
                    return Some(rva);
                }
                let file_alignment = self.optional_header.file_alignment();
                self.section_headers.iter().find_map(|section| {
                    crate::layout::section_rva_to_file_offset(section, rva, file_alignment)
                })
            }
        }
    }

    /// Convert an RVA to a file offset in the raw file.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.rva_to_source_offset(rva, SourceLayout::File)
    }

    /// Return the RVA of the entry point.
    #[must_use]
    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point()
    }

    /// Return the preferred image base (a VA) from the optional header.
    #[must_use]
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeImage;

    #[test]
    fn test_parse_invalid_dos_signature() {
        let data = vec![0u8; 256];
        let result = PeImage::parse(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
        ));
    }

    #[test]
    fn test_parse_dos_signature_only() {
        // The missing DOS header bytes read as zeros, so `e_lfanew` is 0 and no PE header follows.
        let data = vec![0x4D, 0x5A];
        let result = PeImage::parse(&data);
        assert!(matches!(
            &result,
            Err(e) if matches!(e.kind, crate::error::ErrorKind::InvalidSection(_))
        ));
    }

    #[test]
    fn test_headers_parse_invalid() {
        let data = vec![0u8; 256];
        let result = PeHeaders::from_slice(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
        ));
    }
}
