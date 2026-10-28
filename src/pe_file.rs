//! Lossless raw-file container for PE images, overlays, and certificates.

use core::ops::{Deref, DerefMut, Range};

use crate::data_dir::{DataDirectory, DataDirectoryType};
use crate::prelude::*;
use crate::reader::ReadAt;
use crate::security::{SecurityBuilder, SecurityDirectory};
use crate::{Error, PeImage, Result};

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::path::Path;

/// A raw PE file together with the bytes outside the mapped image.
///
/// [`PeImage`] owns the normalized headers and sections. Thus it can hold raw-file input or
/// loader-mapped input. `PeFile` adds the raw-only state that a mapped image cannot have: the
/// file overlay and the attribute certificate table.
///
/// Use this type if you must keep the overlay byte for byte or keep Authenticode certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeFile {
    /// Parsed executable image.
    pub image: PeImage,
    overlay: Vec<u8>,
    certificate_range: Option<Range<usize>>,
    /// The Security directory entry of the source, if it does not give a valid certificate table.
    /// The loader does not use this entry, so the build keeps it as it is.
    invalid_security: Option<DataDirectory>,
    source_layout: RawLayoutFingerprint,
    /// The length of the source, if its headers or raw section data go past its end. The build
    /// of the source layout then keeps this length.
    source_end: Option<usize>,
    preserved_regions: Vec<PreservedRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawLayoutFingerprint {
    pe_offset: usize,
    optional_header_size: usize,
    size_of_headers: usize,
    sections: Vec<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreservedRegion {
    range: Range<usize>,
    data: Vec<u8>,
}

impl PeFile {
    /// Wrap a normalized image as a raw file with no overlay.
    ///
    /// # Errors
    ///
    /// Returns an error if the layout update fails, or if the new raw layout cannot be
    /// represented.
    pub fn new(mut image: PeImage) -> Result<Self> {
        image.try_update_layout()?;
        let source_layout = RawLayoutFingerprint::from_image(&image)?;
        Ok(Self {
            image,
            overlay: Vec::new(),
            certificate_range: None,
            invalid_security: None,
            source_layout,
            source_end: None,
            preserved_regions: Vec::new(),
        })
    }

    /// Borrow the normalized executable image.
    #[must_use]
    pub const fn image(&self) -> &PeImage {
        &self.image
    }

    /// Borrow the normalized executable image for editing.
    pub fn image_mut(&mut self) -> &mut PeImage {
        &mut self.image
    }

    /// Parse a complete raw PE file.
    ///
    /// The `VirtualAddress` field of the Security directory holds a file offset, not an RVA.
    ///
    /// The method accepts these layouts, as the loader does:
    ///
    /// - The headers or the raw data of a section go past the end of the file. The loader maps
    ///   zeros for the missing bytes. The build keeps the layout and the length of the file.
    /// - A `PointerToRawData` is not a multiple of 0x200. The loader rounds it down, and the
    ///   build writes the section data at the rounded offset.
    ///
    /// The loader does not use the Security directory. If it does not give a valid certificate
    /// table in the overlay, the method ignores it. The build keeps the entry as it is.
    ///
    /// # Errors
    ///
    /// Returns an error if [`PeImage::parse`] fails.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let image = PeImage::parse(data)?;
        let declared_end = raw_image_end(&image)?;
        let image_end = declared_end.min(data.len());
        let source_layout = RawLayoutFingerprint::from_image(&image)?;
        let certificate_range = certificate_range(&image, data, image_end);
        let invalid_security = image
            .data_directory(DataDirectoryType::Security)
            .copied()
            .filter(|directory| certificate_range.is_none() && directory.is_present());
        let preserved_regions = collect_preserved_regions(data, &image, image_end)?;

        Ok(Self {
            image,
            overlay: data[image_end..].to_vec(),
            certificate_range,
            invalid_security,
            source_layout,
            source_end: (declared_end > data.len()).then_some(data.len()),
            preserved_regions,
        })
    }

    /// Read and parse a complete raw PE file from a [`ReadAt`].
    ///
    /// `base_offset` is the offset in the source where the PE file starts. The method reads from
    /// `base_offset` to the end of the source.
    ///
    /// The reader must report its size, because no header field gives the end of an overlay.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The reader does not report its size.
    /// - `base_offset` is past the end of the source.
    /// - A read fails.
    /// - Any condition listed on [`Self::parse`] occurs.
    pub fn read_from<R: ReadAt>(reader: &R, base_offset: u64) -> Result<Self> {
        let source_size = reader
            .size()
            .ok_or_else(|| Error::generic("PeFile requires a ReadAt source with a known size"))?;
        let length = source_size
            .checked_sub(base_offset)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| Error::offset_out_of_bounds(usize::MAX, usize::MAX))?;
        let bytes = reader.read_bytes_at(base_offset, length)?;
        Self::parse(&bytes)
    }

    /// Load a complete raw PE file from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the read of the file fails. Also returns an error for any condition
    /// listed on [`Self::parse`].
    #[cfg(feature = "std")]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::parse(&std::fs::read(path)?)
    }

    /// Read a complete raw PE file from a sequential `nostdio` stream.
    ///
    /// # Errors
    ///
    /// Returns an error if a read from the stream fails. Also returns an error for any condition
    /// listed on [`Self::parse`].
    pub fn from_stream<R: nostdio::Read>(stream: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        Self::parse(&data)
    }

    /// Return all bytes after the headers and the raw section data.
    #[must_use]
    pub fn overlay(&self) -> &[u8] {
        &self.overlay
    }

    /// Return the overlay for in-place byte edits.
    ///
    /// The slice has a fixed length, so a stored certificate location stays valid. To replace the
    /// complete overlay, use [`Self::set_overlay`].
    pub fn overlay_mut(&mut self) -> &mut [u8] {
        &mut self.overlay
    }

    /// Replace the complete overlay and clear the Security directory.
    ///
    /// To put a new certificate table in the new bytes, call [`Self::set_security`] after this
    /// method.
    pub fn set_overlay(&mut self, overlay: Vec<u8>) {
        self.overlay = overlay;
        self.certificate_range = None;
        self.image.clear_security();
    }

    /// Return `true` if the next build can still safely restore the raw gaps in the headers and
    /// sections of the parsed source.
    #[must_use]
    pub fn preserves_source_gaps(&self) -> bool {
        RawLayoutFingerprint::from_image(&self.image)
            .is_ok_and(|layout| layout == self.source_layout)
    }

    /// Consume the container and return the normalized executable image.
    #[must_use]
    pub fn into_image(self) -> PeImage {
        self.image
    }

    /// Return the range of the certificate table, as offsets from the start of the overlay.
    #[must_use]
    pub fn certificate_overlay_range(&self) -> Option<Range<usize>> {
        self.certificate_range.clone()
    }

    /// Parse the attribute certificate table (the `WIN_CERTIFICATE` entries).
    ///
    /// # Errors
    ///
    /// Returns an error if the stored certificate range exceeds the overlay, or if the
    /// `WIN_CERTIFICATE` entries are malformed.
    pub fn security(&self) -> Result<Option<SecurityDirectory>> {
        let Some(range) = &self.certificate_range else {
            return Ok(None);
        };
        let data = self.overlay.get(range.clone()).ok_or_else(|| {
            Error::invalid_data_directory("stored certificate range exceeds the overlay")
        })?;
        Ok(Some(SecurityDirectory::parse(data)?))
    }

    /// Return the raw bytes of a standard data directory.
    ///
    /// # Errors
    ///
    /// For the Security directory, returns an error if the stored certificate range exceeds the
    /// overlay. For other directories, returns an error for any condition listed on
    /// [`PeImage::directory_data`].
    pub fn directory_data(&self, dir_type: DataDirectoryType) -> Result<Option<Vec<u8>>> {
        if dir_type != DataDirectoryType::Security {
            return self.image.directory_data(dir_type);
        }
        let Some(range) = &self.certificate_range else {
            return Ok(None);
        };
        self.overlay
            .get(range.clone())
            .map(|bytes| Some(bytes.to_vec()))
            .ok_or_else(|| Error::invalid_data_directory("certificate range exceeds the overlay"))
    }

    /// Parse the debug entries from the raw file.
    ///
    /// The result includes payloads that only `PointerToRawData` (a file offset) can reach. These
    /// payloads are not in a loader-mapped image.
    ///
    /// # Errors
    ///
    /// Returns an error if the build or the new parse of the raw file fails. Also returns an
    /// error if the debug directory or its payloads are unreadable or malformed.
    pub fn debug_info(&self) -> Result<Option<crate::debug::DebugInfo>> {
        let raw = self.try_build()?;
        let image = PeImage::parse(&raw)?;
        let Some(directory) = image
            .data_directory(DataDirectoryType::Debug)
            .copied()
            .filter(|directory| directory.is_present())
        else {
            return Ok(None);
        };
        let read_rva = |rva: u32, size: usize| image.read_rva(rva, size);
        let read_file = |offset: u32, size: usize| {
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(size)?;
            raw.get(start..end).map(<[u8]>::to_vec)
        };
        crate::debug::DebugInfo::parse_with_file(
            directory.virtual_address,
            directory.size,
            read_rva,
            read_file,
        )
        .map(Some)
    }

    /// Replace or add the attribute certificate table, and keep the other overlay bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The certificate table cannot be encoded.
    /// - The stored certificate range exceeds the overlay.
    /// - The aligned overlay size overflows.
    pub fn set_security(&mut self, directory: &SecurityDirectory) -> Result<()> {
        if directory.certificates.is_empty() {
            self.clear_security();
            return Ok(());
        }

        let certificate_data = SecurityBuilder::try_build(directory)?;
        let range = if let Some(old_range) = self.certificate_range.take() {
            if old_range.end > self.overlay.len() || old_range.start > old_range.end {
                return Err(Error::invalid_data_directory(
                    "stored certificate range exceeds the overlay",
                ));
            }
            let start = old_range.start;
            let end = start
                .checked_add(certificate_data.len())
                .ok_or_else(|| Error::invalid_data_directory("overlay size overflow"))?;
            self.overlay
                .splice(old_range, certificate_data.iter().copied());
            start..end
        } else {
            let start = align_up_usize(self.overlay.len(), 8)
                .ok_or_else(|| Error::invalid_data_directory("overlay size overflow"))?;
            self.overlay.resize(start, 0);
            self.overlay.extend_from_slice(&certificate_data);
            start..self.overlay.len()
        };

        self.certificate_range = Some(range);
        Ok(())
    }

    /// Remove the certificate table and its bytes, and keep the rest of the overlay.
    pub fn clear_security(&mut self) {
        if let Some(range) = self.certificate_range.take()
            && range.start <= range.end
            && range.end <= self.overlay.len()
        {
            self.overlay.drain(range);
        }
        self.image.clear_security();
    }

    /// Clear the Security directory entry of `pe`, unless it is the invalid entry of the source.
    fn clear_security_entry(&self, pe: &mut PeImage) {
        if pe.data_directory(DataDirectoryType::Security).copied() != self.invalid_security {
            pe.clear_security();
        }
    }

    /// Build a raw PE file with its overlay and certificate table.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The size or the file offset of the certificate table does not fit in a `u32`.
    /// - The stored certificate range exceeds the overlay.
    /// - The file size overflows.
    /// - The build of the image fails (see [`PeImage::try_build`]).
    /// - The overlay or the certificate table is not empty, but the build keeps a layout whose
    ///   raw data goes past the end of the output. Then the appended bytes would be section data.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let mut pe = self.image.clone();
        let certificate_size = self
            .certificate_range
            .as_ref()
            .map(|range| {
                u32::try_from(range.len()).map_err(|_| {
                    Error::invalid_data_directory("certificate table size exceeds u32")
                })
            })
            .transpose()?;
        if let Some(size) = certificate_size {
            // Reserve the entry before the layout update. The source can have fewer than the
            // five directory slots that Security needs.
            pe.set_data_directory(DataDirectoryType::Security, 1, size);
        } else {
            self.clear_security_entry(&mut pe);
        }
        // A layout whose raw data goes past the end of the source can keep the source length
        // only without bytes after it. Otherwise make a new layout.
        let appends_data = !self.overlay.is_empty() || self.certificate_range.is_some();
        let keeps_source_end = self.source_end.is_none() || !appends_data;
        let preserved_pass =
            if keeps_source_end && RawLayoutFingerprint::from_image(&pe)? == self.source_layout {
                pe.try_build_current_layout(self.source_end)?
            } else {
                None
            };
        let preserve_layout = preserved_pass.is_some();
        let first_pass = if let Some(bytes) = preserved_pass {
            bytes
        } else if pe.try_update_layout().is_ok() {
            pe.try_build_updated_layout()?
        } else {
            // No new layout can use the values of the image. `try_build` then keeps the current
            // layout, if it holds the data.
            pe.try_build()?
        };
        let base_size = first_pass.len();
        if appends_data && base_size < raw_image_end(&pe)? {
            return Err(Error::invalid_section(
                "the raw section data goes past the end of the image, so an overlay or a certificate table cannot follow it",
            ));
        }

        let prefix_padding = if let Some(range) = &self.certificate_range {
            if range.start > range.end || range.end > self.overlay.len() {
                return Err(Error::invalid_data_directory(
                    "stored certificate range exceeds the overlay",
                ));
            }
            let certificate_position = base_size
                .checked_add(range.start)
                .ok_or_else(|| Error::invalid_data_directory("certificate offset overflow"))?;
            padding_for(certificate_position, 8)
        } else {
            0
        };

        if let Some(range) = &self.certificate_range {
            let certificate_offset = base_size
                .checked_add(prefix_padding)
                .and_then(|offset| offset.checked_add(range.start))
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or_else(|| Error::invalid_data_directory("certificate offset exceeds u32"))?;
            let certificate_size = certificate_size.ok_or_else(|| {
                Error::invalid_data_directory("certificate range is missing its encoded size")
            })?;
            pe.set_data_directory(
                DataDirectoryType::Security,
                certificate_offset,
                certificate_size,
            );
        } else {
            self.clear_security_entry(&mut pe);
        }

        let mut output = if preserve_layout {
            pe.try_build_current_layout(self.source_end)?
                .ok_or_else(|| {
                    Error::invalid_section(
                        "current raw layout cannot hold the headers and the section data",
                    )
                })?
        } else {
            pe.try_build()?
        };
        if preserve_layout {
            restore_preserved_regions(&mut output, &self.preserved_regions)?;
        }
        output.resize(
            output
                .len()
                .checked_add(prefix_padding)
                .ok_or_else(|| Error::invalid_data_directory("file size overflow"))?,
            0,
        );
        output.extend_from_slice(&self.overlay);
        Ok(output)
    }

    /// Build a raw PE file, or panic if its hand-built state is not valid.
    ///
    /// For untrusted state, use [`Self::try_build`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] returns an error.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("PeFile build failed: use PeFile::try_build() to handle invalid structures")
    }

    /// Write the complete raw PE file to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails, or if the creation of the file or the write
    /// fails.
    #[cfg(feature = "std")]
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.write_to(&mut File::create(path)?)
    }

    /// Serialize the complete raw file to a `nostdio` stream.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::try_build`] fails or the stream write fails.
    pub fn write_to<W: nostdio::Write>(&self, stream: &mut W) -> Result<()> {
        stream.write_all(&self.try_build()?)?;
        Ok(())
    }
}

impl TryFrom<PeImage> for PeFile {
    type Error = Error;

    fn try_from(image: PeImage) -> Result<Self> {
        Self::new(image)
    }
}

impl Deref for PeFile {
    type Target = PeImage;

    fn deref(&self) -> &Self::Target {
        &self.image
    }
}

impl DerefMut for PeFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.image
    }
}

/// Return the file offset after the headers and the raw data of the sections.
///
/// The result can be past the end of the file. The raw data starts where the loader reads it.
fn raw_image_end(pe: &PeImage) -> Result<usize> {
    let file_alignment = pe.optional_header.file_alignment();
    let mut image_end = u64::from(pe.optional_header.size_of_headers());
    for section in &pe.sections {
        let header = &section.header;
        if header.pointer_to_raw_data == 0 || header.size_of_raw_data == 0 {
            continue;
        }
        let start = crate::layout::loader_raw_offset(header.pointer_to_raw_data, file_alignment);
        image_end = image_end.max(u64::from(start) + u64::from(header.size_of_raw_data));
    }
    Ok(usize::try_from(image_end)
        .unwrap_or(usize::MAX)
        .max(nt_headers_end(pe)?))
}

/// Return the range of the certificate table, as offsets from the start of the overlay.
///
/// The result is `None` if the Security directory is absent, or if it does not give a valid
/// certificate table in the overlay: inside the file, after `image_end`, aligned to 8 bytes, and
/// with entries that parse.
fn certificate_range(pe: &PeImage, data: &[u8], image_end: usize) -> Option<Range<usize>> {
    let directory = pe
        .data_directory(DataDirectoryType::Security)
        .filter(|directory| directory.is_present())?;
    let start = directory.virtual_address as usize;
    let end = start.checked_add(directory.size as usize)?;
    let valid = directory.virtual_address != 0
        && directory.size != 0
        && start >= image_end
        && start.is_multiple_of(8)
        && data
            .get(start..end)
            .is_some_and(|table| SecurityDirectory::parse(table).is_ok());
    valid.then(|| (start - image_end)..(end - image_end))
}

/// Return the file offset of the end of the NT headers.
///
/// The loader reads the complete section table and optional header, also if they end after
/// `SizeOfHeaders`.
fn nt_headers_end(image: &PeImage) -> Result<usize> {
    image
        .nt_headers_end()
        .ok_or_else(|| Error::invalid_section("NT header offset overflow"))
}

impl RawLayoutFingerprint {
    fn from_image(image: &PeImage) -> Result<Self> {
        let pe_offset = usize::try_from(image.dos_header.e_lfanew)
            .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
        Ok(Self {
            pe_offset,
            optional_header_size: usize::from(image.coff_header.size_of_optional_header),
            size_of_headers: image.optional_header.size_of_headers() as usize,
            sections: image
                .sections
                .iter()
                .map(|section| {
                    (
                        section.header.pointer_to_raw_data,
                        section.header.size_of_raw_data,
                    )
                })
                .collect(),
        })
    }
}

fn collect_preserved_regions(
    data: &[u8],
    image: &PeImage,
    image_end: usize,
) -> Result<Vec<PreservedRegion>> {
    // The image keeps the header bytes after the section table and the padding before it, so
    // the gaps start after them.
    let headers_end = nt_headers_end(image)?;
    let header_data_end = image.header_data_end(headers_end).unwrap_or(headers_end);

    let mut regions = Vec::new();

    let file_alignment = image.optional_header.file_alignment();
    let mut occupied: Vec<Range<usize>> = image
        .sections
        .iter()
        .filter(|section| {
            section.header.pointer_to_raw_data != 0 && section.header.size_of_raw_data != 0
        })
        .map(|section| {
            // The section data starts where the loader reads it.
            let start = crate::layout::loader_raw_offset(
                section.header.pointer_to_raw_data,
                file_alignment,
            ) as usize;
            start..start.saturating_add(section.header.size_of_raw_data as usize)
        })
        .collect();
    occupied.sort_by_key(|range| range.start);

    let mut cursor = header_data_end.min(image_end);
    for range in occupied {
        if range.end <= cursor {
            continue;
        }
        if range.start > cursor {
            push_preserved_region(&mut regions, data, cursor..range.start.min(image_end))?;
        }
        cursor = cursor.max(range.end.min(image_end));
        if cursor >= image_end {
            break;
        }
    }
    if cursor < image_end {
        push_preserved_region(&mut regions, data, cursor..image_end)?;
    }
    Ok(regions)
}

fn push_preserved_region(
    regions: &mut Vec<PreservedRegion>,
    source: &[u8],
    range: Range<usize>,
) -> Result<()> {
    if range.start >= range.end {
        return Ok(());
    }
    let bytes = source
        .get(range.clone())
        .ok_or_else(|| Error::buffer_too_small(range.end, source.len()))?;
    regions.push(PreservedRegion {
        range,
        data: bytes.to_vec(),
    });
    Ok(())
}

fn restore_preserved_regions(output: &mut [u8], regions: &[PreservedRegion]) -> Result<()> {
    for region in regions {
        let target = output.get_mut(region.range.clone()).ok_or_else(|| {
            Error::invalid_section("preserved raw-file region exceeds rebuilt image")
        })?;
        if target.len() != region.data.len() {
            return Err(Error::invalid_section(
                "preserved raw-file region changed size",
            ));
        }
        target.copy_from_slice(&region.data);
    }
    Ok(())
}

fn align_up_usize(value: usize, alignment: usize) -> Option<usize> {
    let padding = padding_for(value, alignment);
    value.checked_add(padding)
}

fn padding_for(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return 0;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        0
    } else {
        alignment - remainder
    }
}
