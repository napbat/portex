//! Debug directory parsing and building.
//!
//! The debug directory holds debug information, for example the path of the PDB file.
//!
//! # Examples
//!
//! ## Reading debug information from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! if let Some(debug_info) = pe.debug_info()? {
//!     for dir in &debug_info.directories {
//!         println!("Debug type: {:?}", dir.get_type());
//!         println!("  Data RVA: {:#x}", dir.address_of_raw_data);
//!     }
//!     if let Some(codeview) = debug_info.codeview()? {
//!         println!("  PDB path: {}", codeview.pdb_path_lossy());
//!         println!("  GUID: {}", codeview.guid_string());
//!         println!("  Age: {}", codeview.age);
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Changing the PDB path
//!
//! [`DebugInfo::data`] holds the CodeView record. Write the changed record back with
//! [`DebugInfo::set_codeview`] before you call
//! [`PeImage::update_debug`](crate::PeImage::update_debug).
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//! if let Some(mut debug_info) = pe.debug_info()? {
//!     if let Some(mut codeview) = debug_info.codeview()? {
//!         codeview.pdb_path = b"C:\\symbols\\app.pdb".to_vec();
//!         debug_info.set_codeview(&codeview)?;
//!         pe.update_debug(&debug_info, None)?;
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

mod build;
mod codeview;

pub use build::DebugBuilder;
pub use codeview::{CV_SIGNATURE_NB10, CV_SIGNATURE_RSDS, CodeViewRsds};

use crate::prelude::*;
use crate::{Error, Result};

/// Debug types (`IMAGE_DEBUG_TYPE_*`).
///
/// A later release can add a variant for a value that [`Self::from_u32`] does not know now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum DebugType {
    /// The value 0 (`IMAGE_DEBUG_TYPE_UNKNOWN`). Tools ignore entries of this type.
    Unknown = 0,
    /// COFF debug information (`IMAGE_DEBUG_TYPE_COFF`).
    Coff = 1,
    /// Visual C++ CodeView debug information (`IMAGE_DEBUG_TYPE_CODEVIEW`).
    CodeView = 2,
    /// Frame pointer omission information (`IMAGE_DEBUG_TYPE_FPO`).
    Fpo = 3,
    /// Location of a DBG file (`IMAGE_DEBUG_TYPE_MISC`).
    Misc = 4,
    /// Copy of the `.pdata` section (`IMAGE_DEBUG_TYPE_EXCEPTION`).
    Exception = 5,
    /// Reserved (`IMAGE_DEBUG_TYPE_FIXUP`).
    Fixup = 6,
    /// Mapping from image RVAs to source-image RVAs (`IMAGE_DEBUG_TYPE_OMAP_TO_SRC`).
    OmapToSrc = 7,
    /// Mapping from source-image RVAs to image RVAs (`IMAGE_DEBUG_TYPE_OMAP_FROM_SRC`).
    OmapFromSrc = 8,
    /// Reserved for Borland (`IMAGE_DEBUG_TYPE_BORLAND`).
    Borland = 9,
    /// Reserved (`IMAGE_DEBUG_TYPE_RESERVED10`).
    Reserved10 = 10,
    /// Reserved (`IMAGE_DEBUG_TYPE_CLSID`).
    Clsid = 11,
    /// Visual C++ feature information (`IMAGE_DEBUG_TYPE_VC_FEATURE`).
    VcFeature = 12,
    /// Profile-guided optimization data (`IMAGE_DEBUG_TYPE_POGO`).
    Pogo = 13,
    /// Incremental link-time code generation data (`IMAGE_DEBUG_TYPE_ILTCG`).
    Iltcg = 14,
    /// Intel MPX data (`IMAGE_DEBUG_TYPE_MPX`).
    Mpx = 15,
    /// PE determinism or reproducibility (`IMAGE_DEBUG_TYPE_REPRO`).
    Repro = 16,
    /// A portable PDB file in the image (`IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB`).
    EmbeddedPortablePdb = 17,
    /// Sample profile-guided optimization data (`IMAGE_DEBUG_TYPE_SPGO`).
    Spgo = 18,
    /// A checksum of the PDB file (`IMAGE_DEBUG_TYPE_PDBCHECKSUM`).
    PdbChecksum = 19,
    /// Extended DLL characteristics bits (`IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS`).
    ExDllCharacteristics = 20,
    /// The location of a perf map file (`IMAGE_DEBUG_TYPE_PERFMAP`).
    PerfMap = 21,
}

impl DebugType {
    /// Map a raw `Type` value to a `DebugType`.
    ///
    /// Returns `None` for a value that this version of the crate does not know. The value 0
    /// maps to [`Self::Unknown`].
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Unknown,
            1 => Self::Coff,
            2 => Self::CodeView,
            3 => Self::Fpo,
            4 => Self::Misc,
            5 => Self::Exception,
            6 => Self::Fixup,
            7 => Self::OmapToSrc,
            8 => Self::OmapFromSrc,
            9 => Self::Borland,
            10 => Self::Reserved10,
            11 => Self::Clsid,
            12 => Self::VcFeature,
            13 => Self::Pogo,
            14 => Self::Iltcg,
            15 => Self::Mpx,
            16 => Self::Repro,
            17 => Self::EmbeddedPortablePdb,
            18 => Self::Spgo,
            19 => Self::PdbChecksum,
            20 => Self::ExDllCharacteristics,
            21 => Self::PerfMap,
            _ => return None,
        })
    }

    /// Return the raw `Type` value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// One entry of the debug directory (`IMAGE_DEBUG_DIRECTORY`, 28 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DebugDirectory {
    /// Reserved. This value must be zero.
    pub characteristics: u32,
    /// The time and date stamp.
    pub time_date_stamp: u32,
    /// The major version number.
    pub major_version: u16,
    /// The minor version number.
    pub minor_version: u16,
    /// The raw debug type value. [`Self::get_type`] maps it to a [`DebugType`].
    pub debug_type: u32,
    /// The size of the debug data in bytes.
    pub size_of_data: u32,
    /// The RVA of the debug data when the image is loaded.
    pub address_of_raw_data: u32,
    /// The file offset of the debug data.
    pub pointer_to_raw_data: u32,
}

impl DebugDirectory {
    /// Size of one `IMAGE_DEBUG_DIRECTORY` entry in bytes.
    pub const SIZE: usize = 28;
    /// [`Self::SIZE`] as a `u32`.
    const SIZE_U32: u32 = 28;

    /// Parse an entry from little-endian bytes.
    ///
    /// # Errors
    /// Returns an error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        Ok(Self {
            characteristics: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            debug_type: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_data: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            address_of_raw_data: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            pointer_to_raw_data: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
        })
    }

    /// Serialize to little-endian bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.debug_type.to_le_bytes());
        buf[16..20].copy_from_slice(&self.size_of_data.to_le_bytes());
        buf[20..24].copy_from_slice(&self.address_of_raw_data.to_le_bytes());
        buf[24..28].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        buf
    }

    /// Return the debug type as a [`DebugType`], or `None` for an unrecognized value.
    #[must_use]
    pub fn get_type(&self) -> Option<DebugType> {
        DebugType::from_u32(self.debug_type)
    }
}

/// Parsed debug information.
///
/// [`Self::data`] holds the payload of each entry, also the CodeView record. To read the
/// CodeView record, use [`Self::codeview`]. To change it, use [`Self::set_codeview`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DebugInfo {
    /// The entries of the debug directory.
    pub directories: Vec<DebugDirectory>,
    /// The raw payload of each directory entry, in the same order as
    /// [`Self::directories`]. `None` means that the entry has no readable payload.
    pub data: Vec<Option<Vec<u8>>>,
}

impl DebugInfo {
    /// The maximum number of payload bytes that one parse keeps, for all entries together.
    ///
    /// Many entries can point to the same bytes. This limit stops a small file from using a
    /// large quantity of memory. The parse does not read a payload that is larger than the
    /// rest of this budget. The entry of that payload stays in [`Self::directories`], and its
    /// payload is `None` in [`Self::data`].
    pub const MAX_PAYLOAD_BYTES: usize = 64 << 20;

    /// Parse the debug directory at RVA `debug_rva`.
    ///
    /// `debug_size` is the size of the directory in bytes. `read_at_rva` reads bytes at an RVA.
    ///
    /// The directory has `debug_size / 28` entries. The function ignores the bytes after the
    /// last complete entry, as the debug tools do.
    ///
    /// The function calls `read_at_rva` one time for the complete directory table. For this
    /// call, `len` can be as large as `debug_size`. The callback must return at least `len`
    /// bytes. Extra bytes are ignored.
    ///
    /// The function does not decode the payloads. A malformed payload, for example a bad
    /// CodeView record, does not cause an error here. An unreadable payload is `None` in
    /// [`Self::data`]. A payload that goes past [`Self::MAX_PAYLOAD_BYTES`] is also `None`.
    ///
    /// # Errors
    /// Returns an error if one of these conditions occurs:
    /// - The table cannot be read.
    /// - A payload length does not match.
    pub fn parse<F>(debug_rva: u32, debug_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_impl(debug_rva, debug_size, &read_at_rva, |directory| {
            if directory.size_of_data == 0 {
                Some(Vec::new())
            } else if directory.address_of_raw_data != 0 {
                read_at_rva(
                    directory.address_of_raw_data,
                    directory.size_of_data as usize,
                )
            } else {
                None
            }
        })
    }

    /// Parse the debug directory of a raw file at RVA `debug_rva`.
    ///
    /// If an entry has no mapped RVA, the function reads its payload at `PointerToRawData` (a
    /// file offset) through `read_at_file_offset`. The notes about `read_at_rva` and the
    /// payloads in [`Self::parse`] apply also to this function.
    ///
    /// # Errors
    /// Returns an error for the same conditions as [`Self::parse`].
    pub fn parse_with_file<F, G>(
        debug_rva: u32,
        debug_size: u32,
        read_at_rva: F,
        read_at_file_offset: G,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
        G: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_impl(debug_rva, debug_size, &read_at_rva, |directory| {
            if directory.size_of_data == 0 {
                Some(Vec::new())
            } else {
                (directory.address_of_raw_data != 0)
                    .then(|| {
                        read_at_rva(
                            directory.address_of_raw_data,
                            directory.size_of_data as usize,
                        )
                    })
                    .flatten()
                    .or_else(|| {
                        (directory.pointer_to_raw_data != 0)
                            .then(|| {
                                read_at_file_offset(
                                    directory.pointer_to_raw_data,
                                    directory.size_of_data as usize,
                                )
                            })
                            .flatten()
                    })
            }
        })
    }

    fn parse_impl<F, P>(
        debug_rva: u32,
        debug_size: u32,
        read_at_rva: &F,
        read_payload: P,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
        P: Fn(&DebugDirectory) -> Option<Vec<u8>>,
    {
        let table_size = debug_size / DebugDirectory::SIZE_U32 * DebugDirectory::SIZE_U32;
        let table = crate::parse_utils::read_record_table(
            read_at_rva,
            debug_rva,
            table_size,
            DebugDirectory::SIZE,
            "debug table",
        )?;

        let entries = table.as_chunks::<{ DebugDirectory::SIZE }>().0;
        let mut directories = Vec::with_capacity(entries.len());
        let mut raw_data = Vec::with_capacity(entries.len());
        let mut budget = Self::MAX_PAYLOAD_BYTES;
        for data in entries {
            let dir = DebugDirectory::parse(data)?;
            // Do not read a payload that goes past the budget. Keep its entry.
            let declared = dir.size_of_data as usize;
            let payload = if declared > budget {
                None
            } else {
                read_payload(&dir)
            };
            if let Some(payload) = &payload {
                if payload.len() != declared {
                    return Err(Error::invalid_data_directory(format!(
                        "debug payload has {} bytes but declares {}",
                        payload.len(),
                        dir.size_of_data
                    )));
                }
                budget -= declared;
            }
            directories.push(dir);
            raw_data.push(payload);
        }

        Ok(Self {
            directories,
            data: raw_data,
        })
    }

    /// Return the index of the first CodeView entry with an RSDS payload.
    fn rsds_index(&self) -> Option<usize> {
        self.directories
            .iter()
            .zip(&self.data)
            .position(|(directory, payload)| {
                directory.get_type() == Some(DebugType::CodeView)
                    && payload.as_deref().is_some_and(codeview::is_rsds)
            })
    }

    /// Decode the CodeView RSDS record of the first CodeView entry that holds one.
    ///
    /// The debug tools use the first record, so this function ignores the other records.
    /// The function does not decode NB10 records.
    ///
    /// The result is a copy. To change the record, call [`Self::set_codeview`] with the
    /// changed copy.
    ///
    /// # Errors
    /// Returns an error if the first RSDS record is malformed (see [`CodeViewRsds::parse`]).
    /// The other entries and payloads stay available.
    pub fn codeview(&self) -> Result<Option<CodeViewRsds>> {
        self.rsds_index()
            .and_then(|index| self.data.get(index)?.as_deref())
            .map(CodeViewRsds::parse)
            .transpose()
    }

    /// Return the PDB path of the first RSDS record.
    ///
    /// Returns `None` if there is no RSDS record, or if the record is malformed. The function
    /// replaces each invalid UTF-8 sequence with U+FFFD.
    #[must_use]
    pub fn pdb_path(&self) -> Option<Cow<'_, str>> {
        let payload = self.data.get(self.rsds_index()?)?.as_deref()?;
        let (_, _, path) = codeview::split_rsds(payload).ok()?;
        Some(String::from_utf8_lossy(path))
    }

    /// Write a CodeView RSDS record into the debug information.
    ///
    /// The function replaces the payload of the first CodeView entry that holds an RSDS
    /// record, and sets its `SizeOfData`. If no entry holds an RSDS record, the function adds
    /// a new CodeView entry. Call [`PeImage::update_debug`](crate::PeImage::update_debug) to
    /// write the result to the image.
    ///
    /// # Errors
    /// Returns an error if the record cannot be serialized, or if [`Self::data`] has more
    /// payloads than [`Self::directories`] has entries.
    pub fn set_codeview(&mut self, codeview: &CodeViewRsds) -> Result<()> {
        let bytes = codeview.try_to_bytes()?;
        let size = u32::try_from(bytes.len())
            .map_err(|_| Error::invalid_data_directory("CodeView payload exceeds u32"))?;
        if let Some(index) = self.rsds_index()
            && let (Some(directory), Some(payload)) =
                (self.directories.get_mut(index), self.data.get_mut(index))
        {
            directory.size_of_data = size;
            *payload = Some(bytes);
            return Ok(());
        }
        if self.data.len() > self.directories.len() {
            return Err(Error::invalid_data_directory(
                "debug payload list is longer than the directory list",
            ));
        }
        self.data.resize(self.directories.len(), None);
        self.directories.push(DebugDirectory {
            debug_type: DebugType::CodeView.as_u32(),
            size_of_data: size,
            ..DebugDirectory::default()
        });
        self.data.push(Some(bytes));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codeview(path: &[u8]) -> CodeViewRsds {
        CodeViewRsds {
            guid: [5; 16],
            age: 1,
            pdb_path: path.to_vec(),
        }
    }

    fn entry(debug_type: DebugType, size: usize, rva: u32) -> [u8; DebugDirectory::SIZE] {
        DebugDirectory {
            debug_type: debug_type.as_u32(),
            size_of_data: u32::try_from(size).unwrap(),
            address_of_raw_data: rva,
            ..DebugDirectory::default()
        }
        .to_bytes()
    }

    /// Return a reader of `bytes`, which start at RVA 0.
    fn reader(bytes: &[u8]) -> impl Fn(u32, usize) -> Option<Vec<u8>> + '_ {
        |rva, len| {
            let start = usize::try_from(rva).ok()?;
            bytes
                .get(start..start.checked_add(len)?)
                .map(<[u8]>::to_vec)
        }
    }

    #[test]
    fn test_debug_directory_size() {
        assert_eq!(DebugDirectory::SIZE, 28);
    }

    #[test]
    fn test_debug_directory_roundtrip() {
        let original = DebugDirectory {
            characteristics: 0,
            time_date_stamp: 0x1234_5678,
            major_version: 1,
            minor_version: 0,
            debug_type: DebugType::CodeView.as_u32(),
            size_of_data: 100,
            address_of_raw_data: 0x1000,
            pointer_to_raw_data: 0x400,
        };

        let bytes = original.to_bytes();
        let parsed = DebugDirectory::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn known_debug_types_map_and_unknown_values_do_not() {
        for value in 0..=21 {
            assert_eq!(DebugType::from_u32(value).unwrap().as_u32(), value);
        }
        assert_eq!(DebugType::from_u32(0), Some(DebugType::Unknown));
        assert_eq!(
            DebugType::from_u32(17),
            Some(DebugType::EmbeddedPortablePdb)
        );
        assert_eq!(DebugType::from_u32(19), Some(DebugType::PdbChecksum));
        assert_eq!(DebugType::from_u32(21), Some(DebugType::PerfMap));
        assert_eq!(DebugType::from_u32(22), None);
        let directory = DebugDirectory {
            debug_type: 0x1234,
            ..DebugDirectory::default()
        };
        assert_eq!(directory.get_type(), None);
    }

    #[test]
    fn set_codeview_replaces_the_first_rsds_payload() {
        let first = codeview(b"first.pdb").to_bytes();
        let second = codeview(b"second.pdb").to_bytes();
        let mut info = DebugInfo::default();
        for payload in [&first, &second] {
            info.directories.push(DebugDirectory {
                debug_type: DebugType::CodeView.as_u32(),
                size_of_data: u32::try_from(payload.len()).unwrap(),
                ..DebugDirectory::default()
            });
            info.data.push(Some(payload.clone()));
        }
        assert_eq!(info.pdb_path().as_deref(), Some("first.pdb"));

        info.set_codeview(&codeview(b"changed-name.pdb")).unwrap();
        assert_eq!(info.directories.len(), 2);
        assert_eq!(info.pdb_path().as_deref(), Some("changed-name.pdb"));
        assert_eq!(
            info.directories[0].size_of_data as usize,
            info.data[0].as_ref().unwrap().len()
        );
        assert_eq!(info.data[1].as_ref(), Some(&second));
    }

    #[test]
    fn set_codeview_adds_an_entry_when_no_rsds_record_exists() {
        let mut info = DebugInfo::default();
        info.directories.push(DebugDirectory {
            debug_type: DebugType::Repro.as_u32(),
            ..DebugDirectory::default()
        });
        info.set_codeview(&codeview(b"new.pdb")).unwrap();
        assert_eq!(info.directories.len(), 2);
        assert_eq!(info.data.len(), 2);
        assert_eq!(info.data[0], None);
        assert_eq!(info.codeview().unwrap(), Some(codeview(b"new.pdb")));
    }

    #[test]
    fn a_malformed_codeview_record_fails_only_its_decode() {
        let mut record = codeview(b"a.pdb").to_bytes();
        record.pop();
        let mut bytes = entry(DebugType::CodeView, record.len(), 0x40).to_vec();
        bytes.resize(0x40, 0);
        bytes.extend_from_slice(&record);

        let info = DebugInfo::parse(0, 28, reader(&bytes)).unwrap();
        assert_eq!(info.data[0].as_deref(), Some(record.as_slice()));
        assert!(info.codeview().is_err());
        assert_eq!(info.pdb_path(), None);
    }

    #[test]
    fn file_offset_payloads_share_the_payload_budget() {
        // Each entry has no RVA, so `parse_with_file` reads its payload at the file offset.
        let size = 1 << 20;
        let count = DebugInfo::MAX_PAYLOAD_BYTES / size + 1;
        let mut table = Vec::new();
        for _ in 0..count {
            let mut directory = DebugDirectory::parse(&entry(DebugType::Coff, size, 0)).unwrap();
            directory.pointer_to_raw_data = 0x1000;
            table.extend_from_slice(&directory.to_bytes());
        }
        let file = vec![0x11; 0x1000 + size];
        let table_size = u32::try_from(table.len()).unwrap();

        // The last payload goes past the budget. Its entry stays, without a payload.
        let info =
            DebugInfo::parse_with_file(0, table_size, reader(&table), reader(&file)).unwrap();
        assert_eq!(info.directories.len(), count);
        assert!(info.data[..count - 1].iter().all(Option::is_some));
        assert_eq!(info.data[count - 1], None);
    }

    #[test]
    fn a_payload_larger_than_the_budget_is_not_read() {
        let size = DebugInfo::MAX_PAYLOAD_BYTES + 1;
        let bytes = entry(DebugType::Coff, size, 0x40).to_vec();
        let read_count = core::cell::Cell::new(0);
        let read = |rva: u32, len: usize| {
            read_count.set(read_count.get() + 1);
            reader(&bytes)(rva, len)
        };

        let info = DebugInfo::parse(0, 28, read).unwrap();
        assert_eq!(info.directories.len(), 1);
        assert_eq!(info.data, [None]);
        // Only the table is read.
        assert_eq!(read_count.get(), 1);
    }
}
