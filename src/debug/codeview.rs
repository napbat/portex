//! CodeView records in the payload of a debug entry.

use core::mem::{offset_of, size_of};

use crate::parse_utils::{le_u16, le_u32, le_u64, put_u16, put_u32, put_u64};
use crate::prelude::*;
use crate::{Error, Result};

/// The layout of `GUID`.
///
/// Portex does not read the structure through this type. The type gives the offset and the width
/// of each field.
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// The layout of the fixed part of `CV_INFO_PDB70`, the CodeView RSDS record.
///
/// The NUL-terminated path `PdbFileName` follows the fixed part. `winnt.h` does not declare
/// this structure.
///
/// Portex does not read the structure through this type. The type gives the offset and the width
/// of each field.
#[repr(C)]
struct CvInfoPdb70 {
    cv_signature: u32,
    signature: Guid,
    age: u32,
}

const _: () = {
    assert!(size_of::<Guid>() == 16);
    assert!(offset_of!(Guid, data4) == 8);
    assert!(size_of::<CvInfoPdb70>() == 24);
    assert!(offset_of!(CvInfoPdb70, signature) == 4);
    assert!(offset_of!(CvInfoPdb70, age) == 20);
};

/// CodeView PDB 7.0 signature (RSDS).
pub const CV_SIGNATURE_RSDS: u32 = 0x5344_5352; // "RSDS"

/// CodeView PDB 2.0 signature (NB10).
///
/// portex does not decode NB10 records. [`DebugInfo`](super::DebugInfo) keeps them as raw
/// payload bytes.
pub const CV_SIGNATURE_NB10: u32 = 0x3031_424E; // "NB10"

/// A CodeView RSDS record (PDB 7.0, `CV_INFO_PDB70`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeViewRsds {
    /// The PDB GUID (16 bytes).
    pub guid: [u8; 16],
    /// The PDB age (revision number).
    pub age: u32,
    /// The path of the PDB file, without the NUL terminator.
    ///
    /// The record stores the path as bytes. The linker writes UTF-8, but older tools write
    /// the bytes of an ANSI code page. Use [`Self::pdb_path_str`] or [`Self::pdb_path_lossy`]
    /// to get text.
    pub pdb_path: Vec<u8>,
}

impl CodeViewRsds {
    /// The minimum record size: signature (4) + GUID (16) + age (4) + NUL terminator (1).
    pub const MIN_SIZE: usize = size_of::<CvInfoPdb70>() + 1;

    /// Parse an RSDS record.
    ///
    /// The function accepts any path bytes before the first NUL byte. It ignores the bytes
    /// after the NUL terminator.
    ///
    /// # Errors
    /// Returns an error if the buffer is too short, the signature is not `RSDS`, or the PDB
    /// path has no NUL terminator.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (guid, age, path) = split_rsds(data)?;
        Ok(Self {
            guid,
            age,
            pdb_path: path.to_vec(),
        })
    }

    /// Return the PDB path as text, if the path is valid UTF-8.
    #[must_use]
    pub fn pdb_path_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.pdb_path).ok()
    }

    /// Return the PDB path as text. Replace each invalid UTF-8 sequence with U+FFFD.
    #[must_use]
    pub fn pdb_path_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.pdb_path)
    }

    /// Serialize the record to bytes.
    ///
    /// # Panics
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("CodeView build failed: use try_to_bytes()")
    }

    /// Serialize an RSDS record. Check the path contents and the record length.
    ///
    /// # Errors
    /// Returns an error if the PDB path contains a NUL byte or the record
    /// size exceeds `u32`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        type R = CvInfoPdb70;
        const N: usize = size_of::<CvInfoPdb70>();

        if self.pdb_path.contains(&0) {
            return Err(Error::invalid_data_directory(
                "CodeView PDB path contains an embedded NUL byte",
            ));
        }
        let capacity = N
            .checked_add(self.pdb_path.len())
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| Error::invalid_data_directory("CodeView payload size overflow"))?;
        u32::try_from(capacity)
            .map_err(|_| Error::invalid_data_directory("CodeView payload exceeds u32"))?;
        let mut header = [0u8; N];
        put_u32::<N, { offset_of!(R, cv_signature) }>(&mut header, CV_SIGNATURE_RSDS);
        put_u32::<N, { offset_of!(R, signature.data1) }>(&mut header, guid_data1(&self.guid));
        put_u16::<N, { offset_of!(R, signature.data2) }>(&mut header, guid_data2(&self.guid));
        put_u16::<N, { offset_of!(R, signature.data3) }>(&mut header, guid_data3(&self.guid));
        put_u64::<N, { offset_of!(R, signature.data4) }>(&mut header, guid_data4(&self.guid));
        put_u32::<N, { offset_of!(R, age) }>(&mut header, self.age);
        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&self.pdb_path);
        buf.push(0); // Null terminator
        Ok(buf)
    }

    /// Format the GUID as a string in the Microsoft format.
    #[must_use]
    pub fn guid_string(&self) -> String {
        // `data4` is a byte array: print its bytes in file order.
        format!(
            "{:08X}{:04X}{:04X}{:016X}",
            guid_data1(&self.guid),
            guid_data2(&self.guid),
            guid_data3(&self.guid),
            guid_data4(&self.guid).swap_bytes(),
        )
    }
}

/// The size of a `GUID`, in bytes.
const GUID: usize = size_of::<Guid>();

/// Return `Data1` of the GUID bytes.
fn guid_data1(guid: &[u8; GUID]) -> u32 {
    le_u32::<GUID, { offset_of!(Guid, data1) }>(guid)
}

/// Return `Data2` of the GUID bytes.
fn guid_data2(guid: &[u8; GUID]) -> u16 {
    le_u16::<GUID, { offset_of!(Guid, data2) }>(guid)
}

/// Return `Data3` of the GUID bytes.
fn guid_data3(guid: &[u8; GUID]) -> u16 {
    le_u16::<GUID, { offset_of!(Guid, data3) }>(guid)
}

/// Return the 8 bytes of `Data4` of the GUID bytes as a little-endian `u64`.
fn guid_data4(guid: &[u8; GUID]) -> u64 {
    le_u64::<GUID, { offset_of!(Guid, data4) }>(guid)
}

/// Return `true` if `data` starts with the RSDS signature.
pub(super) fn is_rsds(data: &[u8]) -> bool {
    const N: usize = size_of::<u32>();
    data.first_chunk::<N>().is_some_and(|signature| {
        le_u32::<N, { offset_of!(CvInfoPdb70, cv_signature) }>(signature) == CV_SIGNATURE_RSDS
    })
}

/// Split an RSDS record into the GUID, the age and the path bytes before the NUL terminator.
pub(super) fn split_rsds(data: &[u8]) -> Result<([u8; 16], u32, &[u8])> {
    type R = CvInfoPdb70;
    const N: usize = size_of::<CvInfoPdb70>();
    if data.len() < CodeViewRsds::MIN_SIZE {
        return Err(Error::buffer_too_small(CodeViewRsds::MIN_SIZE, data.len()));
    }
    let Some((header, path_data)) = data.split_first_chunk::<N>() else {
        return Err(Error::buffer_too_small(CodeViewRsds::MIN_SIZE, data.len()));
    };
    if le_u32::<N, { offset_of!(R, cv_signature) }>(header) != CV_SIGNATURE_RSDS {
        return Err(Error::invalid_data_directory("Invalid RSDS signature"));
    }
    let mut guid = [0u8; GUID];
    let data1 = le_u32::<N, { offset_of!(R, signature.data1) }>(header);
    put_u32::<GUID, { offset_of!(Guid, data1) }>(&mut guid, data1);
    let data2 = le_u16::<N, { offset_of!(R, signature.data2) }>(header);
    put_u16::<GUID, { offset_of!(Guid, data2) }>(&mut guid, data2);
    let data3 = le_u16::<N, { offset_of!(R, signature.data3) }>(header);
    put_u16::<GUID, { offset_of!(Guid, data3) }>(&mut guid, data3);
    let data4 = le_u64::<N, { offset_of!(R, signature.data4) }>(header);
    put_u64::<GUID, { offset_of!(Guid, data4) }>(&mut guid, data4);
    let age = le_u32::<N, { offset_of!(R, age) }>(header);
    let path = path_data
        .iter()
        .position(|&b| b == 0)
        .and_then(|end| path_data.get(..end))
        .ok_or_else(|| Error::invalid_data_directory("RSDS PDB path is not null-terminated"))?;
    Ok((guid, age, path))
}

#[cfg(test)]
mod tests;
