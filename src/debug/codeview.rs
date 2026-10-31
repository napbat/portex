//! CodeView records in the payload of a debug entry.

use crate::prelude::*;
use crate::{Error, Result};

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
    pub const MIN_SIZE: usize = 25;

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
        if self.pdb_path.contains(&0) {
            return Err(Error::invalid_data_directory(
                "CodeView PDB path contains an embedded NUL byte",
            ));
        }
        let capacity = 24usize
            .checked_add(self.pdb_path.len())
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| Error::invalid_data_directory("CodeView payload size overflow"))?;
        u32::try_from(capacity)
            .map_err(|_| Error::invalid_data_directory("CodeView payload exceeds u32"))?;
        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(&CV_SIGNATURE_RSDS.to_le_bytes());
        buf.extend_from_slice(&self.guid);
        buf.extend_from_slice(&self.age.to_le_bytes());
        buf.extend_from_slice(&self.pdb_path);
        buf.push(0); // Null terminator
        Ok(buf)
    }

    /// Format the GUID as a string in the Microsoft format.
    #[must_use]
    pub fn guid_string(&self) -> String {
        format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([self.guid[0], self.guid[1], self.guid[2], self.guid[3]]),
            u16::from_le_bytes([self.guid[4], self.guid[5]]),
            u16::from_le_bytes([self.guid[6], self.guid[7]]),
            self.guid[8],
            self.guid[9],
            self.guid[10],
            self.guid[11],
            self.guid[12],
            self.guid[13],
            self.guid[14],
            self.guid[15]
        )
    }
}

/// Return `true` if `data` starts with the RSDS signature.
pub(super) fn is_rsds(data: &[u8]) -> bool {
    data.first_chunk::<4>()
        .is_some_and(|signature| u32::from_le_bytes(*signature) == CV_SIGNATURE_RSDS)
}

/// Split an RSDS record into the GUID, the age and the path bytes before the NUL terminator.
pub(super) fn split_rsds(data: &[u8]) -> Result<([u8; 16], u32, &[u8])> {
    if data.len() < CodeViewRsds::MIN_SIZE {
        return Err(Error::buffer_too_small(CodeViewRsds::MIN_SIZE, data.len()));
    }
    // The length check above makes each split succeed.
    let Some((signature, rest)) = data.split_first_chunk::<4>() else {
        return Err(Error::buffer_too_small(CodeViewRsds::MIN_SIZE, data.len()));
    };
    if u32::from_le_bytes(*signature) != CV_SIGNATURE_RSDS {
        return Err(Error::invalid_data_directory("Invalid RSDS signature"));
    }
    let Some((guid, rest)) = rest.split_first_chunk::<16>() else {
        return Err(Error::buffer_too_small(CodeViewRsds::MIN_SIZE, data.len()));
    };
    let Some((age, path_data)) = rest.split_first_chunk::<4>() else {
        return Err(Error::buffer_too_small(CodeViewRsds::MIN_SIZE, data.len()));
    };
    let path = path_data
        .iter()
        .position(|&b| b == 0)
        .and_then(|end| path_data.get(..end))
        .ok_or_else(|| Error::invalid_data_directory("RSDS PDB path is not null-terminated"))?;
    Ok((*guid, u32::from_le_bytes(*age), path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codeview_rsds_roundtrip() {
        let original = CodeViewRsds {
            guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            age: 1,
            pdb_path: b"C:\\path\\to\\file.pdb".to_vec(),
        };

        let bytes = original.to_bytes();
        let parsed = CodeViewRsds::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.pdb_path_str(), Some("C:\\path\\to\\file.pdb"));
    }

    #[test]
    fn an_ansi_path_parses_and_keeps_its_bytes() {
        // 0xE9 is "é" in Windows-1252, and it is not valid UTF-8 alone.
        let original = CodeViewRsds {
            guid: [9; 16],
            age: 2,
            pdb_path: b"\xe9t\xe9.pdb".to_vec(),
        };
        let parsed = CodeViewRsds::parse(&original.to_bytes()).unwrap();
        assert_eq!(parsed.pdb_path, b"\xe9t\xe9.pdb");
        assert_eq!(parsed.pdb_path_str(), None);
        assert_eq!(parsed.pdb_path_lossy(), "\u{fffd}t\u{fffd}.pdb");
        assert_eq!(parsed.to_bytes(), original.to_bytes());
    }

    #[test]
    fn a_path_without_a_terminator_is_an_error() {
        let mut bytes = CodeViewRsds {
            guid: [0; 16],
            age: 0,
            pdb_path: b"a.pdb".to_vec(),
        }
        .to_bytes();
        bytes.pop();
        assert!(CodeViewRsds::parse(&bytes).is_err());
    }
}
