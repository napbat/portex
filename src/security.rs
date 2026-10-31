//! Security directory (Authenticode) parsing.
//!
//! The security directory contains `WIN_CERTIFICATE` structures for code signing.
//! Unlike the other data directories, this directory uses a **file offset**, not an RVA.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeFile;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeFile::parse(file_bytes)?;
//!
//! if let Some(certs) = pe.security()? {
//!     for cert in &certs.certificates {
//!         println!("Certificate type: {:?}, revision: {:?}",
//!             cert.certificate_type, cert.revision);
//!         println!("  Data length: {} bytes", cert.data.len());
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// `WIN_CERTIFICATE` revision values (`wRevision`).
///
/// A later release can add a named variant for a value that is [`Self::Unknown`] now.
/// [`Self::from_u16`] never returns `Unknown` for a value that has a named variant. Do not
/// make `Unknown` with such a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateRevision {
    /// `WIN_CERT_REVISION_1_0`
    Revision1,
    /// `WIN_CERT_REVISION_2_0`
    Revision2,
    /// A revision that this version of the crate does not know.
    Unknown(u16),
}

impl CertificateRevision {
    /// Convert from the raw `wRevision` value.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0100 => Self::Revision1,
            0x0200 => Self::Revision2,
            other => Self::Unknown(other),
        }
    }

    /// Convert to the raw `wRevision` value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Revision1 => 0x0100,
            Self::Revision2 => 0x0200,
            Self::Unknown(value) => value,
        }
    }
}

/// `WIN_CERTIFICATE` type values (`wCertificateType`).
///
/// A later release can add a named variant for a value that is [`Self::Unknown`] now.
/// [`Self::from_u16`] never returns `Unknown` for a value that has a named variant. Do not
/// make `Unknown` with such a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateType {
    /// `WIN_CERT_TYPE_X509`: an X.509 certificate.
    X509,
    /// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`: a PKCS#7 `SignedData` structure.
    PkcsSignedData,
    /// `WIN_CERT_TYPE_RESERVED_1`
    Reserved1,
    /// `WIN_CERT_TYPE_TS_STACK_SIGNED`: Terminal Server Protocol Stack.
    TsStackSigned,
    /// `WIN_CERT_TYPE_EFI_PKCS115` (0x0EF0): a UEFI PKCS#1 v1.5 signature.
    EfiPkcs115,
    /// `WIN_CERT_TYPE_EFI_GUID` (0x0EF1): a UEFI signature that a GUID identifies.
    EfiGuid,
    /// A certificate type that this version of the crate does not know.
    Unknown(u16),
}

impl CertificateType {
    /// Convert from the raw `wCertificateType` value.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0001 => Self::X509,
            0x0002 => Self::PkcsSignedData,
            0x0003 => Self::Reserved1,
            0x0004 => Self::TsStackSigned,
            0x0EF0 => Self::EfiPkcs115,
            0x0EF1 => Self::EfiGuid,
            other => Self::Unknown(other),
        }
    }

    /// Convert to the raw `wCertificateType` value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::X509 => 0x0001,
            Self::PkcsSignedData => 0x0002,
            Self::Reserved1 => 0x0003,
            Self::TsStackSigned => 0x0004,
            Self::EfiPkcs115 => 0x0EF0,
            Self::EfiGuid => 0x0EF1,
            Self::Unknown(value) => value,
        }
    }
}

/// `WIN_CERTIFICATE`: one entry of the attribute certificate table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "certificate_type mirrors the spec field wCertificateType; `type` is a keyword"
)]
pub struct Certificate {
    /// Total length in bytes (`dwLength`). The length includes the header but not the alignment
    /// padding.
    pub length: u32,
    /// Certificate revision (`wRevision`).
    pub revision: CertificateRevision,
    /// Certificate type (`wCertificateType`).
    pub certificate_type: CertificateType,
    /// Raw certificate data (`bCertificate`), without the header.
    pub data: Vec<u8>,
}

impl Certificate {
    /// Size of the header in bytes (length, revision and type).
    pub const HEADER_SIZE: usize = 8;

    /// Parse one certificate from a byte slice.
    ///
    /// Returns the certificate and the number of bytes that it uses, including the padding.
    /// Each certificate starts at an 8-byte boundary. The padding of the last certificate can
    /// be missing, as in the table walk of the PE specification. Then the number of bytes is
    /// the length of `data`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::BufferTooSmall`](crate::error::ErrorKind::BufferTooSmall)
    /// if `data` is shorter than the 8-byte header.
    ///
    /// Returns [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if `dwLength` is smaller than the header, or if it is larger than `data`.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        let Some((header, _)) = data.split_first_chunk::<{ Self::HEADER_SIZE }>() else {
            return Err(Error::buffer_too_small(Self::HEADER_SIZE, data.len()));
        };
        let [l0, l1, l2, l3, r0, r1, t0, t1] = *header;
        let length_u32 = u32::from_le_bytes([l0, l1, l2, l3]);
        let length = usize::try_from(length_u32)
            .map_err(|_| Error::invalid_data_directory("certificate length exceeds usize"))?;
        let revision = CertificateRevision::from_u16(u16::from_le_bytes([r0, r1]));
        let certificate_type = CertificateType::from_u16(u16::from_le_bytes([t0, t1]));

        let Some(cert_data) = data.get(Self::HEADER_SIZE..length).map(<[u8]>::to_vec) else {
            return Err(Error::invalid_data_directory(format!(
                "invalid certificate length: {} (available: {})",
                length,
                data.len()
            )));
        };

        // Each certificate is aligned to 8 bytes. The table can end before the padding of
        // its last certificate.
        let padded_length = length
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or_else(|| Error::invalid_data_directory("certificate alignment overflow"))?
            .min(data.len());

        Ok((
            Self {
                length: length_u32,
                revision,
                certificate_type,
                data: cert_data,
            },
            padded_length,
        ))
    }
}

/// The security directory (attribute certificate table), with all its certificates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityDirectory {
    /// The certificates, in file order.
    pub certificates: Vec<Certificate>,
}

impl SecurityDirectory {
    /// Parse all certificates from the data of the security directory.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if the bytes at the end are too short for a certificate header. Also returns each
    /// error from [`Certificate::parse`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut certificates = Vec::new();
        let mut rest = data;

        while !rest.is_empty() {
            if rest.len() < Certificate::HEADER_SIZE {
                return Err(Error::invalid_data_directory(format!(
                    "{} trailing bytes remain after the final certificate",
                    rest.len()
                )));
            }

            let (cert, consumed) = Certificate::parse(rest)?;
            certificates.push(cert);
            // `Certificate::parse` returns `consumed <= rest.len()`.
            rest = rest.get(consumed..).unwrap_or_default();
        }

        Ok(Self { certificates })
    }
}

/// Builder that serializes security certificates.
///
/// **Note:** The security directory is special. Its data directory holds a file offset, not
/// an RVA. The certificates are in the overlay, after all section data.
///
/// This builder only makes the certificate data. Append the data to the file yourself. Then
/// update the data directory entry.
#[derive(Debug, Default)]
pub struct SecurityBuilder;

impl SecurityBuilder {
    /// Create a builder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Calculate the total size of all certificates, in bytes.
    ///
    /// Each certificate is aligned to 8 bytes.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] returns an error.
    #[must_use]
    pub fn calculate_size(directory: &SecurityDirectory) -> usize {
        Self::try_calculate_size(directory)
            .expect("certificate table size overflow: use try_calculate_size()")
    }

    /// Calculate the table size, with checked `WIN_CERTIFICATE` lengths.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if a certificate length or the total table size overflows or is larger than `u32::MAX`.
    pub fn try_calculate_size(directory: &SecurityDirectory) -> Result<usize> {
        let size = directory
            .certificates
            .iter()
            .try_fold(0usize, |total, certificate| {
                let length = Certificate::HEADER_SIZE
                    .checked_add(certificate.data.len())
                    .ok_or_else(|| Error::invalid_data_directory("certificate length overflow"))?;
                u32::try_from(length).map_err(|_| {
                    Error::invalid_data_directory("WIN_CERTIFICATE length exceeds u32")
                })?;
                let padded = length
                    .checked_add(7)
                    .map(|value| value & !7)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("certificate alignment overflow")
                    })?;
                total
                    .checked_add(padded)
                    .ok_or_else(|| Error::invalid_data_directory("certificate-table size overflow"))
            })?;
        u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("certificate table exceeds u32"))?;
        Ok(size)
    }

    /// Build the data of the security directory.
    ///
    /// Returns the raw bytes to append to the overlay of the file. After you append them,
    /// update the security data directory entry:
    /// - `virtual_address`: the file offset of the appended data (not an RVA).
    /// - size: the length of the returned data.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] returns an error.
    #[must_use]
    pub fn build(directory: &SecurityDirectory) -> Vec<u8> {
        Self::try_build(directory)
            .expect("certificate build failed: use try_build() for fallible serialization")
    }

    /// Build the security directory, with checked lengths and alignments.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidDataDirectory`](crate::error::ErrorKind::InvalidDataDirectory)
    /// if a certificate length or the total table size overflows or is larger than `u32::MAX`.
    pub fn try_build(directory: &SecurityDirectory) -> Result<Vec<u8>> {
        if directory.certificates.is_empty() {
            return Ok(Vec::new());
        }

        let total_size = Self::try_calculate_size(directory)?;
        let mut data = Vec::with_capacity(total_size);

        for cert in &directory.certificates {
            // Write the length: the header plus the data, without padding.
            let cert_length_u32 = Certificate::HEADER_SIZE
                .checked_add(cert.data.len())
                .and_then(|length| u32::try_from(length).ok())
                .ok_or_else(|| Error::invalid_data_directory("certificate length exceeds u32"))?;
            data.extend_from_slice(&cert_length_u32.to_le_bytes());
            data.extend_from_slice(&cert.revision.as_u16().to_le_bytes());
            data.extend_from_slice(&cert.certificate_type.as_u16().to_le_bytes());
            data.extend_from_slice(&cert.data);

            // Pad to the next 8-byte boundary. Each certificate starts at an aligned
            // position, so this aligns the certificate length.
            let padded_end = data
                .len()
                .checked_add(7)
                .map(|value| value & !7)
                .ok_or_else(|| Error::invalid_data_directory("certificate alignment overflow"))?;
            data.resize(padded_end, 0);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_header_size() {
        assert_eq!(Certificate::HEADER_SIZE, 8);
    }

    #[test]
    fn test_certificate_revision() {
        assert_eq!(
            CertificateRevision::from_u16(0x0100),
            CertificateRevision::Revision1
        );
        assert_eq!(
            CertificateRevision::from_u16(0x0200),
            CertificateRevision::Revision2
        );
        assert_eq!(
            CertificateRevision::from_u16(0x0300),
            CertificateRevision::Unknown(0x0300)
        );
    }

    #[test]
    fn test_certificate_type() {
        assert_eq!(
            CertificateType::from_u16(0x0002),
            CertificateType::PkcsSignedData
        );
        assert_eq!(
            CertificateType::from_u16(0x0000),
            CertificateType::Unknown(0x0000)
        );
    }

    #[test]
    fn test_certificate_buffer_too_small() {
        let data = [0u8; 7];
        assert!(Certificate::parse(&data).is_err());
    }

    #[test]
    fn test_builder_empty() {
        let dir = SecurityDirectory::default();
        let data = SecurityBuilder::build(&dir);
        assert_eq!(data, [] as [u8; 0]);
        assert_eq!(SecurityBuilder::calculate_size(&dir), 0);
    }

    #[test]
    fn test_builder_roundtrip() {
        let cert = Certificate {
            length: 0, // The builder calculates the length.
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![0x30, 0x82, 0x01, 0x00], // A fake ASN.1 header.
        };

        let dir = SecurityDirectory {
            certificates: vec![cert],
        };

        let data = SecurityBuilder::build(&dir);

        // Parse the data again.
        let parsed = SecurityDirectory::parse(&data).unwrap();
        assert_eq!(parsed.certificates.len(), 1);
        assert_eq!(
            parsed.certificates[0].revision,
            CertificateRevision::Revision2
        );
        assert_eq!(
            parsed.certificates[0].certificate_type,
            CertificateType::PkcsSignedData
        );
        assert_eq!(parsed.certificates[0].data, vec![0x30, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_builder_alignment() {
        // Each certificate must be aligned to 8 bytes.
        let cert = Certificate {
            length: 0,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![1, 2, 3], // 3 data bytes + 8 header bytes = 11, rounded up to 16.
        };

        let dir = SecurityDirectory {
            certificates: vec![cert],
        };

        let size = SecurityBuilder::calculate_size(&dir);
        assert_eq!(size % 8, 0); // The size must be aligned to 8 bytes.
        assert_eq!(size, 16); // 11, rounded up to 16.
    }

    #[test]
    fn test_builder_two_certificates_layout() {
        let first = Certificate {
            length: 0,
            revision: CertificateRevision::Revision2,
            certificate_type: CertificateType::PkcsSignedData,
            data: vec![1, 2, 3],
        };
        let second = Certificate {
            length: 0,
            revision: CertificateRevision::Revision1,
            certificate_type: CertificateType::X509,
            data: vec![4; 8],
        };
        let dir = SecurityDirectory {
            certificates: vec![first, second],
        };

        let data = SecurityBuilder::try_build(&dir).unwrap();
        assert_eq!(
            data.len(),
            SecurityBuilder::try_calculate_size(&dir).unwrap()
        );
        assert_eq!(data.len(), 32);
        assert_eq!(&data[0..4], &11u32.to_le_bytes());
        assert_eq!(&data[11..16], &[0; 5]);
        assert_eq!(&data[16..20], &16u32.to_le_bytes());

        let parsed = SecurityDirectory::parse(&data).unwrap();
        assert_eq!(parsed.certificates.len(), 2);
        assert_eq!(parsed.certificates[1].data, vec![4; 8]);
    }

    #[test]
    fn test_certificate_length_out_of_range() {
        let mut data = [0u8; 16];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(Certificate::parse(&data).is_err());
        data[0..4].copy_from_slice(&17u32.to_le_bytes());
        assert!(Certificate::parse(&data).is_err());
        assert!(SecurityDirectory::parse(&data[..12]).is_err());
    }

    #[test]
    fn a_last_certificate_without_padding_parses() {
        // Two certificates of 11 and 13 bytes. Only the first one has its padding.
        let mut data = vec![0u8; 16 + 13];
        data[0..4].copy_from_slice(&11u32.to_le_bytes());
        data[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
        data[6..8].copy_from_slice(&0x0002u16.to_le_bytes());
        data[16..20].copy_from_slice(&13u32.to_le_bytes());
        data[20..22].copy_from_slice(&0x0200u16.to_le_bytes());
        data[22..24].copy_from_slice(&0x0EF1u16.to_le_bytes());
        data[24..29].copy_from_slice(&[1, 2, 3, 4, 5]);

        let (_, consumed) = Certificate::parse(&data[16..]).unwrap();
        assert_eq!(consumed, 13);
        let parsed = SecurityDirectory::parse(&data).unwrap();
        assert_eq!(parsed.certificates.len(), 2);
        assert_eq!(parsed.certificates[1].length, 13);
        assert_eq!(
            parsed.certificates[1].certificate_type,
            CertificateType::EfiGuid
        );
        assert_eq!(parsed.certificates[1].data, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn efi_certificate_types_have_names() {
        for (value, name) in [
            (0x0EF0, CertificateType::EfiPkcs115),
            (0x0EF1, CertificateType::EfiGuid),
        ] {
            assert_eq!(CertificateType::from_u16(value), name);
            assert_eq!(name.as_u16(), value);
        }
    }
}
