//! Exception table that selects the record format from the machine type.

use super::{ExceptionDirectory, PackedExceptionDirectory};
use crate::coff::MachineType;
use crate::prelude::*;
use crate::{Error, Result};

/// The PE exception directory in the record format of the machine architecture.
///
/// The enum is `#[non_exhaustive]`: a later version can add typed variants for machines that
/// now use [`Self::Raw`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExceptionTable {
    /// AMD64 `RUNTIME_FUNCTION` records.
    X64(ExceptionDirectory),
    /// Windows NT ARM (`ARMv7` Thumb-2, machine `ARMNT`) packed `.pdata` records.
    Arm(PackedExceptionDirectory),
    /// ARM64, ARM64EC, or ARM64X packed `.pdata` records.
    Arm64(PackedExceptionDirectory),
    /// Raw bytes for a machine with an exception ABI that this crate does not model.
    ///
    /// The Windows CE ARM machines (`ARM` and `THUMB`) use this variant. Their records have a
    /// different second word than the Windows NT ARM records.
    Raw {
        /// `IMAGE_FILE_HEADER.Machine` value.
        machine: u16,
        /// Raw table bytes.
        data: Vec<u8>,
    },
}

impl ExceptionTable {
    /// Parse the exception directory according to `machine`.
    ///
    /// For ARM NT, bit 0 of `begin_address` is the Thumb bit. For ARM64, `Flag` 3 marks a
    /// `.pdata` record link; see [`PackedRuntimeFunction::parent_record_rva`].
    ///
    /// [`PackedRuntimeFunction::parent_record_rva`]: super::PackedRuntimeFunction::parent_record_rva
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - The table cannot be read or parsed.
    /// - ARM64 records are not aligned to 4 bytes.
    pub fn parse<F>(machine: u16, pdata_rva: u32, pdata_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        match MachineType::from_u16(machine) {
            Some(MachineType::Amd64) => {
                ExceptionDirectory::parse(pdata_rva, pdata_size, read_at_rva).map(Self::X64)
            }
            Some(MachineType::ArmNt) => {
                PackedExceptionDirectory::parse(pdata_rva, pdata_size, read_at_rva).map(Self::Arm)
            }
            Some(MachineType::Arm64 | MachineType::Arm64Ec | MachineType::Arm64X) => {
                let directory =
                    PackedExceptionDirectory::parse(pdata_rva, pdata_size, read_at_rva)?;
                if directory
                    .functions
                    .iter()
                    .any(|function| !function.begin_address.is_multiple_of(4))
                {
                    return Err(Error::invalid_data_directory(
                        "ARM64 runtime-function address is not aligned to 4 bytes",
                    ));
                }
                Ok(Self::Arm64(directory))
            }
            _ => crate::parse_utils::read_exact_rva(
                &read_at_rva,
                pdata_rva,
                pdata_size as usize,
                "raw exception table",
            )
            .map(|data| Self::Raw { machine, data }),
        }
    }

    /// Serialize to bytes.
    ///
    /// # Panics
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("exception-table build failed: use try_to_bytes()")
    }

    /// Serialize to bytes.
    ///
    /// # Errors
    /// Returns an error if the table is invalid or its size exceeds `u32`.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::X64(directory) => directory.try_to_bytes(),
            Self::Arm(directory) | Self::Arm64(directory) => directory.try_to_bytes(),
            Self::Raw { data, .. } => {
                u32::try_from(data.len()).map_err(|_| {
                    Error::invalid_data_directory("exception table size exceeds u32")
                })?;
                Ok(data.clone())
            }
        }
    }

    /// Number of records (or bytes for [`Self::Raw`]).
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::X64(directory) => directory.len(),
            Self::Arm(directory) | Self::Arm64(directory) => directory.len(),
            Self::Raw { data, .. } => data.len(),
        }
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::X64(directory) => directory.is_empty(),
            Self::Arm(directory) | Self::Arm64(directory) => directory.is_empty(),
            Self::Raw { data, .. } => data.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exception::PackedRuntimeFunction;

    fn parse_records(machine: MachineType, records: &[[u32; 2]]) -> Result<ExceptionTable> {
        let bytes: Vec<u8> = records
            .iter()
            .flat_map(|&[begin_address, unwind_data]| {
                PackedRuntimeFunction {
                    begin_address,
                    unwind_data,
                }
                .to_bytes()
            })
            .collect();
        let size = u32::try_from(bytes.len()).unwrap();
        ExceptionTable::parse(machine as u16, 0x7000, size, |rva, len| {
            let start = usize::try_from(rva.checked_sub(0x7000)?).ok()?;
            bytes
                .get(start..start.checked_add(len)?)
                .map(<[u8]>::to_vec)
        })
    }

    /// Before the fix, an odd `begin_address` (the Thumb bit) was rejected.
    #[test]
    fn arm_nt_accepts_the_thumb_bit() {
        let table = parse_records(MachineType::ArmNt, &[[0x1001, 0x0020_0001]]).unwrap();
        let ExceptionTable::Arm(directory) = table else {
            panic!("expected an ARM NT table");
        };
        assert_eq!(directory.functions[0].begin_address, 0x1001);
    }

    /// Before the fix, a `Flag` 3 record link was rejected as reserved.
    #[test]
    fn arm64_accepts_record_links() {
        let table =
            parse_records(MachineType::Arm64, &[[0x1000, 0x0020_0011], [0x2000, 3]]).unwrap();
        let ExceptionTable::Arm64(directory) = table else {
            panic!("expected an ARM64 table");
        };
        assert_eq!(directory.functions[1].parent_record_rva(), Some(0));
        assert!(parse_records(MachineType::Arm64, &[[0x1002, 1]]).is_err());
    }

    /// Before the fix, Windows CE ARM tables were decoded as Windows NT ARM records.
    #[test]
    fn windows_ce_arm_tables_are_raw() {
        for machine in [MachineType::Arm, MachineType::Thumb] {
            let table = parse_records(machine, &[[0x1000, 0x8000_0001]]).unwrap();
            assert!(
                matches!(table, ExceptionTable::Raw { machine: raw, ref data }
                    if raw == machine as u16 && data.len() == 8)
            );
        }
    }
}
