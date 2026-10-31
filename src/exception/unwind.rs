//! x64 `UNWIND_INFO` records and their unwind codes.

use super::RuntimeFunction;
use crate::prelude::*;
use crate::{Error, Result};

/// An x64 unwind operation code (`UWOP_*`).
///
/// The enum is `#[non_exhaustive]`: the 4-bit code space has unused values 11 to 15, which a
/// later version of the format can define.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum UnwindOpCode {
    /// Push a nonvolatile integer register.
    PushNonVol = 0,
    /// Allocate a large-sized area on the stack.
    AllocLarge = 1,
    /// Allocate a small-sized area on the stack.
    AllocSmall = 2,
    /// Establish the frame pointer register.
    SetFpReg = 3,
    /// Save a nonvolatile integer register on the stack using MOV.
    SaveNonVol = 4,
    /// Save a nonvolatile integer register on the stack with a far offset.
    SaveNonVolFar = 5,
    /// Describe the function epilog (`UWOP_EPILOG`).
    ///
    /// Only version 2 of `UNWIND_INFO` defines this code. [`Self::from_u8`] decodes the value
    /// 6 for every version. Check [`UnwindInfo::version`] before you use it.
    Epilog = 6,
    /// Reserved (`UWOP_SPARE_CODE`).
    SpareCode = 7,
    /// Save an XMM(128) register on the stack.
    SaveXmm128 = 8,
    /// Save an XMM(128) register on the stack with a far offset.
    SaveXmm128Far = 9,
    /// Push a machine frame.
    PushMachFrame = 10,
}

impl UnwindOpCode {
    /// Decode a 4-bit `UWOP_*` operation code.
    ///
    /// Returns `None` if the code is unknown.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::PushNonVol),
            1 => Some(Self::AllocLarge),
            2 => Some(Self::AllocSmall),
            3 => Some(Self::SetFpReg),
            4 => Some(Self::SaveNonVol),
            5 => Some(Self::SaveNonVolFar),
            6 => Some(Self::Epilog),
            7 => Some(Self::SpareCode),
            8 => Some(Self::SaveXmm128),
            9 => Some(Self::SaveXmm128Far),
            10 => Some(Self::PushMachFrame),
            _ => None,
        }
    }
}

/// One x64 unwind code slot (`UNWIND_CODE`).
///
/// An operation uses one, two or three slots. `AllocLarge`, `SaveNonVol`, `SaveNonVolFar`,
/// `SaveXmm128` and `SaveXmm128Far` keep their operand in the slots that follow. In such a
/// data slot, [`Self::op_code`] and [`Self::op_info`] have no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCode {
    /// Offset in the prolog of the end of the instruction for this operation.
    pub code_offset: u8,
    /// Operation code (4 bits) and operation info (4 bits).
    pub op_and_info: u8,
}

impl UnwindCode {
    /// Return the operation code.
    #[must_use]
    pub fn op_code(self) -> Option<UnwindOpCode> {
        UnwindOpCode::from_u8(self.op_and_info & 0x0F)
    }

    /// Return the operation info.
    ///
    /// The meaning of the value depends on [`Self::op_code`].
    #[must_use]
    pub fn op_info(self) -> u8 {
        self.op_and_info >> 4
    }
}

/// No handler (`UNW_FLAG_NHANDLER`).
pub const UNW_FLAG_NHANDLER: u8 = 0;
/// Exception handler present (`UNW_FLAG_EHANDLER`).
pub const UNW_FLAG_EHANDLER: u8 = 1;
/// Termination handler present (`UNW_FLAG_UHANDLER`).
pub const UNW_FLAG_UHANDLER: u8 = 2;
/// Chained to another `RUNTIME_FUNCTION` (`UNW_FLAG_CHAININFO`).
pub const UNW_FLAG_CHAININFO: u8 = 4;

/// Size of the exception-handler RVA that follows the unwind codes.
const HANDLER_RVA_SIZE: usize = 4;

/// An x64 unwind information record (`UNWIND_INFO`).
///
/// The record has no separate field for `CountOfCodes`: the serializer writes the length of
/// `unwind_codes`. The record has no separate field for the chained `RUNTIME_FUNCTION`
/// either: `chained_function` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnwindInfo {
    /// Version (3 bits) and flags (5 bits).
    pub version_flags: u8,
    /// Size of the prolog in bytes.
    pub size_of_prolog: u8,
    /// Frame register (4 bits) and frame register offset (4 bits).
    pub frame_reg_and_offset: u8,
    /// The unwind code slots. `CountOfCodes` is the length of this array.
    ///
    /// The array holds slots, not operations. See [`UnwindCode`].
    pub unwind_codes: Vec<UnwindCode>,
    /// Exception handler RVA (if `UNW_FLAG_EHANDLER` or `UNW_FLAG_UHANDLER`).
    pub exception_handler: Option<u32>,
    /// The chained `RUNTIME_FUNCTION` entry (if `UNW_FLAG_CHAININFO`).
    pub chained_function: Option<RuntimeFunction>,
    /// Language-specific bytes that follow the exception handler RVA.
    ///
    /// The format does not give the length of these bytes. Thus [`Self::parse`] keeps all
    /// bytes of its input after the handler RVA. Give `parse` a slice that ends where the
    /// language-specific data ends.
    pub handler_data: Vec<u8>,
}

impl UnwindInfo {
    /// Minimum size in bytes.
    ///
    /// The header has `version_flags`, `size_of_prolog`, `CountOfCodes` and
    /// `frame_reg_and_offset`.
    pub const MIN_SIZE: usize = 4;

    /// Return the version (bits 0-2).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version_flags & 0x07
    }

    /// Return the flags (bits 3-7).
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.version_flags >> 3
    }

    /// Return `true` if the record has an exception handler or a termination handler.
    #[must_use]
    pub fn has_exception_handler(&self) -> bool {
        let flags = self.flags();
        (flags & UNW_FLAG_EHANDLER) != 0 || (flags & UNW_FLAG_UHANDLER) != 0
    }

    /// Return `true` if the record chains to other unwind information.
    #[must_use]
    pub fn is_chained(&self) -> bool {
        (self.flags() & UNW_FLAG_CHAININFO) != 0
    }

    /// Return the frame register (0 = no frame register).
    #[must_use]
    pub fn frame_register(&self) -> u8 {
        self.frame_reg_and_offset & 0x0F
    }

    /// Return the frame register offset (scaled by 16).
    #[must_use]
    pub fn frame_offset(&self) -> u8 {
        self.frame_reg_and_offset >> 4
    }

    /// Parse an `UNWIND_INFO` record from the bytes at its RVA.
    ///
    /// If the record has a handler, [`Self::handler_data`] gets all bytes of `data` after the
    /// handler RVA. Thus `data` must end where the language-specific data ends.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - The buffer is too short for the header, the unwind codes, or the
    ///   trailing handler or chain data.
    /// - The version or the flags are unsupported or inconsistent.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some((header, after_header)) = data.split_first_chunk::<{ Self::MIN_SIZE }>() else {
            return Err(Error::buffer_too_small(Self::MIN_SIZE, data.len()));
        };
        let [
            version_flags,
            size_of_prolog,
            count_of_codes,
            frame_reg_and_offset,
        ] = *header;

        Self::validate_header(version_flags)?;

        // Each unwind code has 2 bytes. A `u8` count gives at most 510 bytes, and the slot
        // array is padded to a multiple of 4 bytes.
        let codes_size = usize::from(count_of_codes) * 2;
        let aligned_codes_size = (codes_size + 3) & !3;
        let Some(codes) = after_header.get(..codes_size) else {
            return Err(Error::buffer_too_small(
                Self::MIN_SIZE + codes_size,
                data.len(),
            ));
        };
        let (code_pairs, _) = codes.as_chunks::<2>();
        let unwind_codes = code_pairs
            .iter()
            .map(|&[code_offset, op_and_info]| UnwindCode {
                code_offset,
                op_and_info,
            })
            .collect();

        // The handler or chain data starts after the padded unwind codes.
        let trailer_offset = Self::MIN_SIZE + aligned_codes_size;
        let trailer = data.get(trailer_offset..).unwrap_or_default();
        let flags = version_flags >> 3;

        let mut exception_handler = None;
        let mut chained_function = None;
        let mut handler_data = Vec::new();

        if (flags & UNW_FLAG_CHAININFO) != 0 {
            if trailer.len() < RuntimeFunction::SIZE {
                return Err(Error::buffer_too_small(
                    trailer_offset + RuntimeFunction::SIZE,
                    data.len(),
                ));
            }
            chained_function = Some(RuntimeFunction::parse(trailer)?);
        } else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0 {
            let Some((handler, language_data)) = trailer.split_first_chunk::<HANDLER_RVA_SIZE>()
            else {
                return Err(Error::buffer_too_small(
                    trailer_offset + HANDLER_RVA_SIZE,
                    data.len(),
                ));
            };
            exception_handler = Some(u32::from_le_bytes(*handler));
            handler_data.extend_from_slice(language_data);
        }

        let info = Self {
            version_flags,
            size_of_prolog,
            frame_reg_and_offset,
            unwind_codes,
            exception_handler,
            chained_function,
            handler_data,
        };
        info.validate()?;
        Ok(info)
    }

    /// Serialize to bytes.
    ///
    /// # Panics
    /// Panics if [`Self::try_to_bytes`] fails.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("unwind-info build failed: use try_to_bytes()")
    }

    /// Serialize the record to bytes after validation.
    ///
    /// The record must be complete and internally consistent.
    ///
    /// # Errors
    /// Returns an error if [`Self::validate`] fails.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        self.try_to_bytes_with_handler_data(&self.handler_data)
    }

    /// Serialize the record with borrowed `handler_data` in place of [`Self::handler_data`].
    ///
    /// The record must stay internally consistent. A nonempty `handler_data` requires an
    /// exception handler. Use this function to emit several records with the same language
    /// data: it does not make an owned copy of the data.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - [`Self::validate`] fails.
    /// - `handler_data` is nonempty and the record has no handler.
    /// - A size calculation overflows.
    pub fn try_to_bytes_with_handler_data(&self, handler_data: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;
        if !handler_data.is_empty() && self.exception_handler.is_none() {
            return Err(Error::invalid_data_directory(
                "borrowed exception-handler data present without a handler",
            ));
        }
        let count_of_codes = u8::try_from(self.unwind_codes.len())
            .map_err(|_| Error::invalid_data_directory("more than 255 unwind-code slots"))?;
        // A `u8` count gives at most 510 bytes of unwind codes. This sum cannot overflow.
        let codes_end = Self::MIN_SIZE + ((usize::from(count_of_codes) * 2 + 3) & !3);
        let chained_size = self.chained_function.map_or(0, |_| RuntimeFunction::SIZE);
        let handler_size = self
            .exception_handler
            .map(|_| {
                HANDLER_RVA_SIZE
                    .checked_add(handler_data.len())
                    .ok_or_else(|| Error::invalid_data_directory("unwind handler size overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        let total_size = codes_end
            .checked_add(chained_size.max(handler_size))
            .ok_or_else(|| Error::invalid_data_directory("unwind-info size overflow"))?;

        let mut buf = Vec::with_capacity(total_size);
        buf.extend_from_slice(&[
            self.version_flags,
            self.size_of_prolog,
            count_of_codes,
            self.frame_reg_and_offset,
        ]);
        for code in &self.unwind_codes {
            buf.extend_from_slice(&[code.code_offset, code.op_and_info]);
        }
        // Pad the unwind-code array to a multiple of 4 bytes.
        buf.resize(codes_end, 0);

        if let Some(chained) = self.chained_function {
            buf.extend_from_slice(&chained.to_bytes());
        } else if let Some(handler) = self.exception_handler {
            buf.extend_from_slice(&handler.to_le_bytes());
            buf.extend_from_slice(handler_data);
        }

        Ok(buf)
    }

    /// Check the flag combination and the related trailing data.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - The version or the flags are unsupported.
    /// - The record has more than 255 unwind codes.
    /// - The handler or chain data does not agree with the flags.
    pub fn validate(&self) -> Result<()> {
        Self::validate_header(self.version_flags)?;
        if self.unwind_codes.len() > usize::from(u8::MAX) {
            return Err(Error::invalid_data_directory(
                "more than 255 unwind-code slots",
            ));
        }

        let chained = self.is_chained();
        let handled = self.has_exception_handler();
        if chained {
            if self.chained_function.is_none() {
                return Err(Error::invalid_data_directory(
                    "UNW_FLAG_CHAININFO requires a complete RUNTIME_FUNCTION record",
                ));
            }
            if self.exception_handler.is_some() || !self.handler_data.is_empty() {
                return Err(Error::invalid_data_directory(
                    "chained unwind info cannot contain exception-handler data",
                ));
            }
        } else if self.chained_function.is_some() {
            return Err(Error::invalid_data_directory(
                "chained runtime function present without UNW_FLAG_CHAININFO",
            ));
        }

        if handled {
            if self.exception_handler.is_none() {
                return Err(Error::invalid_data_directory(
                    "unwind handler flag requires an exception-handler RVA",
                ));
            }
        } else if self.exception_handler.is_some() || !self.handler_data.is_empty() {
            return Err(Error::invalid_data_directory(
                "exception-handler data present without a handler flag",
            ));
        }
        Ok(())
    }

    fn validate_header(version_flags: u8) -> Result<()> {
        let version = version_flags & 0x07;
        if !(1..=2).contains(&version) {
            return Err(Error::invalid_data_directory(format!(
                "unsupported x64 unwind version {version}"
            )));
        }
        let flags = version_flags >> 3;
        let supported = UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO;
        if flags & !supported != 0 {
            return Err(Error::invalid_data_directory(format!(
                "unsupported x64 unwind flags {flags:#x}"
            )));
        }
        if flags & UNW_FLAG_CHAININFO != 0 && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            return Err(Error::invalid_data_directory(
                "UNW_FLAG_CHAININFO cannot be combined with handler flags",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_handler_payload_is_serialized_without_owned_replacement() {
        let info = UnwindInfo {
            version_flags: 1 | (UNW_FLAG_EHANDLER << 3),
            exception_handler: Some(0x3000),
            handler_data: vec![0xaa],
            ..UnwindInfo::default()
        };
        let bytes = info
            .try_to_bytes_with_handler_data(&[0x11, 0x22, 0x33])
            .expect("borrowed language metadata is valid");
        assert_eq!(&bytes[4..8], &0x3000_u32.to_le_bytes());
        assert_eq!(&bytes[8..], &[0x11, 0x22, 0x33]);
        assert_eq!(info.handler_data, [0xaa]);
        assert_eq!(
            &info.try_to_bytes().expect("owned metadata remains valid")[8..],
            &[0xaa]
        );
        let unhandled = UnwindInfo {
            version_flags: 1,
            ..UnwindInfo::default()
        };
        assert!(unhandled.try_to_bytes_with_handler_data(&[1]).is_err());
    }

    /// Before the fix, `count_of_codes` and `chained_info` were fields that serialization
    /// ignored. A value with default fields did not survive a round trip.
    #[test]
    fn serialized_record_round_trips_without_redundant_fields() {
        let info = UnwindInfo {
            version_flags: 1 | (UNW_FLAG_CHAININFO << 3),
            size_of_prolog: 4,
            unwind_codes: vec![UnwindCode {
                code_offset: 4,
                op_and_info: 0x32,
            }],
            chained_function: Some(RuntimeFunction {
                begin_address: 0x1000,
                end_address: 0x1100,
                unwind_info_address: 0x2000,
            }),
            ..UnwindInfo::default()
        };
        let bytes = info.try_to_bytes().unwrap();
        assert_eq!(bytes[2], 1);
        assert_eq!(UnwindInfo::parse(&bytes).unwrap(), info);
    }
}
