//! x64 `UNWIND_INFO` records and their unwind codes.

use core::mem::{offset_of, size_of};

use nostdio::{ReadLe, WriteLe};

use super::RuntimeFunction;
use crate::parse_utils::{le_u8, put_u8};
use crate::prelude::*;
use crate::{Error, Result};

mod v3;

pub use v3::{
    EpilogOpsV3, EpilogV3, ResolvedEpilogV3, UNW_FLAG_LARGE, UnwindInfoV3, WindOp, X64UnwindInfo,
};

/// The layout of the 4-byte header of the x64 `UNWIND_INFO`.
///
/// `winnt.h` does not define the structure. The Microsoft x64 exception-handling
/// documentation does. The version (3 bits) and the flags (5 bits) share the first byte. The
/// frame register (4 bits) and the scaled frame offset (4 bits) share the last byte.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
pub(crate) struct UnwindInfoHeader {
    pub(crate) version_and_flags: u8,
    pub(crate) size_of_prolog: u8,
    pub(crate) count_of_codes: u8,
    pub(crate) frame_register_and_offset: u8,
}

/// The layout of the x64 `UNWIND_CODE` slot.
///
/// `winnt.h` does not define the structure. The Microsoft x64 exception-handling
/// documentation does. The operation code (4 bits) and the operation info (4 bits) share the
/// second byte.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
pub(crate) struct UnwindCodeSlot {
    pub(crate) code_offset: u8,
    pub(crate) unwind_op_and_info: u8,
}

const _: () = {
    assert!(size_of::<UnwindInfoHeader>() == 4);
    assert!(offset_of!(UnwindInfoHeader, count_of_codes) == 2);
    assert!(offset_of!(UnwindInfoHeader, frame_register_and_offset) == 3);
    assert!(size_of::<UnwindCodeSlot>() == 2);
    assert!(offset_of!(UnwindCodeSlot, unwind_op_and_info) == 1);
};

/// Return the size of the `UNWIND_INFO` header and of `count_of_codes` unwind code slots.
///
/// The slot array is padded to a multiple of 4 bytes. Thus this is the offset of the handler
/// RVA or of the chained `RUNTIME_FUNCTION`. A `u8` count gives at most 512 bytes, so the
/// calculation cannot overflow.
pub(crate) const fn unwind_codes_end(count_of_codes: u8) -> usize {
    let codes_size = count_of_codes as usize * size_of::<UnwindCodeSlot>();
    size_of::<UnwindInfoHeader>() + codes_size.next_multiple_of(size_of::<u32>())
}

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
const HANDLER_RVA_SIZE: usize = size_of::<u32>();

/// An x64 unwind information record (`UNWIND_INFO`) of version 1 or version 2.
///
/// The record has no separate field for `CountOfCodes`: the serializer writes the length of
/// `unwind_codes`. The record has no separate field for the chained `RUNTIME_FUNCTION`
/// either: `chained_function` holds it.
///
/// [`UnwindInfoV3`] holds a version 3 record. [`X64UnwindInfo`] holds a record of any of these
/// versions.
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
    pub const MIN_SIZE: usize = size_of::<UnwindInfoHeader>();

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
        const N: usize = UnwindInfo::MIN_SIZE;
        const SLOT: usize = size_of::<UnwindCodeSlot>();
        let Some((header, after_header)) = data.split_first_chunk::<{ Self::MIN_SIZE }>() else {
            return Err(Error::buffer_too_small(Self::MIN_SIZE, data.len()));
        };
        let version_flags = le_u8::<N, { offset_of!(UnwindInfoHeader, version_and_flags) }>(header);
        let size_of_prolog = le_u8::<N, { offset_of!(UnwindInfoHeader, size_of_prolog) }>(header);
        let count_of_codes = le_u8::<N, { offset_of!(UnwindInfoHeader, count_of_codes) }>(header);
        let frame_reg_and_offset =
            le_u8::<N, { offset_of!(UnwindInfoHeader, frame_register_and_offset) }>(header);

        Self::validate_header(version_flags)?;

        let codes_size = usize::from(count_of_codes) * size_of::<UnwindCodeSlot>();
        let Some(codes) = after_header.get(..codes_size) else {
            return Err(Error::buffer_too_small(
                Self::MIN_SIZE + codes_size,
                data.len(),
            ));
        };
        let (slots, _) = codes.as_chunks::<SLOT>();
        let unwind_codes = slots
            .iter()
            .map(|slot| UnwindCode {
                code_offset: le_u8::<SLOT, { offset_of!(UnwindCodeSlot, code_offset) }>(slot),
                op_and_info: le_u8::<SLOT, { offset_of!(UnwindCodeSlot, unwind_op_and_info) }>(
                    slot,
                ),
            })
            .collect();

        // The handler or chain data starts after the padded unwind codes.
        let trailer = parse_trailer(data, unwind_codes_end(count_of_codes), version_flags >> 3)?;
        let info = Self {
            version_flags,
            size_of_prolog,
            frame_reg_and_offset,
            unwind_codes,
            exception_handler: trailer.exception_handler,
            chained_function: trailer.chained_function,
            handler_data: trailer.handler_data,
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
        const N: usize = UnwindInfo::MIN_SIZE;
        const SLOT: usize = size_of::<UnwindCodeSlot>();
        self.validate()?;
        let trailer_size =
            trailer_size(self.exception_handler, self.chained_function, handler_data)?;
        let count_of_codes = u8::try_from(self.unwind_codes.len())
            .map_err(|_| Error::invalid_data_directory("more than 255 unwind-code slots"))?;
        let codes_end = unwind_codes_end(count_of_codes);
        let total_size = codes_end
            .checked_add(trailer_size)
            .ok_or_else(|| Error::invalid_data_directory("unwind-info size overflow"))?;

        let mut buf = Vec::with_capacity(total_size);
        let mut header = [0; N];
        put_u8::<N, { offset_of!(UnwindInfoHeader, version_and_flags) }>(
            &mut header,
            self.version_flags,
        );
        put_u8::<N, { offset_of!(UnwindInfoHeader, size_of_prolog) }>(
            &mut header,
            self.size_of_prolog,
        );
        put_u8::<N, { offset_of!(UnwindInfoHeader, count_of_codes) }>(&mut header, count_of_codes);
        put_u8::<N, { offset_of!(UnwindInfoHeader, frame_register_and_offset) }>(
            &mut header,
            self.frame_reg_and_offset,
        );
        buf.extend_from_slice(&header);
        for code in &self.unwind_codes {
            let mut slot = [0; SLOT];
            put_u8::<SLOT, { offset_of!(UnwindCodeSlot, code_offset) }>(
                &mut slot,
                code.code_offset,
            );
            put_u8::<SLOT, { offset_of!(UnwindCodeSlot, unwind_op_and_info) }>(
                &mut slot,
                code.op_and_info,
            );
            buf.extend_from_slice(&slot);
        }
        // Pad the unwind-code array to a multiple of 4 bytes.
        buf.resize(codes_end, 0);

        write_trailer(
            &mut buf,
            self.exception_handler,
            self.chained_function,
            handler_data,
        )?;
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
        validate_trailer(
            self.flags(),
            self.exception_handler,
            self.chained_function,
            &self.handler_data,
        )
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
        validate_handler_flags(flags)
    }
}

/// The handler or the chained `RUNTIME_FUNCTION` that follows the unwind operations.
struct Trailer {
    exception_handler: Option<u32>,
    chained_function: Option<RuntimeFunction>,
    handler_data: Vec<u8>,
}

/// Read the handler or the chained `RUNTIME_FUNCTION` at `trailer_offset` of `data`.
///
/// `flags` are the 5 flag bits of the header. The handler data gets all bytes of `data` after
/// the handler RVA.
fn parse_trailer(data: &[u8], trailer_offset: usize, flags: u8) -> Result<Trailer> {
    let trailer = data.get(trailer_offset..).unwrap_or_default();
    let mut parsed = Trailer {
        exception_handler: None,
        chained_function: None,
        handler_data: Vec::new(),
    };
    if (flags & UNW_FLAG_CHAININFO) != 0 {
        if trailer.len() < RuntimeFunction::SIZE {
            return Err(Error::buffer_too_small(
                trailer_offset + RuntimeFunction::SIZE,
                data.len(),
            ));
        }
        parsed.chained_function = Some(RuntimeFunction::parse(trailer)?);
    } else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0 {
        let mut language_data = trailer;
        let handler = language_data
            .read_u32_le()
            .map_err(|_| Error::buffer_too_small(trailer_offset + HANDLER_RVA_SIZE, data.len()))?;
        parsed.exception_handler = Some(handler);
        parsed.handler_data.extend_from_slice(language_data);
    }
    Ok(parsed)
}

/// Return the size of the trailer that [`write_trailer`] writes.
///
/// # Errors
/// Returns an error in these conditions:
/// - `handler_data` is nonempty and the record has no handler.
/// - A size calculation overflows.
fn trailer_size(
    exception_handler: Option<u32>,
    chained_function: Option<RuntimeFunction>,
    handler_data: &[u8],
) -> Result<usize> {
    if !handler_data.is_empty() && exception_handler.is_none() {
        return Err(Error::invalid_data_directory(
            "borrowed exception-handler data present without a handler",
        ));
    }
    let chained_size = chained_function.map_or(0, |_| RuntimeFunction::SIZE);
    let handler_size = exception_handler
        .map(|_| {
            HANDLER_RVA_SIZE
                .checked_add(handler_data.len())
                .ok_or_else(|| Error::invalid_data_directory("unwind handler size overflow"))
        })
        .transpose()?
        .unwrap_or(0);
    Ok(chained_size.max(handler_size))
}

/// Write the chained `RUNTIME_FUNCTION`, or the handler RVA and `handler_data`.
fn write_trailer(
    buf: &mut Vec<u8>,
    exception_handler: Option<u32>,
    chained_function: Option<RuntimeFunction>,
    handler_data: &[u8],
) -> Result<()> {
    if let Some(chained) = chained_function {
        buf.extend_from_slice(&chained.to_bytes());
    } else if let Some(handler) = exception_handler {
        buf.write_u32_le(handler)?;
        buf.extend_from_slice(handler_data);
    }
    Ok(())
}

/// Check that the handler or chain data agrees with the 5 flag bits `flags`.
///
/// # Errors
/// Returns an error if the handler or chain data does not agree with the flags.
fn validate_trailer(
    flags: u8,
    exception_handler: Option<u32>,
    chained_function: Option<RuntimeFunction>,
    handler_data: &[u8],
) -> Result<()> {
    let chained = (flags & UNW_FLAG_CHAININFO) != 0;
    let handled = (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0;
    if chained {
        if chained_function.is_none() {
            return Err(Error::invalid_data_directory(
                "UNW_FLAG_CHAININFO requires a complete RUNTIME_FUNCTION record",
            ));
        }
        if exception_handler.is_some() || !handler_data.is_empty() {
            return Err(Error::invalid_data_directory(
                "chained unwind info cannot contain exception-handler data",
            ));
        }
    } else if chained_function.is_some() {
        return Err(Error::invalid_data_directory(
            "chained runtime function present without UNW_FLAG_CHAININFO",
        ));
    }

    if handled {
        if exception_handler.is_none() {
            return Err(Error::invalid_data_directory(
                "unwind handler flag requires an exception-handler RVA",
            ));
        }
    } else if exception_handler.is_some() || !handler_data.is_empty() {
        return Err(Error::invalid_data_directory(
            "exception-handler data present without a handler flag",
        ));
    }
    Ok(())
}

/// Check that the 5 flag bits `flags` do not combine `UNW_FLAG_CHAININFO` with a handler flag.
fn validate_handler_flags(flags: u8) -> Result<()> {
    if flags & UNW_FLAG_CHAININFO != 0 && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        return Err(Error::invalid_data_directory(
            "UNW_FLAG_CHAININFO cannot be combined with handler flags",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
