//! The `UNWIND_INFO_V3` record and its epilog descriptors.

use core::mem::{offset_of, size_of};

use nostdio::{ReadLe, WriteLe};

use super::{UNW_FLAG_LARGE, VERSION, WindOp, decode_ops};
use crate::exception::RuntimeFunction;
use crate::exception::unwind::{
    UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, parse_trailer, trailer_size,
    validate_handler_flags, validate_trailer, write_trailer,
};
use crate::parse_utils::{le_u8, le_u16, put_u8, put_u16};
use crate::prelude::*;
use crate::{Error, Result};

/// The layout of the 4-byte header of the x64 `UNWIND_INFO_V3`.
///
/// `winnt.h` does not define the structure. The Microsoft "x64 Unwind Information V3"
/// specification does. The version (3 bits) and the flags (5 bits) share the first byte. The
/// prolog operation count (5 bits) and the epilog count (3 bits) share the last byte.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
struct UnwindInfoV3Header {
    version_and_flags: u8,
    size_of_prolog: u8,
    payload_words: u8,
    ops_and_epilogs: u8,
}

/// The layout of `EPILOG_INFO_V3`. The specification packs it to 1 byte.
///
/// The flags (3 bits) and the operation count (5 bits) share the first byte.
#[repr(C, packed(1))]
struct EpilogInfoV3 {
    flags_and_ops: u8,
    epilog_offset: i16,
}

/// The layout of `EPILOG_INFO_EX_V3`. The specification packs it to 1 byte.
#[repr(C, packed(1))]
struct EpilogInfoExV3 {
    first_op: u16,
    ip_offset_of_last_instruction: u8,
}

/// The layout of `EPILOG_INFO_LARGE_EX_V3`.
#[repr(C)]
struct EpilogInfoLargeExV3 {
    first_op: u16,
    ip_offset_of_last_instruction: u16,
}

const _: () = {
    assert!(size_of::<UnwindInfoV3Header>() == 4);
    assert!(offset_of!(UnwindInfoV3Header, payload_words) == 2);
    assert!(offset_of!(UnwindInfoV3Header, ops_and_epilogs) == 3);
    assert!(size_of::<EpilogInfoV3>() == 3);
    assert!(offset_of!(EpilogInfoV3, epilog_offset) == 1);
    assert!(size_of::<EpilogInfoExV3>() == 3);
    assert!(offset_of!(EpilogInfoExV3, ip_offset_of_last_instruction) == 2);
    assert!(size_of::<EpilogInfoLargeExV3>() == 4);
    assert!(offset_of!(EpilogInfoLargeExV3, ip_offset_of_last_instruction) == 2);
};

/// The header flags that version 3 defines. Bit 4 is reserved.
const SUPPORTED_FLAGS: u8 =
    UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO | UNW_FLAG_LARGE;
/// The epilog returns to the parent fragment (`EPILOG_INFO_PARENT_FRAGMENT_TRANSFER`).
const EPILOG_INFO_PARENT_FRAGMENT_TRANSFER: u8 = 0x01;
/// The epilog has 16-bit IP offsets (`EPILOG_INFO_LARGE`).
const EPILOG_INFO_LARGE: u8 = 0x02;
/// The epilog flags that the specification defines. Bit 2 is reserved.
const EPILOG_FLAGS: u8 = EPILOG_INFO_PARENT_FRAGMENT_TRANSFER | EPILOG_INFO_LARGE;
/// The largest operation count of a prolog or of an epilog (5 bits).
const MAX_OPS: usize = 31;
/// The largest epilog count (3 bits).
const MAX_EPILOGS: usize = 7;

/// The operations of a full x64 version 3 epilog descriptor.
///
/// The value holds the `EPILOG_INFO_EX_V3` or `EPILOG_INFO_LARGE_EX_V3` extension, and the IP
/// offset array that follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpilogOpsV3 {
    /// The byte offset of the first WOD of the epilog in the WOD pool (`FirstOp`).
    ///
    /// This is a byte offset, not a WOD index. An epilog can share WODs with the prolog and
    /// with other epilogs.
    pub first_op: u16,
    /// The offset of the last epilog instruction from the epilog start
    /// (`IpOffsetOfLastInstruction`). This instruction is usually a RET or a JMP.
    pub last_instruction: u16,
    /// The offset of each epilog instruction with a WOD, from the epilog start.
    ///
    /// The length is the operation count of the epilog (1 to 31). The first entry is the
    /// operation closest to the function body.
    pub ip_offsets: Vec<u16>,
}

/// One x64 version 3 epilog descriptor (`EPILOG_INFO_V3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpilogV3 {
    /// The 3 flag bits.
    ///
    /// - Bit 0 (`EPILOG_INFO_PARENT_FRAGMENT_TRANSFER`): the epilog transfers control to the
    ///   parent fragment, and does not return to the caller.
    /// - Bit 1 (`EPILOG_INFO_LARGE`): `last_instruction` and the IP offsets have 16 bits.
    /// - Bit 2 is reserved.
    pub flags: u8,
    /// The offset of the epilog start (`EpilogOffset`).
    ///
    /// For the first epilog, a positive value is an offset from the fragment start. A negative
    /// value is an offset from the fragment tail, the first byte after the fragment. For each
    /// other epilog, the value is the distance from the start of the previous epilog. All
    /// nonzero offsets of a record have the same sign.
    pub offset: i16,
    /// The operations, or `None` if the epilog inherits them (`NumberOfOps` is 0).
    ///
    /// An epilog inherits the operations of the nearest epilog before it that has operations.
    /// Bits 0 and 1 of the two flag values must be equal. The first epilog cannot inherit.
    pub ops: Option<EpilogOpsV3>,
}

impl EpilogV3 {
    /// Return `true` if the epilog has `EPILOG_INFO_LARGE`.
    fn is_large(&self) -> bool {
        self.flags & EPILOG_INFO_LARGE != 0
    }

    /// Return the encoded size of the descriptor, its extension and its IP offsets.
    fn encoded_len(&self) -> Option<usize> {
        let Some(ops) = &self.ops else {
            return Some(size_of::<EpilogInfoV3>());
        };
        let extension = if self.is_large() {
            size_of::<EpilogInfoLargeExV3>()
        } else {
            size_of::<EpilogInfoExV3>()
        };
        ops.ip_offsets
            .len()
            .checked_mul(ip_offset_size(self.is_large()))?
            .checked_add(size_of::<EpilogInfoV3>() + extension)
    }
}

/// An x64 version 3 unwind information record (`UNWIND_INFO_V3`).
///
/// The record has no separate fields for `NumberOfOps`, `NumberOfEpilogs` and `PayloadWords`.
/// The serializer calculates them from `prolog_ip_offsets`, `epilogs` and `pool`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnwindInfoV3 {
    /// The 5 flag bits of the header (`UNW_FLAG_*`). Bit 4 is reserved.
    pub flags: u8,
    /// The size of the prolog in bytes. A value above 255 requires [`UNW_FLAG_LARGE`].
    pub size_of_prolog: u16,
    /// The offset of each prolog instruction with a WOD, from the fragment start.
    ///
    /// Each offset is the start of the instruction. A version 1 or 2 unwind code gives the end
    /// of its instruction instead ([`crate::UnwindCode::code_offset`]). The length is
    /// `NumberOfOps` (0 to 31). The first entry is the operation closest to the function body.
    /// An offset above 255 requires [`UNW_FLAG_LARGE`].
    pub prolog_ip_offsets: Vec<u16>,
    /// The epilog descriptors (0 to 7).
    pub epilogs: Vec<EpilogV3>,
    /// The WOD pool: all payload bytes after the epilog descriptors.
    ///
    /// The prolog WODs start at byte 0. The pool keeps its padding bytes, so a round trip is
    /// exact. The payload size must be a multiple of 2 bytes. Thus give the pool the length
    /// that makes the payload a whole number of 16-bit words.
    pub pool: Vec<u8>,
    /// Exception handler RVA (if `UNW_FLAG_EHANDLER` or `UNW_FLAG_UHANDLER`).
    pub exception_handler: Option<u32>,
    /// The chained `RUNTIME_FUNCTION` entry (if `UNW_FLAG_CHAININFO`).
    pub chained_function: Option<RuntimeFunction>,
    /// Language-specific bytes that follow the exception handler RVA.
    ///
    /// The rule of [`UnwindInfo::handler_data`](crate::UnwindInfo::handler_data) applies:
    /// [`Self::parse`] keeps all bytes of its input after the handler RVA.
    pub handler_data: Vec<u8>,
}

impl UnwindInfoV3 {
    /// Parse an `UNWIND_INFO_V3` record from the bytes at its RVA.
    ///
    /// If the record has a handler, [`Self::handler_data`] gets all bytes of `data` after the
    /// handler RVA. Thus `data` must end where the language-specific data ends.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - The buffer is too short for the header, the payload, or the trailing handler or
    ///   chain data.
    /// - The version is not 3, or the flags are unsupported or inconsistent.
    /// - The epilog descriptors do not fit in the payload.
    /// - The record fails [`Self::validate`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        const N: usize = size_of::<UnwindInfoV3Header>();
        let Some((header, after_header)) = data.split_first_chunk::<N>() else {
            return Err(Error::buffer_too_small(N, data.len()));
        };
        let version_and_flags =
            le_u8::<N, { offset_of!(UnwindInfoV3Header, version_and_flags) }>(header);
        let prolog_low = le_u8::<N, { offset_of!(UnwindInfoV3Header, size_of_prolog) }>(header);
        let payload_words = le_u8::<N, { offset_of!(UnwindInfoV3Header, payload_words) }>(header);
        let ops_and_epilogs =
            le_u8::<N, { offset_of!(UnwindInfoV3Header, ops_and_epilogs) }>(header);
        validate_header(version_and_flags)?;
        let flags = version_and_flags >> 3;
        let large = flags & UNW_FLAG_LARGE != 0;

        let payload_size = usize::from(payload_words) * size_of::<u16>();
        let Some(mut payload) = after_header.get(..payload_size) else {
            return Err(Error::buffer_too_small(N + payload_size, data.len()));
        };
        let prolog_high = if large {
            payload.read_u8_le().map_err(|_| payload_overrun())?
        } else {
            0
        };
        let prolog_ip_offsets = read_ip_offsets(&mut payload, ops_and_epilogs & 0x1F, large)?;
        let epilogs = (0..ops_and_epilogs >> 5)
            .map(|_| read_epilog(&mut payload))
            .collect::<Result<Vec<_>>>()?;

        let trailer = parse_trailer(data, trailer_offset(payload_words), flags)?;
        let info = Self {
            flags,
            size_of_prolog: u16::from_le_bytes([prolog_low, prolog_high]),
            prolog_ip_offsets,
            epilogs,
            pool: payload.to_vec(),
            exception_handler: trailer.exception_handler,
            chained_function: trailer.chained_function,
            handler_data: trailer.handler_data,
        };
        info.validate()?;
        Ok(info)
    }

    /// Check the record.
    ///
    /// If the record passes this check, it serializes, and all its WOD lists decode.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - The flags are unsupported, or the handler or chain data does not agree with them.
    /// - The record has more than 31 prolog operations or more than 7 epilogs.
    /// - The prolog size or a prolog IP offset is above 255 without [`UNW_FLAG_LARGE`].
    /// - An epilog descriptor breaks a rule of [`EpilogV3`]. A full descriptor must have 1 to
    ///   31 operations, and an offset above 255 requires `EPILOG_INFO_LARGE`.
    /// - The payload size is odd or larger than 255 16-bit words.
    /// - A prolog or epilog WOD list does not decode in the WOD pool.
    pub fn validate(&self) -> Result<()> {
        validate_flags(self.flags)?;
        validate_trailer(
            self.flags,
            self.exception_handler,
            self.chained_function,
            &self.handler_data,
        )?;
        self.validate_prolog()?;
        validate_epilogs(&self.epilogs)?;
        payload_words(self.payload_len()?)?;
        self.prolog_ops()?;
        for epilog in &self.epilogs {
            if let Some(ops) = &epilog.ops {
                decode_ops(&self.pool, ops.first_op, &ops.ip_offsets)?;
            }
        }
        Ok(())
    }

    /// Serialize the record to bytes after validation.
    ///
    /// The bytes are the header, the payload and the handler or chain data, if the record has
    /// it. Zero bytes align the handler or chain data to 4 bytes. Without handler or chain
    /// data, the bytes end at the end of the payload.
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
        const N: usize = size_of::<UnwindInfoV3Header>();
        self.validate()?;
        let trailer_size =
            trailer_size(self.exception_handler, self.chained_function, handler_data)?;
        let payload_len = self.payload_len()?;
        let payload_words = payload_words(payload_len)?;
        let trailer_offset = trailer_offset(payload_words);
        // A record without handler or chain data has a trailer size of 0.
        let total_size = if trailer_size == 0 {
            N + payload_len
        } else {
            trailer_offset
                .checked_add(trailer_size)
                .ok_or_else(|| Error::invalid_data_directory("unwind-info size overflow"))?
        };
        let large = self.is_large();
        let [prolog_low, prolog_high] = self.size_of_prolog.to_le_bytes();
        let ops = to_u8(self.prolog_ip_offsets.len())?;
        let epilogs = to_u8(self.epilogs.len())?;

        let mut buf = Vec::with_capacity(total_size);
        let mut header = [0; N];
        put_u8::<N, { offset_of!(UnwindInfoV3Header, version_and_flags) }>(
            &mut header,
            VERSION | (self.flags << 3),
        );
        put_u8::<N, { offset_of!(UnwindInfoV3Header, size_of_prolog) }>(&mut header, prolog_low);
        put_u8::<N, { offset_of!(UnwindInfoV3Header, payload_words) }>(&mut header, payload_words);
        put_u8::<N, { offset_of!(UnwindInfoV3Header, ops_and_epilogs) }>(
            &mut header,
            ops | (epilogs << 5),
        );
        buf.extend_from_slice(&header);
        if large {
            buf.push(prolog_high);
        }
        write_ip_offsets(&mut buf, &self.prolog_ip_offsets, large)?;
        for epilog in &self.epilogs {
            write_epilog(&mut buf, epilog)?;
        }
        buf.extend_from_slice(&self.pool);
        if trailer_size != 0 {
            buf.resize(trailer_offset, 0);
            write_trailer(
                &mut buf,
                self.exception_handler,
                self.chained_function,
                handler_data,
            )?;
        }
        Ok(buf)
    }

    /// Return `true` if the record has an exception handler or a termination handler.
    #[must_use]
    pub fn has_exception_handler(&self) -> bool {
        self.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0
    }

    /// Return `true` if the record chains to other unwind information.
    #[must_use]
    pub fn is_chained(&self) -> bool {
        self.flags & UNW_FLAG_CHAININFO != 0
    }

    /// Decode the prolog WODs.
    ///
    /// The prolog has one WOD for each prolog IP offset. Its WODs start at byte 0 of the WOD
    /// pool. Returns each IP offset (the start of its instruction) with its operation, in
    /// stored order.
    ///
    /// # Errors
    /// Returns an error if a WOD does not decode in the WOD pool.
    pub fn prolog_ops(&self) -> Result<Vec<(u16, WindOp)>> {
        decode_ops(&self.pool, 0, &self.prolog_ip_offsets)
    }

    /// Return the operation fields that epilog `index` uses.
    ///
    /// An epilog without its own operations (`NumberOfOps` is 0) inherits the fields of the
    /// nearest epilog before it that has operations. For such an epilog, the method returns the
    /// inherited fields.
    ///
    /// # Errors
    /// Returns an error if the record has no epilog `index`, or if the epilog inherits and no
    /// epilog before it has operations.
    pub fn epilog_fields(&self, index: usize) -> Result<&EpilogOpsV3> {
        let epilogs = self.epilogs.get(..=index).ok_or_else(|| {
            Error::invalid_data_directory(format!("UNWIND_INFO_V3 has no epilog {index}"))
        })?;
        epilogs
            .iter()
            .rev()
            .find_map(|epilog| epilog.ops.as_ref())
            .ok_or_else(|| no_inherit_source(index))
    }

    /// Decode the WODs of epilog `index`.
    ///
    /// The WODs start at [`EpilogOpsV3::first_op`] of the fields that the epilog uses
    /// ([`Self::epilog_fields`]). Returns each IP offset (from the epilog start, as stored) with
    /// its operation, in stored order.
    ///
    /// # Errors
    /// Returns an error if [`Self::epilog_fields`] fails or a WOD does not decode in the WOD
    /// pool.
    pub fn epilog_ops(&self, index: usize) -> Result<Vec<(u16, WindOp)>> {
        let fields = self.epilog_fields(index)?;
        decode_ops(&self.pool, fields.first_op, &fields.ip_offsets)
    }

    /// Return `true` if the record has [`UNW_FLAG_LARGE`].
    fn is_large(&self) -> bool {
        self.flags & UNW_FLAG_LARGE != 0
    }

    /// Check the prolog operation count, the prolog size and the prolog IP offsets.
    fn validate_prolog(&self) -> Result<()> {
        if self.prolog_ip_offsets.len() > MAX_OPS {
            return Err(Error::invalid_data_directory(
                "UNWIND_INFO_V3 has more than 31 prolog operations",
            ));
        }
        if !self.is_large() {
            let limit = u16::from(u8::MAX);
            if self.size_of_prolog > limit {
                return Err(Error::invalid_data_directory(
                    "a prolog size above 255 bytes requires UNW_FLAG_LARGE",
                ));
            }
            if self.prolog_ip_offsets.iter().any(|&offset| offset > limit) {
                return Err(Error::invalid_data_directory(
                    "a prolog IP offset above 255 requires UNW_FLAG_LARGE",
                ));
            }
        }
        Ok(())
    }

    /// Return the payload size in bytes.
    fn payload_len(&self) -> Result<usize> {
        let large = self.is_large();
        let prolog_high = if large { size_of::<u8>() } else { 0 };
        let prolog = self
            .prolog_ip_offsets
            .len()
            .checked_mul(ip_offset_size(large));
        [Some(prolog_high), prolog, Some(self.pool.len())]
            .into_iter()
            .chain(self.epilogs.iter().map(EpilogV3::encoded_len))
            .try_fold(0_usize, |total, part| total.checked_add(part?))
            .ok_or_else(|| Error::invalid_data_directory("UNWIND_INFO_V3 payload size overflow"))
    }
}

/// Check the version and the flags of the first header byte.
fn validate_header(version_and_flags: u8) -> Result<()> {
    let version = version_and_flags & 0x07;
    if version != VERSION {
        return Err(Error::invalid_data_directory(format!(
            "unsupported x64 unwind version {version}"
        )));
    }
    validate_flags(version_and_flags >> 3)
}

/// Check the 5 flag bits `flags` of a version 3 header.
fn validate_flags(flags: u8) -> Result<()> {
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err(Error::invalid_data_directory(format!(
            "unsupported x64 unwind flags {flags:#x}"
        )));
    }
    validate_handler_flags(flags)
}

/// Check the epilog count, the epilog flags, the inherited epilogs and the offset signs.
fn validate_epilogs(epilogs: &[EpilogV3]) -> Result<()> {
    if epilogs.len() > MAX_EPILOGS {
        return Err(Error::invalid_data_directory(
            "UNWIND_INFO_V3 has more than 7 epilogs",
        ));
    }
    // The flags of the nearest epilog that has operations.
    let mut source_flags = None;
    // The sign of the first nonzero epilog offset.
    let mut sign = 0;
    for (index, epilog) in epilogs.iter().enumerate() {
        if epilog.flags & !EPILOG_FLAGS != 0 {
            return Err(Error::invalid_data_directory(format!(
                "epilog {index} has unsupported flags {:#x}",
                epilog.flags
            )));
        }
        if let Some(ops) = &epilog.ops {
            validate_epilog_ops(index, epilog, ops)?;
            source_flags = Some(epilog.flags);
        } else {
            let source = source_flags.ok_or_else(|| no_inherit_source(index))?;
            if (source ^ epilog.flags) & EPILOG_FLAGS != 0 {
                return Err(Error::invalid_data_directory(format!(
                    "epilog {index} has flags that differ from the epilog it inherits from"
                )));
            }
        }
        let offset_sign = epilog.offset.signum();
        if offset_sign != 0 {
            if sign == 0 {
                sign = offset_sign;
            } else if offset_sign != sign {
                return Err(Error::invalid_data_directory(format!(
                    "epilog {index} changes the sign of the epilog offsets"
                )));
            }
        }
    }
    Ok(())
}

/// Check the operation count and the offset widths of the full epilog `epilog`.
fn validate_epilog_ops(index: usize, epilog: &EpilogV3, ops: &EpilogOpsV3) -> Result<()> {
    if ops.ip_offsets.is_empty() || ops.ip_offsets.len() > MAX_OPS {
        return Err(Error::invalid_data_directory(format!(
            "epilog {index} must have 1 to 31 operations"
        )));
    }
    let limit = u16::from(u8::MAX);
    if !epilog.is_large()
        && (ops.last_instruction > limit || ops.ip_offsets.iter().any(|&offset| offset > limit))
    {
        return Err(Error::invalid_data_directory(format!(
            "epilog {index} has an offset above 255 without EPILOG_INFO_LARGE"
        )));
    }
    Ok(())
}

/// Return the error for the epilog at `index` that inherits from no epilog.
fn no_inherit_source(index: usize) -> Error {
    Error::invalid_data_directory(format!(
        "epilog {index} inherits its operations, but no epilog before it has operations"
    ))
}

/// Return the size of one IP offset: 2 bytes if `large`, else 1 byte.
fn ip_offset_size(large: bool) -> usize {
    if large {
        size_of::<u16>()
    } else {
        size_of::<u8>()
    }
}

/// Return the payload size in 16-bit words.
fn payload_words(payload_len: usize) -> Result<u8> {
    if !payload_len.is_multiple_of(size_of::<u16>()) {
        return Err(Error::invalid_data_directory(format!(
            "the UNWIND_INFO_V3 payload has an odd size of {payload_len} bytes"
        )));
    }
    u8::try_from(payload_len / size_of::<u16>()).map_err(|_| {
        Error::invalid_data_directory(format!(
            "the UNWIND_INFO_V3 payload of {payload_len} bytes is larger than 255 16-bit words"
        ))
    })
}

/// Return the offset of the handler RVA or of the chained `RUNTIME_FUNCTION`.
///
/// The offset is the end of the payload, aligned up to 4 bytes. A `u8` word count gives at most
/// 514 bytes, so the calculation cannot overflow.
fn trailer_offset(payload_words: u8) -> usize {
    (size_of::<UnwindInfoV3Header>() + usize::from(payload_words) * size_of::<u16>())
        .next_multiple_of(size_of::<u32>())
}

/// Convert a count or an offset that [`UnwindInfoV3::validate`] checked to `u8`.
fn to_u8<T: TryInto<u8>>(value: T) -> Result<u8> {
    value.try_into().map_err(|_| {
        Error::invalid_data_directory("an UNWIND_INFO_V3 field does not fit in 8 bits")
    })
}

/// Return the error for a payload that ends before the end of its descriptors.
fn payload_overrun() -> Error {
    Error::invalid_data_directory("the UNWIND_INFO_V3 descriptors do not fit in the payload")
}

/// Remove a fixed structure of `N` bytes from the start of `cursor`, and return it.
fn take<'a, const N: usize>(cursor: &mut &'a [u8]) -> Result<&'a [u8; N]> {
    let (raw, rest) = cursor
        .split_first_chunk::<N>()
        .ok_or_else(payload_overrun)?;
    *cursor = rest;
    Ok(raw)
}

/// Read `count` IP offsets of 16 bits if `large`, else of 8 bits.
fn read_ip_offsets(cursor: &mut &[u8], count: u8, large: bool) -> Result<Vec<u16>> {
    (0..count)
        .map(|_| {
            let offset = if large {
                cursor.read_u16_le()
            } else {
                cursor.read_u8_le().map(u16::from)
            };
            offset.map_err(|_| payload_overrun())
        })
        .collect()
}

/// Read one epilog descriptor with its extension and its IP offsets.
fn read_epilog(cursor: &mut &[u8]) -> Result<EpilogV3> {
    const N: usize = size_of::<EpilogInfoV3>();
    let raw = take::<N>(cursor)?;
    let flags_and_ops = le_u8::<N, { offset_of!(EpilogInfoV3, flags_and_ops) }>(raw);
    let offset = le_u16::<N, { offset_of!(EpilogInfoV3, epilog_offset) }>(raw).cast_signed();
    let flags = flags_and_ops & 0x07;
    let count = flags_and_ops >> 3;
    if count == 0 {
        return Ok(EpilogV3 {
            flags,
            offset,
            ops: None,
        });
    }
    let large = flags & EPILOG_INFO_LARGE != 0;
    let (first_op, last_instruction) = if large {
        const L: usize = size_of::<EpilogInfoLargeExV3>();
        let raw = take::<L>(cursor)?;
        (
            le_u16::<L, { offset_of!(EpilogInfoLargeExV3, first_op) }>(raw),
            le_u16::<L, { offset_of!(EpilogInfoLargeExV3, ip_offset_of_last_instruction) }>(raw),
        )
    } else {
        const S: usize = size_of::<EpilogInfoExV3>();
        const LAST: usize = offset_of!(EpilogInfoExV3, ip_offset_of_last_instruction);
        let raw = take::<S>(cursor)?;
        (
            le_u16::<S, { offset_of!(EpilogInfoExV3, first_op) }>(raw),
            u16::from(le_u8::<S, LAST>(raw)),
        )
    };
    let ip_offsets = read_ip_offsets(cursor, count, large)?;
    Ok(EpilogV3 {
        flags,
        offset,
        ops: Some(EpilogOpsV3 {
            first_op,
            last_instruction,
            ip_offsets,
        }),
    })
}

/// Write IP offsets of 16 bits if `large`, else of 8 bits.
fn write_ip_offsets(buf: &mut Vec<u8>, offsets: &[u16], large: bool) -> Result<()> {
    for &offset in offsets {
        if large {
            buf.write_u16_le(offset)?;
        } else {
            buf.push(to_u8(offset)?);
        }
    }
    Ok(())
}

/// Write one epilog descriptor with its extension and its IP offsets.
fn write_epilog(buf: &mut Vec<u8>, epilog: &EpilogV3) -> Result<()> {
    const N: usize = size_of::<EpilogInfoV3>();
    let count = to_u8(epilog.ops.as_ref().map_or(0, |ops| ops.ip_offsets.len()))?;
    let mut raw = [0; N];
    put_u8::<N, { offset_of!(EpilogInfoV3, flags_and_ops) }>(&mut raw, epilog.flags | (count << 3));
    put_u16::<N, { offset_of!(EpilogInfoV3, epilog_offset) }>(
        &mut raw,
        epilog.offset.cast_unsigned(),
    );
    buf.extend_from_slice(&raw);
    let Some(ops) = &epilog.ops else {
        return Ok(());
    };
    if epilog.is_large() {
        const L: usize = size_of::<EpilogInfoLargeExV3>();
        let mut raw = [0; L];
        put_u16::<L, { offset_of!(EpilogInfoLargeExV3, first_op) }>(&mut raw, ops.first_op);
        put_u16::<L, { offset_of!(EpilogInfoLargeExV3, ip_offset_of_last_instruction) }>(
            &mut raw,
            ops.last_instruction,
        );
        buf.extend_from_slice(&raw);
    } else {
        const S: usize = size_of::<EpilogInfoExV3>();
        let mut raw = [0; S];
        put_u16::<S, { offset_of!(EpilogInfoExV3, first_op) }>(&mut raw, ops.first_op);
        put_u8::<S, { offset_of!(EpilogInfoExV3, ip_offset_of_last_instruction) }>(
            &mut raw,
            to_u8(ops.last_instruction)?,
        );
        buf.extend_from_slice(&raw);
    }
    write_ip_offsets(buf, &ops.ip_offsets, epilog.is_large())
}
