//! x64 `UNWIND_INFO_V3` records and their winding operation descriptors (WODs).
//!
//! The Microsoft specification "x64 Unwind Information V3" defines the format. Version 3 keeps
//! the 4-byte header of versions 1 and 2, and the location of the handler or the chained
//! `RUNTIME_FUNCTION`. A packed payload replaces the unwind code slots. The payload holds, in
//! this order:
//!
//! 1. The high byte of the prolog size, if the header has `UNW_FLAG_LARGE`.
//! 2. The prolog IP offsets.
//! 3. The epilog descriptors (`EPILOG_INFO_V3`), each with its IP offsets.
//! 4. The WOD pool: all remaining payload bytes.

use core::mem::{offset_of, size_of};

use super::{RuntimeFunction, UnwindInfo};
use crate::parse_utils::{le_u8, le_u16, le_u32, put_u8, put_u16, put_u32};
use crate::prelude::*;
use crate::{Error, Result};

mod record;

pub use record::{EpilogOpsV3, EpilogV3, ResolvedEpilogV3, UnwindInfoV3};

/// The layout of a WOD with a byte operand: `WOD_SET_FPREG`, `WOD_PUSH2` and
/// `WOD_PUSH_CANONICAL_FRAME`.
///
/// The specification gives the WOD layouts bit by bit. It does not name a structure for them.
#[repr(C)]
struct WodByteOperand {
    opcode: u8,
    operand: u8,
}

/// The layout of a WOD with a 16-bit operand: `WOD_ALLOC_LARGE`, `WOD_SAVE_NONVOL` and
/// `WOD_SAVE_XMM128`. WODs have no alignment.
#[repr(C, packed(1))]
struct WodWordOperand {
    opcode: u8,
    operand: u16,
}

/// The layout of a WOD with a 32-bit operand: `WOD_ALLOC_HUGE`, `WOD_SAVE_NONVOL_FAR` and
/// `WOD_SAVE_XMM128_FAR`. WODs have no alignment.
#[repr(C, packed(1))]
struct WodDwordOperand {
    opcode: u8,
    operand: u32,
}

const _: () = {
    assert!(size_of::<WodByteOperand>() == 2);
    assert!(offset_of!(WodByteOperand, operand) == 1);
    assert!(size_of::<WodWordOperand>() == 3);
    assert!(offset_of!(WodWordOperand, operand) == 1);
    assert!(size_of::<WodDwordOperand>() == 5);
    assert!(offset_of!(WodDwordOperand, operand) == 1);
};

/// The prolog is larger than 255 bytes (`UNW_FLAG_LARGE`).
///
/// Only version 3 of `UNWIND_INFO` defines this flag. With it, the payload starts with the high
/// byte of the prolog size, and each prolog IP offset has 16 bits.
pub const UNW_FLAG_LARGE: u8 = 0x08;

/// The x64 unwind version that [`UnwindInfoV3`] holds.
const VERSION: u8 = 3;
/// The size in bytes of one stack slot.
const STACK_SLOT: u32 = 8;

/// `WOD_SET_FPREG` (8-bit opcode).
const OP_SET_FPREG: u8 = 0x00;
/// `WOD_ALLOC_HUGE` (8-bit opcode).
const OP_ALLOC_HUGE: u8 = 0x01;
/// `WOD_ALLOC_LARGE` (8-bit opcode).
const OP_ALLOC_LARGE: u8 = 0x02;
/// `WOD_PUSH_CANONICAL_FRAME` (8-bit opcode).
const OP_PUSH_CANONICAL_FRAME: u8 = 0x03;
/// `WOD_PUSH` (3-bit opcode).
const OP_PUSH: u8 = 0x04;
/// `WOD_SAVE_NONVOL_FAR` (3-bit opcode).
const OP_SAVE_NONVOL_FAR: u8 = 0x05;
/// `WOD_SAVE_NONVOL` (3-bit opcode).
const OP_SAVE_NONVOL: u8 = 0x06;
/// `WOD_PUSH_CONSECUTIVE_2` (3-bit opcode).
const OP_PUSH_CONSECUTIVE_2: u8 = 0x07;
/// `WOD_ALLOC_SMALL` (4-bit opcode).
const OP_ALLOC_SMALL: u8 = 0x08;
/// `WOD_SAVE_XMM128_FAR` (4-bit opcode).
const OP_SAVE_XMM128_FAR: u8 = 0x09;
/// `WOD_SAVE_XMM128` (4-bit opcode).
const OP_SAVE_XMM128: u8 = 0x0A;
/// `WOD_PUSH2` (6-bit opcode).
const OP_PUSH2: u8 = 0x20;

/// One x64 version 3 winding operation descriptor (WOD).
///
/// A WOD describes one prolog or epilog instruction that changes the stack or saves a
/// register. It has 1 to 5 bytes. The integer register numbers are the AMD64 numbers: 0 is
/// RAX, 3 is RBX, 4 is RSP, and 16 to 31 are the APX registers R16 to R31. An XMM register
/// number is 0 to 15.
///
/// The enum is `#[non_exhaustive]`: a later version of the specification can add operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WindOp {
    /// Establish the frame register (`WOD_SET_FPREG`): `register = RSP + offset * 16`.
    SetFrameRegister {
        /// The frame register (4 bits).
        register: u8,
        /// The offset from RSP, scaled by 16 (4 bits).
        offset: u8,
    },
    /// Allocate `(size + 1) * 8` bytes on the stack (`WOD_ALLOC_SMALL`).
    AllocSmall {
        /// The scaled size (0 to 15).
        size: u8,
    },
    /// Allocate `size * 8` bytes on the stack (`WOD_ALLOC_LARGE`).
    AllocLarge {
        /// The size, scaled by 8.
        size: u16,
    },
    /// Allocate `size` bytes on the stack (`WOD_ALLOC_HUGE`).
    AllocHuge {
        /// The size in bytes.
        size: u32,
    },
    /// The processor or the operating system pushed a canonical frame
    /// (`WOD_PUSH_CANONICAL_FRAME`), for example a machine frame or a context record.
    PushCanonicalFrame {
        /// The frame type. The Windows SDK headers define the values.
        kind: u8,
    },
    /// Push an integer register (`WOD_PUSH`).
    Push {
        /// The register (0 to 31).
        register: u8,
    },
    /// Push two integer registers with one APX `PUSH2` instruction (`WOD_PUSH2`).
    Push2 {
        /// The first register of the instruction (0 to 31).
        first: u8,
        /// The second register of the instruction (0 to 31).
        second: u8,
    },
    /// Push `register` and then `register + 1` (`WOD_PUSH_CONSECUTIVE_2`).
    PushConsecutive2 {
        /// The first register (0 to 30).
        register: u8,
    },
    /// Save an integer register at `[RSP + displacement * 8]` (`WOD_SAVE_NONVOL`).
    SaveNonvol {
        /// The register (0 to 31).
        register: u8,
        /// The displacement from RSP, scaled by 8.
        displacement: u16,
    },
    /// Save an integer register at `[RSP + displacement]` (`WOD_SAVE_NONVOL_FAR`).
    SaveNonvolFar {
        /// The register (0 to 31).
        register: u8,
        /// The displacement from RSP in bytes.
        displacement: u32,
    },
    /// Save an XMM register at `[RSP + displacement * 16]` (`WOD_SAVE_XMM128`).
    SaveXmm128 {
        /// The XMM register (0 to 15).
        register: u8,
        /// The displacement from RSP, scaled by 16.
        displacement: u16,
    },
    /// Save an XMM register at `[RSP + displacement]` (`WOD_SAVE_XMM128_FAR`).
    SaveXmm128Far {
        /// The XMM register (0 to 15).
        register: u8,
        /// The displacement from RSP in bytes.
        displacement: u32,
    },
}

impl WindOp {
    /// Decode the WOD at the start of `bytes`.
    ///
    /// Returns the operation and its encoded length in bytes.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - `bytes` ends before the end of the WOD.
    /// - The first byte is not a WOD opcode.
    /// - A `WOD_PUSH_CONSECUTIVE_2` names register 31.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        let Some(&first) = bytes.first() else {
            return Err(Error::buffer_too_small(size_of::<u8>(), 0));
        };
        let op = match first & 0x07 {
            OP_PUSH => Self::Push {
                register: first >> 3,
            },
            OP_SAVE_NONVOL_FAR => Self::SaveNonvolFar {
                register: first >> 3,
                displacement: dword_operand(bytes)?,
            },
            OP_SAVE_NONVOL => Self::SaveNonvol {
                register: first >> 3,
                displacement: word_operand(bytes)?,
            },
            OP_PUSH_CONSECUTIVE_2 if first >> 3 < 31 => Self::PushConsecutive2 {
                register: first >> 3,
            },
            OP_PUSH_CONSECUTIVE_2 => {
                return Err(Error::invalid_data_directory(
                    "WOD_PUSH_CONSECUTIVE_2 names register 31",
                ));
            }
            _ => Self::decode_wide(first, bytes)?,
        };
        Ok((op, op.encoded_len()))
    }

    /// Decode a WOD with a 4-bit, 6-bit or 8-bit opcode.
    fn decode_wide(first: u8, bytes: &[u8]) -> Result<Self> {
        Ok(match first & 0x0F {
            OP_ALLOC_SMALL => Self::AllocSmall { size: first >> 4 },
            OP_SAVE_XMM128_FAR => Self::SaveXmm128Far {
                register: first >> 4,
                displacement: dword_operand(bytes)?,
            },
            OP_SAVE_XMM128 => Self::SaveXmm128 {
                register: first >> 4,
                displacement: word_operand(bytes)?,
            },
            _ if first & 0x3F == OP_PUSH2 => {
                let second = byte_operand(bytes)?;
                Self::Push2 {
                    first: (first >> 6) | ((second & 0x07) << 2),
                    second: second >> 3,
                }
            }
            _ => match first {
                OP_SET_FPREG => {
                    let operand = byte_operand(bytes)?;
                    Self::SetFrameRegister {
                        register: operand & 0x0F,
                        offset: operand >> 4,
                    }
                }
                OP_ALLOC_HUGE => Self::AllocHuge {
                    size: dword_operand(bytes)?,
                },
                OP_ALLOC_LARGE => Self::AllocLarge {
                    size: word_operand(bytes)?,
                },
                OP_PUSH_CANONICAL_FRAME => Self::PushCanonicalFrame {
                    kind: byte_operand(bytes)?,
                },
                _ => {
                    return Err(Error::invalid_data_directory(format!(
                        "invalid x64 WOD opcode byte {first:#04x}"
                    )));
                }
            },
        })
    }

    /// Return the encoded length in bytes.
    #[must_use]
    pub fn encoded_len(self) -> usize {
        match self {
            Self::AllocSmall { .. } | Self::Push { .. } | Self::PushConsecutive2 { .. } => {
                size_of::<u8>()
            }
            Self::SetFrameRegister { .. }
            | Self::PushCanonicalFrame { .. }
            | Self::Push2 { .. } => size_of::<WodByteOperand>(),
            Self::AllocLarge { .. } | Self::SaveNonvol { .. } | Self::SaveXmm128 { .. } => {
                size_of::<WodWordOperand>()
            }
            Self::AllocHuge { .. } | Self::SaveNonvolFar { .. } | Self::SaveXmm128Far { .. } => {
                size_of::<WodDwordOperand>()
            }
        }
    }

    /// Append the encoded WOD to `out`.
    ///
    /// Each field has a range: see the field documentation. `encode` keeps only the bits of
    /// a field that the encoding has room for. Thus give each field a value in its range.
    pub fn encode(self, out: &mut Vec<u8>) {
        match self {
            Self::SetFrameRegister { register, offset } => {
                push_byte_operand(out, OP_SET_FPREG, (register & 0x0F) | (offset << 4));
            }
            Self::AllocSmall { size } => out.push(OP_ALLOC_SMALL | (size << 4)),
            Self::AllocLarge { size } => push_word_operand(out, OP_ALLOC_LARGE, size),
            Self::AllocHuge { size } => push_dword_operand(out, OP_ALLOC_HUGE, size),
            Self::PushCanonicalFrame { kind } => {
                push_byte_operand(out, OP_PUSH_CANONICAL_FRAME, kind);
            }
            Self::Push { register } => out.push(OP_PUSH | (register << 3)),
            Self::Push2 { first, second } => push_byte_operand(
                out,
                OP_PUSH2 | (first << 6),
                ((first >> 2) & 0x07) | (second << 3),
            ),
            Self::PushConsecutive2 { register } => {
                out.push(OP_PUSH_CONSECUTIVE_2 | (register << 3));
            }
            Self::SaveNonvol {
                register,
                displacement,
            } => push_word_operand(out, OP_SAVE_NONVOL | (register << 3), displacement),
            Self::SaveNonvolFar {
                register,
                displacement,
            } => push_dword_operand(out, OP_SAVE_NONVOL_FAR | (register << 3), displacement),
            Self::SaveXmm128 {
                register,
                displacement,
            } => push_word_operand(out, OP_SAVE_XMM128 | (register << 4), displacement),
            Self::SaveXmm128Far {
                register,
                displacement,
            } => push_dword_operand(out, OP_SAVE_XMM128_FAR | (register << 4), displacement),
        }
    }

    /// Return the count of bytes by which the operation lowers RSP.
    ///
    /// A push lowers RSP by 8 bytes for each register. An allocation lowers RSP by its size.
    /// `SetFrameRegister` and the save operations do not change RSP. Returns `None` for
    /// `PushCanonicalFrame`: the operating system defines the size of the frame.
    #[must_use]
    pub fn stack_bytes(self) -> Option<u32> {
        match self {
            Self::Push { .. } => Some(STACK_SLOT),
            Self::Push2 { .. } | Self::PushConsecutive2 { .. } => Some(2 * STACK_SLOT),
            Self::AllocSmall { size } => Some((u32::from(size) + 1) * STACK_SLOT),
            Self::AllocLarge { size } => Some(u32::from(size) * STACK_SLOT),
            Self::AllocHuge { size } => Some(size),
            Self::SetFrameRegister { .. }
            | Self::SaveNonvol { .. }
            | Self::SaveNonvolFar { .. }
            | Self::SaveXmm128 { .. }
            | Self::SaveXmm128Far { .. } => Some(0),
            Self::PushCanonicalFrame { .. } => None,
        }
    }
}

/// Return the operand of the WOD with a byte operand at the start of `bytes`.
fn byte_operand(bytes: &[u8]) -> Result<u8> {
    const N: usize = size_of::<WodByteOperand>();
    let raw = bytes
        .first_chunk::<N>()
        .ok_or_else(|| Error::buffer_too_small(N, bytes.len()))?;
    Ok(le_u8::<N, { offset_of!(WodByteOperand, operand) }>(raw))
}

/// Return the operand of the WOD with a 16-bit operand at the start of `bytes`.
fn word_operand(bytes: &[u8]) -> Result<u16> {
    const N: usize = size_of::<WodWordOperand>();
    let raw = bytes
        .first_chunk::<N>()
        .ok_or_else(|| Error::buffer_too_small(N, bytes.len()))?;
    Ok(le_u16::<N, { offset_of!(WodWordOperand, operand) }>(raw))
}

/// Return the operand of the WOD with a 32-bit operand at the start of `bytes`.
fn dword_operand(bytes: &[u8]) -> Result<u32> {
    const N: usize = size_of::<WodDwordOperand>();
    let raw = bytes
        .first_chunk::<N>()
        .ok_or_else(|| Error::buffer_too_small(N, bytes.len()))?;
    Ok(le_u32::<N, { offset_of!(WodDwordOperand, operand) }>(raw))
}

/// Append a WOD with a byte operand to `out`.
fn push_byte_operand(out: &mut Vec<u8>, opcode: u8, operand: u8) {
    const N: usize = size_of::<WodByteOperand>();
    let mut raw = [0; N];
    put_u8::<N, { offset_of!(WodByteOperand, opcode) }>(&mut raw, opcode);
    put_u8::<N, { offset_of!(WodByteOperand, operand) }>(&mut raw, operand);
    out.extend_from_slice(&raw);
}

/// Append a WOD with a 16-bit operand to `out`.
fn push_word_operand(out: &mut Vec<u8>, opcode: u8, operand: u16) {
    const N: usize = size_of::<WodWordOperand>();
    let mut raw = [0; N];
    put_u8::<N, { offset_of!(WodWordOperand, opcode) }>(&mut raw, opcode);
    put_u16::<N, { offset_of!(WodWordOperand, operand) }>(&mut raw, operand);
    out.extend_from_slice(&raw);
}

/// Append a WOD with a 32-bit operand to `out`.
fn push_dword_operand(out: &mut Vec<u8>, opcode: u8, operand: u32) {
    const N: usize = size_of::<WodDwordOperand>();
    let mut raw = [0; N];
    put_u8::<N, { offset_of!(WodDwordOperand, opcode) }>(&mut raw, opcode);
    put_u32::<N, { offset_of!(WodDwordOperand, operand) }>(&mut raw, operand);
    out.extend_from_slice(&raw);
}

/// Decode one WOD list: one WOD for each IP offset, from the byte `first_op` of `pool`.
///
/// Returns each IP offset with its operation, in stored order.
fn decode_ops(pool: &[u8], first_op: u16, ip_offsets: &[u16]) -> Result<Vec<(u16, WindOp)>> {
    let mut rest = pool.get(usize::from(first_op)..).ok_or_else(|| {
        Error::invalid_data_directory(format!(
            "a WOD list starts at byte {first_op}, after the end of the {}-byte WOD pool",
            pool.len()
        ))
    })?;
    let mut ops = Vec::with_capacity(ip_offsets.len());
    for &ip_offset in ip_offsets {
        let (op, len) =
            WindOp::decode(rest).map_err(|error| error.in_structure("UNWIND_INFO_V3 WOD pool"))?;
        rest = rest.get(len..).unwrap_or_default();
        ops.push((ip_offset, op));
    }
    Ok(ops)
}

/// An x64 unwind information record of any version that Portex reads.
///
/// Versions 1 and 2 use [`UnwindInfo`]. Version 3 uses [`UnwindInfoV3`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X64UnwindInfo {
    /// A version 1 or version 2 record (`UNWIND_INFO`).
    Classic(UnwindInfo),
    /// A version 3 record (`UNWIND_INFO_V3`).
    V3(UnwindInfoV3),
}

impl X64UnwindInfo {
    /// Parse an x64 unwind information record from the bytes at its RVA.
    ///
    /// The version bits of the first byte select the format. The input rule of
    /// [`UnwindInfo::parse`] applies: `data` must end where the language-specific handler data
    /// ends.
    ///
    /// # Errors
    /// Returns an error in these conditions:
    /// - `data` is empty.
    /// - The version is not 1, 2 or 3.
    /// - [`UnwindInfo::parse`] or [`UnwindInfoV3::parse`] fails.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(&version_and_flags) = data.first() else {
            return Err(Error::buffer_too_small(UnwindInfo::MIN_SIZE, data.len()));
        };
        match version_and_flags & 0x07 {
            1 | 2 => UnwindInfo::parse(data).map(Self::Classic),
            VERSION => UnwindInfoV3::parse(data).map(Self::V3),
            version => Err(Error::invalid_data_directory(format!(
                "unsupported x64 unwind version {version}"
            ))),
        }
    }

    /// Return the version (1, 2 or 3).
    #[must_use]
    pub fn version(&self) -> u8 {
        match self {
            Self::Classic(info) => info.version(),
            Self::V3(_) => VERSION,
        }
    }

    /// Return the 5 flag bits of the header.
    #[must_use]
    pub fn flags(&self) -> u8 {
        match self {
            Self::Classic(info) => info.flags(),
            Self::V3(info) => info.flags,
        }
    }

    /// Return `true` if the record has an exception handler or a termination handler.
    #[must_use]
    pub fn has_exception_handler(&self) -> bool {
        match self {
            Self::Classic(info) => info.has_exception_handler(),
            Self::V3(info) => info.has_exception_handler(),
        }
    }

    /// Return `true` if the record chains to other unwind information.
    #[must_use]
    pub fn is_chained(&self) -> bool {
        match self {
            Self::Classic(info) => info.is_chained(),
            Self::V3(info) => info.is_chained(),
        }
    }

    /// Return the RVA of the exception handler or of the termination handler.
    #[must_use]
    pub fn exception_handler(&self) -> Option<u32> {
        match self {
            Self::Classic(info) => info.exception_handler,
            Self::V3(info) => info.exception_handler,
        }
    }

    /// Return the chained `RUNTIME_FUNCTION`.
    #[must_use]
    pub fn chained_function(&self) -> Option<RuntimeFunction> {
        match self {
            Self::Classic(info) => info.chained_function,
            Self::V3(info) => info.chained_function,
        }
    }

    /// Return the language-specific bytes that follow the handler RVA.
    #[must_use]
    pub fn handler_data(&self) -> &[u8] {
        match self {
            Self::Classic(info) => &info.handler_data,
            Self::V3(info) => &info.handler_data,
        }
    }

    /// Return the size of the prolog in bytes.
    #[must_use]
    pub fn size_of_prolog(&self) -> u16 {
        match self {
            Self::Classic(info) => u16::from(info.size_of_prolog),
            Self::V3(info) => info.size_of_prolog,
        }
    }

    /// Return `true` if the record describes unwind operations.
    ///
    /// A version 1 or version 2 record must have an unwind code slot. A version 3 record must
    /// have a prolog operation or an epilog.
    #[must_use]
    pub fn has_operations(&self) -> bool {
        match self {
            Self::Classic(info) => !info.unwind_codes.is_empty(),
            Self::V3(info) => !info.prolog_ip_offsets.is_empty() || !info.epilogs.is_empty(),
        }
    }

    /// Serialize the record to bytes after validation.
    ///
    /// # Errors
    /// Returns an error if [`UnwindInfo::try_to_bytes`] or [`UnwindInfoV3::try_to_bytes`]
    /// fails.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Classic(info) => info.try_to_bytes(),
            Self::V3(info) => info.try_to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests;
