//! COFF file header (`IMAGE_FILE_HEADER`) structures and parsing.

use core::mem::{offset_of, size_of};

use crate::parse_utils::{le_u16, le_u32, put_u16, put_u32};
use crate::prelude::*;
use crate::reader::ReadAt;
use crate::{Error, Result};

/// The PE signature `PE\0\0`, read as a little-endian `u32`.
pub const PE_SIGNATURE: u32 = 0x0000_4550;

/// The size of the PE signature in bytes: the offset of `IMAGE_FILE_HEADER` in
/// `IMAGE_NT_HEADERS`.
pub(crate) const PE_SIGNATURE_SIZE: usize =
    offset_of!(crate::optional::ImageNtHeaders32, file_header);

/// Machine types (`IMAGE_FILE_MACHINE_*` values) for `IMAGE_FILE_HEADER.Machine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum MachineType {
    /// Unknown machine type.
    Unknown = 0x0000,
    /// Intel 386 or later.
    I386 = 0x014C,
    /// MIPS little-endian R4000.
    R4000 = 0x0166,
    /// MIPS little-endian WCE v2.
    WceMipsV2 = 0x0169,
    /// Hitachi SH3.
    Sh3 = 0x01A2,
    /// Hitachi SH3 DSP.
    Sh3Dsp = 0x01A3,
    /// Hitachi SH4.
    Sh4 = 0x01A6,
    /// Hitachi SH5.
    Sh5 = 0x01A8,
    /// x64 (AMD64).
    Amd64 = 0x8664,
    /// MIPS16.
    Mips16 = 0x0266,
    /// MIPS with FPU.
    MipsFpu = 0x0366,
    /// MIPS16 with FPU.
    MipsFpu16 = 0x0466,
    /// ARM little endian.
    Arm = 0x01C0,
    /// ARM Thumb.
    Thumb = 0x01C2,
    /// ARM64 little endian.
    Arm64 = 0xAA64,
    /// ARM64 emulation-compatible ABI.
    Arm64Ec = 0xA641,
    /// Hybrid ARM64X image.
    Arm64X = 0xA64E,
    /// ARM Thumb-2 little endian.
    ArmNt = 0x01C4,
    /// Matsushita AM33.
    Am33 = 0x01D3,
    /// EFI byte code.
    Ebc = 0x0EBC,
    /// Intel Itanium.
    Ia64 = 0x0200,
    /// DEC Alpha AXP.
    Alpha = 0x0184,
    /// DEC Alpha AXP 64-bit.
    Alpha64 = 0x0284,
    /// IBM PowerPC little endian.
    PowerPc = 0x01F0,
    /// IBM PowerPC with floating point support.
    PowerPcFp = 0x01F1,
    /// Mitsubishi M32R little endian.
    M32R = 0x9041,
    /// RISC-V 32-bit.
    RiscV32 = 0x5032,
    /// RISC-V 64-bit.
    RiscV64 = 0x5064,
    /// RISC-V 128-bit.
    RiscV128 = 0x5128,
    /// LoongArch 32-bit.
    LoongArch32 = 0x6232,
    /// LoongArch 64-bit.
    LoongArch64 = 0x6264,
}

impl MachineType {
    /// Convert from a raw `IMAGE_FILE_HEADER.Machine` value.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::Unknown),
            0x014C => Some(Self::I386),
            0x0166 => Some(Self::R4000),
            0x0169 => Some(Self::WceMipsV2),
            0x01A2 => Some(Self::Sh3),
            0x01A3 => Some(Self::Sh3Dsp),
            0x01A6 => Some(Self::Sh4),
            0x01A8 => Some(Self::Sh5),
            0x8664 => Some(Self::Amd64),
            0x0266 => Some(Self::Mips16),
            0x0366 => Some(Self::MipsFpu),
            0x0466 => Some(Self::MipsFpu16),
            0x01C0 => Some(Self::Arm),
            0x01C2 => Some(Self::Thumb),
            0xAA64 => Some(Self::Arm64),
            0xA641 => Some(Self::Arm64Ec),
            0xA64E => Some(Self::Arm64X),
            0x01C4 => Some(Self::ArmNt),
            0x01D3 => Some(Self::Am33),
            0x0EBC => Some(Self::Ebc),
            0x0200 => Some(Self::Ia64),
            0x0184 => Some(Self::Alpha),
            0x0284 => Some(Self::Alpha64),
            0x01F0 => Some(Self::PowerPc),
            0x01F1 => Some(Self::PowerPcFp),
            0x9041 => Some(Self::M32R),
            0x5032 => Some(Self::RiscV32),
            0x5064 => Some(Self::RiscV64),
            0x5128 => Some(Self::RiscV128),
            0x6232 => Some(Self::LoongArch32),
            0x6264 => Some(Self::LoongArch64),
            _ => None,
        }
    }

    /// Return `true` if this machine usually uses a PE32+ optional header.
    #[must_use]
    pub const fn is_64_bit(self) -> bool {
        matches!(
            self,
            Self::Amd64
                | Self::Ebc
                | Self::Arm64
                | Self::Arm64Ec
                | Self::Arm64X
                | Self::Ia64
                | Self::Alpha64
                | Self::RiscV64
                | Self::RiscV128
                | Self::LoongArch64
        )
    }

    /// Return `true` if this machine usually uses a PE32 optional header.
    ///
    /// [`MachineType::Unknown`] returns `false`.
    #[must_use]
    pub const fn is_32_bit(self) -> bool {
        !matches!(self, Self::Unknown) && !self.is_64_bit()
    }
}

/// Characteristics flags (`IMAGE_FILE_*` values) for `IMAGE_FILE_HEADER.Characteristics`.
pub mod characteristics {
    /// `IMAGE_FILE_RELOCS_STRIPPED`: the file has no base relocations.
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    /// `IMAGE_FILE_EXECUTABLE_IMAGE`: the file is executable.
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    /// `IMAGE_FILE_LINE_NUMS_STRIPPED`: the file has no COFF line numbers (obsolete).
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    /// `IMAGE_FILE_LOCAL_SYMS_STRIPPED`: the file has no COFF local symbols (obsolete).
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    /// `IMAGE_FILE_AGGRESSIVE_WS_TRIM`: trim the working set aggressively (obsolete).
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    /// `IMAGE_FILE_LARGE_ADDRESS_AWARE`: the application can use addresses above 2 GB.
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    /// `IMAGE_FILE_BYTES_REVERSED_LO`: the bytes of the machine word are reversed (obsolete).
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    /// `IMAGE_FILE_32BIT_MACHINE`: the machine uses 32-bit words.
    pub const MACHINE_32BIT: u16 = 0x0100;
    /// `IMAGE_FILE_DEBUG_STRIPPED`: the file has no debug information.
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    /// `IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP`: on removable media, copy the image to the swap
    /// file and run it from there.
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    /// `IMAGE_FILE_NET_RUN_FROM_SWAP`: on network media, copy the image to the swap file and
    /// run it from there.
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    /// `IMAGE_FILE_SYSTEM`: the file is a system file.
    pub const SYSTEM: u16 = 0x1000;
    /// `IMAGE_FILE_DLL`: the file is a DLL.
    pub const DLL: u16 = 0x2000;
    /// `IMAGE_FILE_UP_SYSTEM_ONLY`: run the file only on a uniprocessor machine.
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    /// `IMAGE_FILE_BYTES_REVERSED_HI`: the bytes of the machine word are reversed (obsolete).
    pub const BYTES_REVERSED_HI: u16 = 0x8000;
}

/// The layout of `IMAGE_FILE_HEADER`.
///
/// Portex does not read the structure through this type. The type gives the offset and the
/// width of each field.
#[repr(C)]
pub(crate) struct ImageFileHeader {
    pub(crate) machine: u16,
    pub(crate) number_of_sections: u16,
    pub(crate) time_date_stamp: u32,
    pub(crate) pointer_to_symbol_table: u32,
    pub(crate) number_of_symbols: u32,
    pub(crate) size_of_optional_header: u16,
    pub(crate) characteristics: u16,
}

// Anchors from `winnt.h` that the layout must keep.
const _: () = {
    assert!(size_of::<ImageFileHeader>() == 20);
    assert!(offset_of!(ImageFileHeader, time_date_stamp) == 4);
    assert!(offset_of!(ImageFileHeader, size_of_optional_header) == 16);
};

/// The COFF file header (`IMAGE_FILE_HEADER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CoffHeader {
    /// The target machine type (`Machine`). See [`MachineType`].
    pub machine: u16,
    /// The number of section headers (`NumberOfSections`).
    pub number_of_sections: u16,
    /// The time stamp, in seconds since 1970-01-01 00:00 UTC (`TimeDateStamp`).
    pub time_date_stamp: u32,
    /// The file offset of the COFF symbol table (`PointerToSymbolTable`), or 0 if there is no
    /// symbol table.
    pub pointer_to_symbol_table: u32,
    /// The number of entries in the COFF symbol table (`NumberOfSymbols`).
    pub number_of_symbols: u32,
    /// The size of the optional header in bytes (`SizeOfOptionalHeader`).
    pub size_of_optional_header: u16,
    /// The characteristics flags (`Characteristics`). See [`characteristics`].
    pub characteristics: u16,
}

impl CoffHeader {
    /// The size of the COFF file header in bytes.
    pub const SIZE: usize = size_of::<ImageFileHeader>();

    /// Parse a COFF file header from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(raw) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        /// Read `$field` of `ImageFileHeader` from `raw` with `$read`.
        macro_rules! field {
            ($read:ident, $field:ident) => {
                $read::<{ CoffHeader::SIZE }, { offset_of!(ImageFileHeader, $field) }>(raw)
            };
        }

        Ok(Self {
            machine: field!(le_u16, machine),
            number_of_sections: field!(le_u16, number_of_sections),
            time_date_stamp: field!(le_u32, time_date_stamp),
            pointer_to_symbol_table: field!(le_u32, pointer_to_symbol_table),
            number_of_symbols: field!(le_u32, number_of_symbols),
            size_of_optional_header: field!(le_u16, size_of_optional_header),
            characteristics: field!(le_u16, characteristics),
        })
    }

    /// Write the COFF file header to a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `buf` is shorter than [`Self::SIZE`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let out = buf
            .first_chunk_mut::<{ Self::SIZE }>()
            .ok_or_else(|| Error::buffer_too_small(Self::SIZE, len))?;
        *out = self.encode();
        Ok(())
    }

    /// Encode the header in its little-endian file layout.
    fn encode(&self) -> [u8; Self::SIZE] {
        /// Write `$field` of `$header` at its offset in `ImageFileHeader` with `$put`.
        macro_rules! put {
            ($raw:ident, $header:ident, $put:ident, $field:ident) => {
                $put::<{ CoffHeader::SIZE }, { offset_of!(ImageFileHeader, $field) }>(
                    &mut $raw,
                    $header.$field,
                )
            };
        }

        let mut raw = [0u8; Self::SIZE];
        put!(raw, self, put_u16, machine);
        put!(raw, self, put_u16, number_of_sections);
        put!(raw, self, put_u32, time_date_stamp);
        put!(raw, self, put_u32, pointer_to_symbol_table);
        put!(raw, self, put_u32, number_of_symbols);
        put!(raw, self, put_u16, size_of_optional_header);
        put!(raw, self, put_u16, characteristics);
        raw
    }

    /// Return the machine type as a [`MachineType`], or `None` for an unknown value.
    #[must_use]
    pub fn machine_type(&self) -> Option<MachineType> {
        MachineType::from_u16(self.machine)
    }

    /// Return `true` if the file is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.characteristics & characteristics::DLL != 0
    }

    /// Return `true` if the file is executable.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.characteristics & characteristics::EXECUTABLE_IMAGE != 0
    }

    /// Read a COFF file header from a [`ReadAt`] reader at the file offset `offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::SIZE`] bytes cannot be read at `offset`.
    pub fn read_from<R: ReadAt>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Serialize the header to a byte vector.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        self.encode().to_vec()
    }
}

/// Verify the `PE\0\0` signature at the file offset `offset`.
///
/// # Errors
///
/// Returns an error if the signature cannot be read at `offset`, or an
/// invalid-PE-signature error if it does not equal [`PE_SIGNATURE`].
pub fn verify_pe_signature<R: ReadAt>(reader: &R, offset: u64) -> Result<()> {
    let sig = reader.read_u32_at(offset)?;
    if sig != PE_SIGNATURE {
        return Err(Error::invalid_pe_signature());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
