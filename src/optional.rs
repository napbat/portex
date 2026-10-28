//! Optional header (`IMAGE_OPTIONAL_HEADER32` and `IMAGE_OPTIONAL_HEADER64`) structures and
//! parsing.

use crate::data_dir::{DataDirectory, NUMBER_OF_DIRECTORY_ENTRIES};
use crate::prelude::*;
use crate::reader::ReadAt;
use crate::{Error, Result};

/// PE32 magic number (`IMAGE_NT_OPTIONAL_HDR32_MAGIC`).
pub const PE32_MAGIC: u16 = 0x10B;
/// PE32+ (64-bit) magic number (`IMAGE_NT_OPTIONAL_HDR64_MAGIC`).
pub const PE32PLUS_MAGIC: u16 = 0x20B;

/// Windows subsystem values (`IMAGE_SUBSYSTEM_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum Subsystem {
    /// Unknown subsystem (`IMAGE_SUBSYSTEM_UNKNOWN`).
    Unknown = 0,
    /// Device drivers and native Windows processes (`IMAGE_SUBSYSTEM_NATIVE`).
    Native = 1,
    /// Windows graphical user interface (`IMAGE_SUBSYSTEM_WINDOWS_GUI`).
    WindowsGui = 2,
    /// Windows character-mode console (`IMAGE_SUBSYSTEM_WINDOWS_CUI`).
    WindowsCui = 3,
    /// OS/2 character subsystem (`IMAGE_SUBSYSTEM_OS2_CUI`).
    Os2Cui = 5,
    /// POSIX character subsystem (`IMAGE_SUBSYSTEM_POSIX_CUI`).
    PosixCui = 7,
    /// Native Windows 9x driver (`IMAGE_SUBSYSTEM_NATIVE_WINDOWS`).
    NativeWindows = 8,
    /// Windows CE (`IMAGE_SUBSYSTEM_WINDOWS_CE_GUI`).
    WindowsCeGui = 9,
    /// EFI application (`IMAGE_SUBSYSTEM_EFI_APPLICATION`).
    EfiApplication = 10,
    /// EFI driver with boot services (`IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER`).
    EfiBootServiceDriver = 11,
    /// EFI driver with run-time services (`IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER`).
    EfiRuntimeDriver = 12,
    /// EFI ROM image (`IMAGE_SUBSYSTEM_EFI_ROM`).
    EfiRom = 13,
    /// Xbox (`IMAGE_SUBSYSTEM_XBOX`).
    Xbox = 14,
    /// Windows boot application (`IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION`).
    WindowsBootApplication = 16,
}

impl Subsystem {
    /// Convert a raw `Subsystem` value of the optional header to a [`Subsystem`].
    ///
    /// Returns `None` for values this crate does not recognize.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Native),
            2 => Some(Self::WindowsGui),
            3 => Some(Self::WindowsCui),
            5 => Some(Self::Os2Cui),
            7 => Some(Self::PosixCui),
            8 => Some(Self::NativeWindows),
            9 => Some(Self::WindowsCeGui),
            10 => Some(Self::EfiApplication),
            11 => Some(Self::EfiBootServiceDriver),
            12 => Some(Self::EfiRuntimeDriver),
            13 => Some(Self::EfiRom),
            14 => Some(Self::Xbox),
            16 => Some(Self::WindowsBootApplication),
            _ => None,
        }
    }
}

/// DLL characteristics flags (`IMAGE_DLLCHARACTERISTICS_*`).
pub mod dll_characteristics {
    /// `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`: the image can use a high-entropy 64-bit
    /// virtual address space.
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    /// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`: the loader can relocate the image at load time
    /// (ASLR).
    pub const DYNAMIC_BASE: u16 = 0x0040;
    /// `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`: the loader enforces code integrity checks.
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    /// `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`: the image is compatible with data execution
    /// prevention (NX).
    pub const NX_COMPAT: u16 = 0x0100;
    /// `IMAGE_DLLCHARACTERISTICS_NO_ISOLATION`: the image is isolation aware, but do not isolate
    /// it.
    pub const NO_ISOLATION: u16 = 0x0200;
    /// `IMAGE_DLLCHARACTERISTICS_NO_SEH`: the image does not use structured exception handling.
    /// No SE handler can be called in the image.
    pub const NO_SEH: u16 = 0x0400;
    /// `IMAGE_DLLCHARACTERISTICS_NO_BIND`: do not bind the image.
    pub const NO_BIND: u16 = 0x0800;
    /// `IMAGE_DLLCHARACTERISTICS_APPCONTAINER`: the image must execute in an `AppContainer`.
    pub const APPCONTAINER: u16 = 0x1000;
    /// `IMAGE_DLLCHARACTERISTICS_WDM_DRIVER`: the image is a WDM driver.
    pub const WDM_DRIVER: u16 = 0x2000;
    /// `IMAGE_DLLCHARACTERISTICS_GUARD_CF`: the image supports Control Flow Guard.
    pub const GUARD_CF: u16 = 0x4000;
    /// `IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE`: the image is Terminal Server aware.
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

/// The PE32 optional header (`IMAGE_OPTIONAL_HEADER32`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader32 {
    /// The magic number that identifies the format. It is [`PE32_MAGIC`] for PE32.
    pub magic: u16,
    /// Linker major version number.
    pub major_linker_version: u8,
    /// Linker minor version number.
    pub minor_linker_version: u8,
    /// Total size in bytes of all code sections.
    pub size_of_code: u32,
    /// Total size in bytes of all initialized-data sections.
    pub size_of_initialized_data: u32,
    /// Total size in bytes of all uninitialized-data sections (BSS).
    pub size_of_uninitialized_data: u32,
    /// RVA of the entry point, or 0 if there is none.
    pub address_of_entry_point: u32,
    /// RVA of the start of the code section.
    pub base_of_code: u32,
    /// RVA of the start of the data section (PE32 only).
    pub base_of_data: u32,
    /// The preferred VA of the first byte of the image when the loader maps it.
    pub image_base: u32,
    /// Alignment in bytes of sections when loaded in memory.
    pub section_alignment: u32,
    /// Alignment in bytes of section raw data in the file.
    pub file_alignment: u32,
    /// Major version of the required operating system.
    pub major_operating_system_version: u16,
    /// Minor version of the required operating system.
    pub minor_operating_system_version: u16,
    /// Major version of the image.
    pub major_image_version: u16,
    /// Minor version of the image.
    pub minor_image_version: u16,
    /// Major version of the subsystem.
    pub major_subsystem_version: u16,
    /// Minor version of the subsystem.
    pub minor_subsystem_version: u16,
    /// Reserved. Must be zero.
    pub win32_version_value: u32,
    /// Size in bytes of the loaded image, a multiple of `section_alignment`.
    pub size_of_image: u32,
    /// Combined size in bytes of all headers, rounded up to `file_alignment`.
    pub size_of_headers: u32,
    /// Image file checksum.
    pub check_sum: u32,
    /// Subsystem required to run the image (see [`Subsystem`]).
    pub subsystem: u16,
    /// DLL characteristics flags (see [`dll_characteristics`]).
    pub dll_characteristics: u16,
    /// Size in bytes of the stack to reserve.
    pub size_of_stack_reserve: u32,
    /// Size in bytes of the stack to commit.
    pub size_of_stack_commit: u32,
    /// Size in bytes of the local heap to reserve.
    pub size_of_heap_reserve: u32,
    /// Size in bytes of the local heap to commit.
    pub size_of_heap_commit: u32,
    /// Reserved. Must be zero.
    pub loader_flags: u32,
    /// Number of data directory entries after the fixed part of the header.
    ///
    /// The loader reads at most [`NUMBER_OF_DIRECTORY_ENTRIES`] entries. The parser keeps a
    /// larger value here, but reads only that number of entries into `data_directories`.
    pub number_of_rva_and_sizes: u32,
    /// Data-directory entries (`IMAGE_DATA_DIRECTORY` array).
    pub data_directories: Vec<DataDirectory>,
}

/// The PE32+ optional header (`IMAGE_OPTIONAL_HEADER64`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader64 {
    /// The magic number that identifies the format. It is [`PE32PLUS_MAGIC`] for PE32+.
    pub magic: u16,
    /// Linker major version number.
    pub major_linker_version: u8,
    /// Linker minor version number.
    pub minor_linker_version: u8,
    /// Total size in bytes of all code sections.
    pub size_of_code: u32,
    /// Total size in bytes of all initialized-data sections.
    pub size_of_initialized_data: u32,
    /// Total size in bytes of all uninitialized-data sections (BSS).
    pub size_of_uninitialized_data: u32,
    /// RVA of the entry point, or 0 if there is none.
    pub address_of_entry_point: u32,
    /// RVA of the start of the code section.
    pub base_of_code: u32,
    /// The preferred VA of the first byte of the image when the loader maps it.
    pub image_base: u64,
    /// Alignment in bytes of sections when loaded in memory.
    pub section_alignment: u32,
    /// Alignment in bytes of section raw data in the file.
    pub file_alignment: u32,
    /// Major version of the required operating system.
    pub major_operating_system_version: u16,
    /// Minor version of the required operating system.
    pub minor_operating_system_version: u16,
    /// Major version of the image.
    pub major_image_version: u16,
    /// Minor version of the image.
    pub minor_image_version: u16,
    /// Major version of the subsystem.
    pub major_subsystem_version: u16,
    /// Minor version of the subsystem.
    pub minor_subsystem_version: u16,
    /// Reserved. Must be zero.
    pub win32_version_value: u32,
    /// Size in bytes of the loaded image, a multiple of `section_alignment`.
    pub size_of_image: u32,
    /// Combined size in bytes of all headers, rounded up to `file_alignment`.
    pub size_of_headers: u32,
    /// Image file checksum.
    pub check_sum: u32,
    /// Subsystem required to run the image (see [`Subsystem`]).
    pub subsystem: u16,
    /// DLL characteristics flags (see [`dll_characteristics`]).
    pub dll_characteristics: u16,
    /// Size in bytes of the stack to reserve.
    pub size_of_stack_reserve: u64,
    /// Size in bytes of the stack to commit.
    pub size_of_stack_commit: u64,
    /// Size in bytes of the local heap to reserve.
    pub size_of_heap_reserve: u64,
    /// Size in bytes of the local heap to commit.
    pub size_of_heap_commit: u64,
    /// Reserved. Must be zero.
    pub loader_flags: u32,
    /// Number of data directory entries after the fixed part of the header.
    ///
    /// The loader reads at most [`NUMBER_OF_DIRECTORY_ENTRIES`] entries. The parser keeps a
    /// larger value here, but reads only that number of entries into `data_directories`.
    pub number_of_rva_and_sizes: u32,
    /// Data-directory entries (`IMAGE_DATA_DIRECTORY` array).
    pub data_directories: Vec<DataDirectory>,
}

/// An optional header in the PE32 or the PE32+ format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionalHeader {
    /// 32-bit PE32 optional header.
    Pe32(OptionalHeader32),
    /// 64-bit PE32+ optional header.
    Pe32Plus(OptionalHeader64),
}

impl OptionalHeader32 {
    /// Size in bytes of the fixed part of the header, excluding data directories.
    pub const BASE_SIZE: usize = 96;

    /// Parse a PE32 optional header and its data directories.
    ///
    /// # Errors
    ///
    /// - Returns a buffer-too-small error if `data` is shorter than the fixed header, or shorter
    ///   than the data directories that `NumberOfRvaAndSizes` declares. As the loader does, the
    ///   parser reads at most [`NUMBER_OF_DIRECTORY_ENTRIES`] entries.
    /// - Returns an invalid-magic error if `Magic` is not [`PE32_MAGIC`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = Self::parse_with_any_magic(data)?;
        if header.magic != PE32_MAGIC {
            return Err(Error::invalid_optional_header_magic(header.magic));
        }
        Ok(header)
    }

    /// Parse the PE32 layout, and keep any `Magic` value.
    fn parse_with_any_magic(data: &[u8]) -> Result<Self> {
        let len = data.len();
        let Some((data, dir_bytes)) = data.split_first_chunk::<{ Self::BASE_SIZE }>() else {
            return Err(Error::buffer_too_small(Self::BASE_SIZE, len));
        };

        let magic = u16::from_le_bytes([data[0], data[1]]);
        let number_of_rva_and_sizes = u32::from_le_bytes([data[92], data[93], data[94], data[95]]);
        let data_directories =
            parse_data_directories(number_of_rva_and_sizes, Self::BASE_SIZE, dir_bytes, len)?;

        Ok(Self {
            magic,
            major_linker_version: data[2],
            minor_linker_version: data[3],
            size_of_code: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size_of_initialized_data: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            size_of_uninitialized_data: u32::from_le_bytes([
                data[12], data[13], data[14], data[15],
            ]),
            address_of_entry_point: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            base_of_code: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            base_of_data: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            image_base: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            section_alignment: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            file_alignment: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            major_operating_system_version: u16::from_le_bytes([data[40], data[41]]),
            minor_operating_system_version: u16::from_le_bytes([data[42], data[43]]),
            major_image_version: u16::from_le_bytes([data[44], data[45]]),
            minor_image_version: u16::from_le_bytes([data[46], data[47]]),
            major_subsystem_version: u16::from_le_bytes([data[48], data[49]]),
            minor_subsystem_version: u16::from_le_bytes([data[50], data[51]]),
            win32_version_value: u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            size_of_image: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            size_of_headers: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            check_sum: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            subsystem: u16::from_le_bytes([data[68], data[69]]),
            dll_characteristics: u16::from_le_bytes([data[70], data[71]]),
            size_of_stack_reserve: u32::from_le_bytes([data[72], data[73], data[74], data[75]]),
            size_of_stack_commit: u32::from_le_bytes([data[76], data[77], data[78], data[79]]),
            size_of_heap_reserve: u32::from_le_bytes([data[80], data[81], data[82], data[83]]),
            size_of_heap_commit: u32::from_le_bytes([data[84], data[85], data[86], data[87]]),
            loader_flags: u32::from_le_bytes([data[88], data[89], data[90], data[91]]),
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    /// Return the serialized size in bytes, including the data directories.
    #[must_use]
    pub fn size(&self) -> usize {
        directories_size(Self::BASE_SIZE, &self.data_directories)
    }

    /// Write the PE32 optional header to a buffer.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `buf` is shorter than [`Self::size`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let total_size = self.size();
        let len = buf.len();
        let Some((fixed, dirs)) = buf
            .get_mut(..total_size)
            .and_then(<[u8]>::split_first_chunk_mut::<{ Self::BASE_SIZE }>)
        else {
            return Err(Error::buffer_too_small(total_size, len));
        };
        *fixed = self.encode_fixed();
        encode_data_directories(&self.data_directories, dirs);
        Ok(())
    }

    /// Encode the fixed part of the header, without the data directories.
    fn encode_fixed(&self) -> [u8; Self::BASE_SIZE] {
        let mut buf = [0u8; Self::BASE_SIZE];
        buf[0..2].copy_from_slice(&self.magic.to_le_bytes());
        buf[2] = self.major_linker_version;
        buf[3] = self.minor_linker_version;
        buf[4..8].copy_from_slice(&self.size_of_code.to_le_bytes());
        buf[8..12].copy_from_slice(&self.size_of_initialized_data.to_le_bytes());
        buf[12..16].copy_from_slice(&self.size_of_uninitialized_data.to_le_bytes());
        buf[16..20].copy_from_slice(&self.address_of_entry_point.to_le_bytes());
        buf[20..24].copy_from_slice(&self.base_of_code.to_le_bytes());
        buf[24..28].copy_from_slice(&self.base_of_data.to_le_bytes());
        buf[28..32].copy_from_slice(&self.image_base.to_le_bytes());
        buf[32..36].copy_from_slice(&self.section_alignment.to_le_bytes());
        buf[36..40].copy_from_slice(&self.file_alignment.to_le_bytes());
        buf[40..42].copy_from_slice(&self.major_operating_system_version.to_le_bytes());
        buf[42..44].copy_from_slice(&self.minor_operating_system_version.to_le_bytes());
        buf[44..46].copy_from_slice(&self.major_image_version.to_le_bytes());
        buf[46..48].copy_from_slice(&self.minor_image_version.to_le_bytes());
        buf[48..50].copy_from_slice(&self.major_subsystem_version.to_le_bytes());
        buf[50..52].copy_from_slice(&self.minor_subsystem_version.to_le_bytes());
        buf[52..56].copy_from_slice(&self.win32_version_value.to_le_bytes());
        buf[56..60].copy_from_slice(&self.size_of_image.to_le_bytes());
        buf[60..64].copy_from_slice(&self.size_of_headers.to_le_bytes());
        buf[64..68].copy_from_slice(&self.check_sum.to_le_bytes());
        buf[68..70].copy_from_slice(&self.subsystem.to_le_bytes());
        buf[70..72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
        buf[72..76].copy_from_slice(&self.size_of_stack_reserve.to_le_bytes());
        buf[76..80].copy_from_slice(&self.size_of_stack_commit.to_le_bytes());
        buf[80..84].copy_from_slice(&self.size_of_heap_reserve.to_le_bytes());
        buf[84..88].copy_from_slice(&self.size_of_heap_commit.to_le_bytes());
        buf[88..92].copy_from_slice(&self.loader_flags.to_le_bytes());
        buf[92..96].copy_from_slice(&self.number_of_rva_and_sizes.to_le_bytes());
        buf
    }

    /// Serialize the header to a byte vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(&self.encode_fixed(), &self.data_directories)
    }
}

/// Parse the data directories that `NumberOfRvaAndSizes` declares from `dir_bytes`.
///
/// As the loader does, read at most [`NUMBER_OF_DIRECTORY_ENTRIES`] entries. `dir_bytes` holds
/// the bytes after a fixed header of `base_size` bytes. `total_len` is the length of the full
/// input. Only the errors use it.
fn parse_data_directories(
    number_of_rva_and_sizes: u32,
    base_size: usize,
    dir_bytes: &[u8],
    total_len: usize,
) -> Result<Vec<DataDirectory>> {
    let dirs_len = directory_count(number_of_rva_and_sizes) * DataDirectory::SIZE;
    let dir_bytes = dir_bytes
        .get(..dirs_len)
        .ok_or_else(|| Error::buffer_too_small(base_size + dirs_len, total_len))?;
    let (entries, _) = dir_bytes.as_chunks::<{ DataDirectory::SIZE }>();
    Ok(entries
        .iter()
        .copied()
        .map(DataDirectory::from_bytes)
        .collect())
}

/// Return the number of data directory entries that the loader reads.
///
/// The loader rounds a `NumberOfRvaAndSizes` larger than [`NUMBER_OF_DIRECTORY_ENTRIES`] down to
/// that value.
fn directory_count(number_of_rva_and_sizes: u32) -> usize {
    usize::try_from(number_of_rva_and_sizes).map_or(NUMBER_OF_DIRECTORY_ENTRIES, |count| {
        count.min(NUMBER_OF_DIRECTORY_ENTRIES)
    })
}

/// Return the serialized size of a header with a fixed part of `base_size` bytes and `dirs`.
fn directories_size(base_size: usize, dirs: &[DataDirectory]) -> usize {
    // A slice of `DataDirectory` holds at most `isize::MAX` bytes. Thus
    // `dirs.len() * DataDirectory::SIZE` is at most `isize::MAX`. The sum with a small fixed
    // header size cannot be more than `usize::MAX`.
    base_size + dirs.len() * DataDirectory::SIZE
}

/// Concatenate an encoded fixed header and the encoded data directories.
fn serialize(fixed: &[u8], dirs: &[DataDirectory]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(directories_size(fixed.len(), dirs));
    buf.extend_from_slice(fixed);
    for dir in dirs {
        buf.extend_from_slice(&dir.to_bytes());
    }
    buf
}

/// Encode `dirs` as consecutive `IMAGE_DATA_DIRECTORY` entries at the start of `buf`.
fn encode_data_directories(dirs: &[DataDirectory], buf: &mut [u8]) {
    let (entries, _) = buf.as_chunks_mut::<{ DataDirectory::SIZE }>();
    for (dir, out) in dirs.iter().zip(entries) {
        *out = dir.to_bytes();
    }
}

impl OptionalHeader64 {
    /// Size in bytes of the fixed part of the header, excluding data directories.
    pub const BASE_SIZE: usize = 112;

    /// Parse a PE32+ optional header and its data directories.
    ///
    /// # Errors
    ///
    /// - Returns a buffer-too-small error if `data` is shorter than the fixed header, or shorter
    ///   than the data directories that `NumberOfRvaAndSizes` declares. As the loader does, the
    ///   parser reads at most [`NUMBER_OF_DIRECTORY_ENTRIES`] entries.
    /// - Returns an invalid-magic error if `Magic` is not [`PE32PLUS_MAGIC`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = Self::parse_with_any_magic(data)?;
        if header.magic != PE32PLUS_MAGIC {
            return Err(Error::invalid_optional_header_magic(header.magic));
        }
        Ok(header)
    }

    /// Parse the PE32+ layout, and keep any `Magic` value.
    fn parse_with_any_magic(data: &[u8]) -> Result<Self> {
        let len = data.len();
        let Some((data, dir_bytes)) = data.split_first_chunk::<{ Self::BASE_SIZE }>() else {
            return Err(Error::buffer_too_small(Self::BASE_SIZE, len));
        };

        let magic = u16::from_le_bytes([data[0], data[1]]);
        let number_of_rva_and_sizes =
            u32::from_le_bytes([data[108], data[109], data[110], data[111]]);
        let data_directories =
            parse_data_directories(number_of_rva_and_sizes, Self::BASE_SIZE, dir_bytes, len)?;

        Ok(Self {
            magic,
            major_linker_version: data[2],
            minor_linker_version: data[3],
            size_of_code: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size_of_initialized_data: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            size_of_uninitialized_data: u32::from_le_bytes([
                data[12], data[13], data[14], data[15],
            ]),
            address_of_entry_point: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            base_of_code: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            image_base: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            section_alignment: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            file_alignment: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            major_operating_system_version: u16::from_le_bytes([data[40], data[41]]),
            minor_operating_system_version: u16::from_le_bytes([data[42], data[43]]),
            major_image_version: u16::from_le_bytes([data[44], data[45]]),
            minor_image_version: u16::from_le_bytes([data[46], data[47]]),
            major_subsystem_version: u16::from_le_bytes([data[48], data[49]]),
            minor_subsystem_version: u16::from_le_bytes([data[50], data[51]]),
            win32_version_value: u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            size_of_image: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            size_of_headers: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            check_sum: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            subsystem: u16::from_le_bytes([data[68], data[69]]),
            dll_characteristics: u16::from_le_bytes([data[70], data[71]]),
            size_of_stack_reserve: u64::from_le_bytes([
                data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
            ]),
            size_of_stack_commit: u64::from_le_bytes([
                data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
            ]),
            size_of_heap_reserve: u64::from_le_bytes([
                data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
            ]),
            size_of_heap_commit: u64::from_le_bytes([
                data[96], data[97], data[98], data[99], data[100], data[101], data[102], data[103],
            ]),
            loader_flags: u32::from_le_bytes([data[104], data[105], data[106], data[107]]),
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    /// Return the serialized size in bytes, including the data directories.
    #[must_use]
    pub fn size(&self) -> usize {
        directories_size(Self::BASE_SIZE, &self.data_directories)
    }

    /// Write the PE32+ optional header to a buffer.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `buf` is shorter than [`Self::size`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let total_size = self.size();
        let len = buf.len();
        let Some((fixed, dirs)) = buf
            .get_mut(..total_size)
            .and_then(<[u8]>::split_first_chunk_mut::<{ Self::BASE_SIZE }>)
        else {
            return Err(Error::buffer_too_small(total_size, len));
        };
        *fixed = self.encode_fixed();
        encode_data_directories(&self.data_directories, dirs);
        Ok(())
    }

    /// Encode the fixed part of the header, without the data directories.
    fn encode_fixed(&self) -> [u8; Self::BASE_SIZE] {
        let mut buf = [0u8; Self::BASE_SIZE];
        buf[0..2].copy_from_slice(&self.magic.to_le_bytes());
        buf[2] = self.major_linker_version;
        buf[3] = self.minor_linker_version;
        buf[4..8].copy_from_slice(&self.size_of_code.to_le_bytes());
        buf[8..12].copy_from_slice(&self.size_of_initialized_data.to_le_bytes());
        buf[12..16].copy_from_slice(&self.size_of_uninitialized_data.to_le_bytes());
        buf[16..20].copy_from_slice(&self.address_of_entry_point.to_le_bytes());
        buf[20..24].copy_from_slice(&self.base_of_code.to_le_bytes());
        buf[24..32].copy_from_slice(&self.image_base.to_le_bytes());
        buf[32..36].copy_from_slice(&self.section_alignment.to_le_bytes());
        buf[36..40].copy_from_slice(&self.file_alignment.to_le_bytes());
        buf[40..42].copy_from_slice(&self.major_operating_system_version.to_le_bytes());
        buf[42..44].copy_from_slice(&self.minor_operating_system_version.to_le_bytes());
        buf[44..46].copy_from_slice(&self.major_image_version.to_le_bytes());
        buf[46..48].copy_from_slice(&self.minor_image_version.to_le_bytes());
        buf[48..50].copy_from_slice(&self.major_subsystem_version.to_le_bytes());
        buf[50..52].copy_from_slice(&self.minor_subsystem_version.to_le_bytes());
        buf[52..56].copy_from_slice(&self.win32_version_value.to_le_bytes());
        buf[56..60].copy_from_slice(&self.size_of_image.to_le_bytes());
        buf[60..64].copy_from_slice(&self.size_of_headers.to_le_bytes());
        buf[64..68].copy_from_slice(&self.check_sum.to_le_bytes());
        buf[68..70].copy_from_slice(&self.subsystem.to_le_bytes());
        buf[70..72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
        buf[72..80].copy_from_slice(&self.size_of_stack_reserve.to_le_bytes());
        buf[80..88].copy_from_slice(&self.size_of_stack_commit.to_le_bytes());
        buf[88..96].copy_from_slice(&self.size_of_heap_reserve.to_le_bytes());
        buf[96..104].copy_from_slice(&self.size_of_heap_commit.to_le_bytes());
        buf[104..108].copy_from_slice(&self.loader_flags.to_le_bytes());
        buf[108..112].copy_from_slice(&self.number_of_rva_and_sizes.to_le_bytes());
        buf
    }

    /// Serialize the header to a byte vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(&self.encode_fixed(), &self.data_directories)
    }
}

impl OptionalHeader {
    /// Parse a PE32 or PE32+ optional header. The `Magic` field selects the format.
    ///
    /// # Errors
    ///
    /// - Returns a buffer-too-small error if `data` is too short.
    /// - Returns an invalid-magic error if `Magic` is not [`PE32_MAGIC`] or [`PE32PLUS_MAGIC`].
    /// - Returns any error from [`OptionalHeader32::parse`] or [`OptionalHeader64::parse`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(&magic_bytes) = data.first_chunk::<2>() else {
            return Err(Error::buffer_too_small(2, data.len()));
        };

        let magic = u16::from_le_bytes(magic_bytes);
        match magic {
            PE32_MAGIC => Ok(Self::Pe32(OptionalHeader32::parse(data)?)),
            PE32PLUS_MAGIC => Ok(Self::Pe32Plus(OptionalHeader64::parse(data)?)),
            _ => Err(Error::invalid_optional_header_magic(magic)),
        }
    }

    /// Return `true` if this is a PE32 (32-bit) optional header.
    #[must_use]
    pub fn is_pe32(&self) -> bool {
        matches!(self, Self::Pe32(_))
    }

    /// Return `true` if this is a PE32+ (64-bit) optional header.
    #[must_use]
    pub fn is_pe32plus(&self) -> bool {
        matches!(self, Self::Pe32Plus(_))
    }

    /// Return the serialized size in bytes, including the data directories.
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Self::Pe32(h) => h.size(),
            Self::Pe32Plus(h) => h.size(),
        }
    }

    /// Return the data directory entries after the fixed part of the header.
    #[must_use]
    pub fn data_directories(&self) -> &[DataDirectory] {
        match self {
            Self::Pe32(h) => &h.data_directories,
            Self::Pe32Plus(h) => &h.data_directories,
        }
    }

    /// Return a mutable reference to the data directory entries.
    pub fn data_directories_mut(&mut self) -> &mut Vec<DataDirectory> {
        match self {
            Self::Pe32(h) => &mut h.data_directories,
            Self::Pe32Plus(h) => &mut h.data_directories,
        }
    }

    /// Write the optional header to a buffer.
    ///
    /// # Errors
    ///
    /// Returns a buffer-too-small error if `buf` is shorter than [`Self::size`].
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Pe32(h) => h.write(buf),
            Self::Pe32Plus(h) => h.write(buf),
        }
    }

    /// Serialize the header to a byte vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pe32(h) => h.to_bytes(),
            Self::Pe32Plus(h) => h.to_bytes(),
        }
    }

    /// Read an optional header from a [`ReadAt`] reader at the file offset `offset`.
    ///
    /// As the loader does, the method reads the fixed header and at most
    /// [`NUMBER_OF_DIRECTORY_ENTRIES`] data directories. It ignores `SizeOfOptionalHeader`: that
    /// field only gives the offset of the section table. Thus the header can overlap the section
    /// table.
    ///
    /// # Errors
    ///
    /// - Returns a read error if the reader cannot read the header.
    /// - Returns an invalid-magic error for an unknown `Magic`.
    /// - Returns an invalid-data-directory error if the header offset overflows.
    /// - Returns any error from [`Self::parse`].
    pub fn read_from<R: ReadAt>(reader: &R, offset: u64) -> Result<Self> {
        let magic = reader.read_u16_at(offset)?;
        match magic {
            PE32_MAGIC => Self::read_layout(reader, offset, false),
            PE32PLUS_MAGIC => Self::read_layout(reader, offset, true),
            _ => Err(Error::invalid_optional_header_magic(magic)),
        }
    }

    /// Read an optional header as [`Self::read_from`] does, but accept an unknown `Magic`.
    ///
    /// For an unknown `Magic`, the method uses the PE32+ layout if `machine` is a 64-bit machine
    /// type, and the PE32 layout for all other values. The header keeps the `Magic` value.
    pub(crate) fn read_for_machine<R: ReadAt>(
        reader: &R,
        offset: u64,
        machine: u16,
    ) -> Result<Self> {
        let pe32plus = match reader.read_u16_at(offset)? {
            PE32_MAGIC => false,
            PE32PLUS_MAGIC => true,
            _ => crate::coff::MachineType::from_u16(machine)
                .is_some_and(crate::coff::MachineType::is_64_bit),
        };
        Self::read_layout(reader, offset, pe32plus)
    }

    /// Read the PE32 or the PE32+ layout, and keep any `Magic` value.
    fn read_layout<R: ReadAt>(reader: &R, offset: u64, pe32plus: bool) -> Result<Self> {
        let (base_size, count_relative) = if pe32plus {
            (OptionalHeader64::BASE_SIZE, 108u64)
        } else {
            (OptionalHeader32::BASE_SIZE, 92u64)
        };
        let num_dirs_offset = offset
            .checked_add(count_relative)
            .ok_or_else(|| Error::invalid_data_directory("optional-header offset overflow"))?;
        let num_dirs = directory_count(reader.read_u32_at(num_dirs_offset)?);
        let data = reader.read_bytes_at(offset, base_size + num_dirs * DataDirectory::SIZE)?;
        Ok(if pe32plus {
            Self::Pe32Plus(OptionalHeader64::parse_with_any_magic(&data)?)
        } else {
            Self::Pe32(OptionalHeader32::parse_with_any_magic(&data)?)
        })
    }

    /// Return the RVA of the entry point.
    #[must_use]
    pub fn address_of_entry_point(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.address_of_entry_point,
            Self::Pe32Plus(h) => h.address_of_entry_point,
        }
    }

    /// Return the preferred VA of the image base.
    #[must_use]
    pub fn image_base(&self) -> u64 {
        match self {
            Self::Pe32(h) => u64::from(h.image_base),
            Self::Pe32Plus(h) => h.image_base,
        }
    }

    /// Return the section alignment in bytes.
    #[must_use]
    pub fn section_alignment(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.section_alignment,
            Self::Pe32Plus(h) => h.section_alignment,
        }
    }

    /// Return the file alignment in bytes.
    #[must_use]
    pub fn file_alignment(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.file_alignment,
            Self::Pe32Plus(h) => h.file_alignment,
        }
    }

    /// Return the size of the loaded image in bytes.
    #[must_use]
    pub fn size_of_image(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.size_of_image,
            Self::Pe32Plus(h) => h.size_of_image,
        }
    }

    /// Return the combined size of all headers in bytes.
    #[must_use]
    pub fn size_of_headers(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.size_of_headers,
            Self::Pe32Plus(h) => h.size_of_headers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_header_sizes() {
        assert_eq!(OptionalHeader32::BASE_SIZE, 96);
        assert_eq!(OptionalHeader64::BASE_SIZE, 112);
    }

    #[test]
    fn test_subsystem_from_u16() {
        assert_eq!(Subsystem::from_u16(2), Some(Subsystem::WindowsGui));
        assert_eq!(Subsystem::from_u16(3), Some(Subsystem::WindowsCui));
        assert_eq!(Subsystem::from_u16(255), None);
    }
}
