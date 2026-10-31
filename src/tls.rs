//! Parse and build the TLS (thread local storage) directory.
//!
//! The TLS directory describes the thread local storage of an image. It also points to the
//! TLS callbacks. The loader calls these callbacks before the entry point.
//!
//! # Examples
//!
//! ## Reading TLS information from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! if let Some(tls) = pe.tls()? {
//!     if let Some(ref dir) = tls.directory {
//!         println!("TLS callbacks VA: {:#x}", dir.callbacks_va());
//!     }
//!     println!("Callback RVAs:");
//!     for &callback in &tls.callback_rvas {
//!         println!("  {:#x}", callback);
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// `IMAGE_TLS_DIRECTORY32`: the 24-byte PE32 TLS directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsDirectory32 {
    /// Starting address of the TLS template (VA).
    pub start_address_of_raw_data: u32,
    /// Ending address of the TLS template (VA).
    pub end_address_of_raw_data: u32,
    /// Address of the TLS index (VA).
    pub address_of_index: u32,
    /// Address of the TLS callback array (VA).
    pub address_of_callbacks: u32,
    /// Size of the zero-filled area in bytes.
    pub size_of_zero_fill: u32,
    /// Characteristics (reserved, usually 0).
    pub characteristics: u32,
}

impl TlsDirectory32 {
    /// Size of an encoded `IMAGE_TLS_DIRECTORY32`, in bytes.
    pub const SIZE: usize = 24;

    /// Parse an `IMAGE_TLS_DIRECTORY32` from little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        Ok(Self {
            start_address_of_raw_data: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            end_address_of_raw_data: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            address_of_index: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            address_of_callbacks: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_zero_fill: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            characteristics: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        })
    }

    /// Encode the directory into its 24-byte little-endian representation.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.start_address_of_raw_data.to_le_bytes());
        buf[4..8].copy_from_slice(&self.end_address_of_raw_data.to_le_bytes());
        buf[8..12].copy_from_slice(&self.address_of_index.to_le_bytes());
        buf[12..16].copy_from_slice(&self.address_of_callbacks.to_le_bytes());
        buf[16..20].copy_from_slice(&self.size_of_zero_fill.to_le_bytes());
        buf[20..24].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }
}

/// `IMAGE_TLS_DIRECTORY64`: the 40-byte PE32+ TLS directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsDirectory64 {
    /// Starting address of the TLS template (VA).
    pub start_address_of_raw_data: u64,
    /// Ending address of the TLS template (VA).
    pub end_address_of_raw_data: u64,
    /// Address of the TLS index (VA).
    pub address_of_index: u64,
    /// Address of the TLS callback array (VA).
    pub address_of_callbacks: u64,
    /// Size of the zero-filled area in bytes.
    pub size_of_zero_fill: u32,
    /// Characteristics (reserved, usually 0).
    pub characteristics: u32,
}

impl TlsDirectory64 {
    /// Size of an encoded `IMAGE_TLS_DIRECTORY64`, in bytes.
    pub const SIZE: usize = 40;

    /// Parse an `IMAGE_TLS_DIRECTORY64` from little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is shorter than [`Self::SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let Some(data) = data.first_chunk::<{ Self::SIZE }>() else {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        };

        Ok(Self {
            start_address_of_raw_data: u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            end_address_of_raw_data: u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
            address_of_index: u64::from_le_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
            address_of_callbacks: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            size_of_zero_fill: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            characteristics: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
        })
    }

    /// Encode the directory into its 40-byte little-endian representation.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.start_address_of_raw_data.to_le_bytes());
        buf[8..16].copy_from_slice(&self.end_address_of_raw_data.to_le_bytes());
        buf[16..24].copy_from_slice(&self.address_of_index.to_le_bytes());
        buf[24..32].copy_from_slice(&self.address_of_callbacks.to_le_bytes());
        buf[32..36].copy_from_slice(&self.size_of_zero_fill.to_le_bytes());
        buf[36..40].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }
}

/// A TLS directory of a PE32 or PE32+ image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsDirectory {
    /// PE32 directory (`IMAGE_TLS_DIRECTORY32`).
    Tls32(TlsDirectory32),
    /// PE32+ directory (`IMAGE_TLS_DIRECTORY64`).
    Tls64(TlsDirectory64),
}

impl TlsDirectory {
    /// Parse a TLS directory from bytes.
    ///
    /// `is_64bit` selects the 64-bit layout. Otherwise, the function uses the 32-bit layout.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is shorter than the selected directory size.
    pub fn parse(data: &[u8], is_64bit: bool) -> Result<Self> {
        if is_64bit {
            Ok(Self::Tls64(TlsDirectory64::parse(data)?))
        } else {
            Ok(Self::Tls32(TlsDirectory32::parse(data)?))
        }
    }

    /// Serialize the directory to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Tls32(tls) => tls.to_bytes().to_vec(),
            Self::Tls64(tls) => tls.to_bytes().to_vec(),
        }
    }

    /// Return the size of the TLS directory in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Self::Tls32(_) => TlsDirectory32::SIZE,
            Self::Tls64(_) => TlsDirectory64::SIZE,
        }
    }

    /// Return the VA of the callback array.
    #[must_use]
    pub fn callbacks_va(&self) -> u64 {
        match self {
            Self::Tls32(tls) => u64::from(tls.address_of_callbacks),
            Self::Tls64(tls) => tls.address_of_callbacks,
        }
    }

    /// Return `true` if the callback array address is not zero.
    #[must_use]
    pub fn has_callbacks(&self) -> bool {
        self.callbacks_va() != 0
    }
}

/// Parsed TLS information, with the callbacks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsInfo {
    /// The TLS directory.
    pub directory: Option<TlsDirectory>,
    /// Callback RVAs, converted from the VAs in the callback array.
    pub callback_rvas: Vec<u32>,
    /// Image base that converts the absolute VAs of the directory to RVAs.
    pub image_base: u64,
}

/// Maximum number of TLS callback array entries to scan for the null terminator.
const MAX_TLS_CALLBACKS: usize = 65_536;

impl TlsInfo {
    /// Parse TLS information from a PE image.
    ///
    /// `tls_rva` and `tls_size` come from the data directory. The function uses `image_base`
    /// to convert VAs to RVAs.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - `tls_size` is smaller than the directory structure.
    /// - `read_at_rva` cannot read the directory or a callback array slot.
    /// - The raw data, index, or callback VAs are below `image_base` or outside the 32-bit
    ///   RVA space.
    /// - Only one end of the raw data range is zero, or the range is reversed.
    /// - The callback array has no null terminator within 65,536 entries.
    pub fn parse<F>(
        tls_rva: u32,
        tls_size: u32,
        image_base: u64,
        is_64bit: bool,
        read_at_rva: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let dir_size = if is_64bit {
            TlsDirectory64::SIZE
        } else {
            TlsDirectory32::SIZE
        };
        if usize::try_from(tls_size).is_ok_and(|size| size < dir_size) {
            return Err(Error::invalid_data_directory(format!(
                "TLS directory size {tls_size} is smaller than {dir_size}"
            )));
        }
        let data = read_at_rva(tls_rva, dir_size).ok_or(Error::invalid_rva(tls_rva))?;
        let directory = TlsDirectory::parse(&data, is_64bit)?;
        validate_directory_vas(&directory, image_base)?;

        let callback_rvas = if directory.has_callbacks() {
            read_callback_rvas(directory.callbacks_va(), image_base, is_64bit, &read_at_rva)?
        } else {
            Vec::new()
        };

        Ok(Self {
            directory: Some(directory),
            callback_rvas,
            image_base,
        })
    }
}

/// Check that the raw-data range and index VAs of `directory` map to RVAs.
fn validate_directory_vas(directory: &TlsDirectory, image_base: u64) -> Result<()> {
    let (raw_start, raw_end, index_va) = match directory {
        TlsDirectory::Tls32(directory) => (
            u64::from(directory.start_address_of_raw_data),
            u64::from(directory.end_address_of_raw_data),
            u64::from(directory.address_of_index),
        ),
        TlsDirectory::Tls64(directory) => (
            directory.start_address_of_raw_data,
            directory.end_address_of_raw_data,
            directory.address_of_index,
        ),
    };
    if (raw_start == 0) != (raw_end == 0) {
        return Err(Error::invalid_data_directory(
            "TLS raw-data start and end must either both be zero or both be VAs",
        ));
    }
    if raw_start != 0 {
        let start_rva = va_to_rva(raw_start, image_base)?;
        let end_rva = va_to_rva(raw_end, image_base)?;
        if end_rva < start_rva {
            return Err(Error::invalid_data_directory(
                "TLS raw-data end precedes its start",
            ));
        }
    }
    if index_va != 0 {
        va_to_rva(index_va, image_base)?;
    }
    Ok(())
}

/// Read the null-terminated TLS callback array at `array_va` and convert each
/// callback VA to an RVA.
fn read_callback_rvas<F>(
    array_va: u64,
    image_base: u64,
    is_64bit: bool,
    read_at_rva: &F,
) -> Result<Vec<u32>>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    if array_va < image_base {
        return Err(Error::invalid_data_directory(format!(
            "TLS callback array VA {array_va:#x} is below image base {image_base:#x}"
        )));
    }
    let first_slot_rva = array_va
        .checked_sub(image_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "TLS callback array VA {array_va:#x} is outside image base {image_base:#x}"
            ))
        })?;
    let (ptr_size, ptr_stride): (usize, u32) = if is_64bit { (8, 8) } else { (4, 4) };
    let mut callback_rvas = Vec::new();
    let mut offset = 0u32;

    for _ in 0..MAX_TLS_CALLBACKS {
        let slot_rva = first_slot_rva
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_data_directory("TLS callback-array RVA overflow"))?;
        let ptr_data = read_at_rva(slot_rva, ptr_size).ok_or(Error::invalid_rva(slot_rva))?;
        let too_small = || Error::buffer_too_small(ptr_size, ptr_data.len());
        let callback_address = if is_64bit {
            u64::from_le_bytes(*ptr_data.first_chunk::<8>().ok_or_else(too_small)?)
        } else {
            u64::from(u32::from_le_bytes(
                *ptr_data.first_chunk::<4>().ok_or_else(too_small)?,
            ))
        };

        // Null terminator.
        if callback_address == 0 {
            break;
        }

        // Convert the VA to an RVA.
        let callback_rva = callback_address.checked_sub(image_base).ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "TLS callback VA {callback_address:#x} is below image base {image_base:#x}"
            ))
        })?;
        let callback_rva = u32::try_from(callback_rva).map_err(|_| {
            Error::invalid_data_directory(format!(
                "TLS callback VA {callback_address:#x} is outside the 32-bit RVA space"
            ))
        })?;
        callback_rvas.push(callback_rva);
        offset = offset
            .checked_add(ptr_stride)
            .ok_or_else(|| Error::invalid_data_directory("TLS callback-array size overflow"))?;
    }

    if callback_rvas.len() == MAX_TLS_CALLBACKS {
        return Err(Error::invalid_data_directory(
            "TLS callback array is missing a terminator",
        ));
    }
    Ok(callback_rvas)
}

/// A builder for TLS directories.
///
/// A TLS directory contains thread local storage initialization data and callbacks. The
/// callbacks are function pointers. The loader calls them before the entry point.
///
/// # Example
///
/// ```
/// use portex::tls::TlsBuilder;
///
/// // Create a TLS builder for 64-bit PE
/// let builder = TlsBuilder::new(0x3000, 0x0001_4000_0000, true);
///
/// // Build with TLS data region and no callbacks
/// let (data, dir_size) = builder.build(0x1000, 0x1100, &[]);
/// assert!(dir_size > 0);
/// ```
#[derive(Debug, Clone)]
pub struct TlsBuilder {
    /// Base RVA of the TLS block.
    base_rva: u32,
    /// Image base, which converts RVAs to VAs.
    image_base: u64,
    /// `true` if the image is a 64-bit PE (PE32+).
    is_64bit: bool,
}

/// The byte layout of the TLS block that [`TlsBuilder`] emits.
///
/// The block is `[directory][TLS index (4 bytes)][padding][null-terminated callback array]`.
/// The block always holds the index slot. If the rebuilt directory keeps its original
/// `AddressOfIndex`, the slot stays zero and is not used.
struct TlsLayout {
    /// Size of the TLS directory structure. This is also the offset of the TLS index.
    dir_size: usize,
    /// Offset of the callback array in the block, aligned to the pointer size.
    callbacks_offset: usize,
    /// Total size of the block.
    total_size: usize,
    /// The `dir_size` value that the data directory stores.
    dir_size_u32: u32,
    /// `total_size` as a 32-bit length.
    total_size_u32: u32,
}

impl TlsBuilder {
    /// Create a new TLS builder.
    ///
    /// # Arguments
    /// * `base_rva` - RVA of the TLS block
    /// * `image_base` - Image base for VA calculations
    /// * `is_64bit` - `true` if the target is a 64-bit PE (PE32+)
    #[must_use]
    pub fn new(base_rva: u32, image_base: u64, is_64bit: bool) -> Self {
        Self {
            base_rva,
            image_base,
            is_64bit,
        }
    }

    /// Build the TLS directory data.
    ///
    /// # Arguments
    /// * `raw_data_start_rva` - RVA of the TLS raw data start
    /// * `raw_data_end_rva` - RVA of the TLS raw data end
    /// * `callback_rvas` - List of callback function RVAs
    ///
    /// Returns `(data, directory_size)`:
    /// - `data` is the raw bytes to write to the section.
    /// - `directory_size` is the size of the TLS directory, for the data directory.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails. Use [`Self::try_build`] for fallible serialization.
    #[must_use]
    pub fn build(
        &self,
        raw_data_start_rva: u32,
        raw_data_end_rva: u32,
        callback_rvas: &[u32],
    ) -> (Vec<u8>, u32) {
        self.try_build(raw_data_start_rva, raw_data_end_rva, callback_rvas)
            .expect("TLS build failed: use try_build() for fallible serialization")
    }

    /// Build the TLS data with checked VA, RVA and size arithmetic.
    ///
    /// `AddressOfIndex` points to the 4-byte index slot in the new block.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The raw data range is reversed, or only one end of it is zero.
    /// - The block size or an RVA or VA calculation overflows.
    /// - A PE32 VA does not fit in 32 bits.
    pub fn try_build(
        &self,
        raw_data_start_rva: u32,
        raw_data_end_rva: u32,
        callback_rvas: &[u32],
    ) -> Result<(Vec<u8>, u32)> {
        self.build_block(
            raw_data_start_rva,
            raw_data_end_rva,
            callback_rvas,
            0,
            0,
            None,
        )
    }

    /// Build the TLS block with the given `SizeOfZeroFill` and
    /// `Characteristics` values.
    ///
    /// If `index_address` is `None`, `AddressOfIndex` points to the index slot in the block.
    fn build_block(
        &self,
        raw_data_start_rva: u32,
        raw_data_end_rva: u32,
        callback_rvas: &[u32],
        size_of_zero_fill: u32,
        characteristics: u32,
        index_address: Option<u64>,
    ) -> Result<(Vec<u8>, u32)> {
        if raw_data_end_rva < raw_data_start_rva {
            return Err(Error::invalid_data_directory(
                "TLS raw-data end precedes its start",
            ));
        }
        if (raw_data_start_rva == 0) != (raw_data_end_rva == 0) {
            return Err(Error::invalid_data_directory(
                "TLS raw-data start and end must either both be zero or both be RVAs",
            ));
        }
        let layout = self.layout(callback_rvas.len())?;
        self.base_rva
            .checked_add(layout.total_size_u32)
            .ok_or_else(|| Error::invalid_data_directory("TLS data RVA range overflow"))?;

        // Convert the RVAs to VAs.
        let (raw_start_address, raw_end_address) = if raw_data_start_rva == 0 {
            (0, 0)
        } else {
            (
                checked_va(
                    self.image_base,
                    u64::from(raw_data_start_rva),
                    "TLS raw-data start",
                )?,
                checked_va(
                    self.image_base,
                    u64::from(raw_data_end_rva),
                    "TLS raw-data end",
                )?,
            )
        };
        let index_address = match index_address {
            Some(address) => address,
            None => self.block_va(layout.dir_size, "TLS index")?,
        };
        let array_address = if callback_rvas.is_empty() {
            0 // No callbacks
        } else {
            self.block_va(layout.callbacks_offset, "TLS callback array")?
        };

        let mut data = Vec::with_capacity(layout.total_size);
        self.push_directory(
            &mut data,
            TlsDirectory64 {
                start_address_of_raw_data: raw_start_address,
                end_address_of_raw_data: raw_end_address,
                address_of_index: index_address,
                address_of_callbacks: array_address,
                size_of_zero_fill,
                characteristics,
            },
        )?;

        // Write the TLS index (initialized to 0).
        data.extend_from_slice(&0u32.to_le_bytes());
        data.resize(layout.callbacks_offset, 0);

        // Write the callback array.
        for &callback_rva in callback_rvas {
            let callback_address =
                checked_va(self.image_base, u64::from(callback_rva), "TLS callback")?;
            self.push_pointer(&mut data, callback_address)?;
        }

        // Write the null terminator of the callback array.
        self.push_pointer(&mut data, 0)?;

        Ok((data, layout.dir_size_u32))
    }

    /// Calculate the serialized layout for `num_callbacks` callbacks.
    fn layout(&self, num_callbacks: usize) -> Result<TlsLayout> {
        let ptr_size: usize = if self.is_64bit { 8 } else { 4 };
        let dir_size = if self.is_64bit {
            TlsDirectory64::SIZE
        } else {
            TlsDirectory32::SIZE
        };
        let callbacks_offset = dir_size
            .checked_add(4)
            .and_then(|size| size.checked_next_multiple_of(ptr_size))
            .ok_or_else(|| Error::invalid_data_directory("TLS callback alignment overflow"))?;
        let callback_bytes = num_callbacks
            .checked_add(1)
            .and_then(|count| count.checked_mul(ptr_size))
            .ok_or_else(|| Error::invalid_data_directory("TLS callback-array size overflow"))?;
        let total_size = callbacks_offset
            .checked_add(callback_bytes)
            .ok_or_else(|| Error::invalid_data_directory("TLS data size overflow"))?;
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| Error::invalid_data_directory("TLS data exceeds u32"))?;
        let dir_size_u32 = u32::try_from(dir_size)
            .map_err(|_| Error::invalid_data_directory("TLS data exceeds u32"))?;
        Ok(TlsLayout {
            dir_size,
            callbacks_offset,
            total_size,
            dir_size_u32,
            total_size_u32,
        })
    }

    /// Return the VA of the byte at `offset` in the TLS block.
    fn block_va(&self, offset: usize, context: &str) -> Result<u64> {
        let offset = u32::try_from(offset)
            .map_err(|_| Error::invalid_data_directory(format!("{context} offset exceeds u32")))?;
        let rva = self
            .base_rva
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))?;
        checked_va(self.image_base, u64::from(rva), context)
    }

    /// Append `directory` in the target bitness. For PE32, narrow the VAs to 32 bits.
    fn push_directory(&self, data: &mut Vec<u8>, directory: TlsDirectory64) -> Result<()> {
        if self.is_64bit {
            data.extend_from_slice(&directory.to_bytes());
            return Ok(());
        }
        let narrow = |va: u64, message: &'static str| {
            u32::try_from(va).map_err(|_| Error::invalid_data_directory(message))
        };
        let directory = TlsDirectory32 {
            start_address_of_raw_data: narrow(
                directory.start_address_of_raw_data,
                "PE32 TLS start VA exceeds u32",
            )?,
            end_address_of_raw_data: narrow(
                directory.end_address_of_raw_data,
                "PE32 TLS end VA exceeds u32",
            )?,
            address_of_index: narrow(directory.address_of_index, "PE32 TLS index VA exceeds u32")?,
            address_of_callbacks: narrow(
                directory.address_of_callbacks,
                "PE32 TLS callback-array VA exceeds u32",
            )?,
            size_of_zero_fill: directory.size_of_zero_fill,
            characteristics: directory.characteristics,
        };
        data.extend_from_slice(&directory.to_bytes());
        Ok(())
    }

    /// Append one callback-array pointer in the target bitness.
    fn push_pointer(&self, data: &mut Vec<u8>, va: u64) -> Result<()> {
        if self.is_64bit {
            data.extend_from_slice(&va.to_le_bytes());
        } else {
            let va = u32::try_from(va)
                .map_err(|_| Error::invalid_data_directory("PE32 TLS callback VA exceeds u32"))?;
            data.extend_from_slice(&va.to_le_bytes());
        }
        Ok(())
    }

    /// Build the TLS block from an existing [`TlsInfo`].
    ///
    /// This function rebuilds the TLS directory from the parsed information.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build_from_info`] fails. Use [`Self::try_build_from_info`] for
    /// fallible serialization.
    #[must_use]
    pub fn build_from_info(&self, tls_info: &TlsInfo) -> (Vec<u8>, u32) {
        self.try_build_from_info(tls_info)
            .expect("TLS build failed: use try_build_from_info() for fallible serialization")
    }

    /// Rebuild parsed TLS information for the image base of this builder.
    ///
    /// The function rebases the VA fields to the image base of the builder. It keeps the
    /// `SizeOfZeroFill` and `Characteristics` values.
    ///
    /// The function also keeps the TLS index (`AddressOfIndex`), rebased in the same way. The
    /// code of the image reads its TLS slot number from this address. If `AddressOfIndex` is
    /// zero, or if `tls_info` has no directory, the function points `AddressOfIndex` to a new
    /// zeroed slot in the block.
    ///
    /// # Errors
    ///
    /// Returns an error in these conditions:
    /// - The directory bitness is not the same as the bitness of the builder.
    /// - A raw data VA or the index VA is outside the 32-bit RVA space of
    ///   `tls_info.image_base`.
    /// - [`Self::try_build`] fails.
    pub fn try_build_from_info(&self, tls_info: &TlsInfo) -> Result<(Vec<u8>, u32)> {
        if matches!(tls_info.directory, Some(TlsDirectory::Tls64(_))) != self.is_64bit
            && tls_info.directory.is_some()
        {
            return Err(Error::invalid_data_directory(
                "TLS directory bitness does not match the target image",
            ));
        }
        let (raw_start_va, raw_end_va, index_va, size_of_zero_fill, characteristics) =
            match &tls_info.directory {
                Some(TlsDirectory::Tls32(dir)) => (
                    u64::from(dir.start_address_of_raw_data),
                    u64::from(dir.end_address_of_raw_data),
                    u64::from(dir.address_of_index),
                    dir.size_of_zero_fill,
                    dir.characteristics,
                ),
                Some(TlsDirectory::Tls64(dir)) => (
                    dir.start_address_of_raw_data,
                    dir.end_address_of_raw_data,
                    dir.address_of_index,
                    dir.size_of_zero_fill,
                    dir.characteristics,
                ),
                None => (0, 0, 0, 0, 0),
            };
        let raw_start = va_to_rva(raw_start_va, tls_info.image_base)?;
        let raw_end = va_to_rva(raw_end_va, tls_info.image_base)?;
        let index_address = match va_to_rva(index_va, tls_info.image_base)? {
            0 => None,
            rva => Some(checked_va(self.image_base, u64::from(rva), "TLS index")?),
        };

        self.build_block(
            raw_start,
            raw_end,
            &tls_info.callback_rvas,
            size_of_zero_fill,
            characteristics,
            index_address,
        )
    }

    /// Return the offsets in `block` of the VAs that need base relocations.
    ///
    /// `block` is a block that this builder made. The offsets are those of the directory VA
    /// fields and of the callback array entries that are not zero, in ascending order.
    pub(crate) fn va_offsets(&self, block: &[u8]) -> Vec<usize> {
        let pointer_size = if self.is_64bit { 8 } else { 4 };
        let directory_fields = (0..4).map(|index| index * pointer_size);
        let callbacks = self
            .layout(0)
            .map_or(block.len(), |layout| layout.callbacks_offset);
        let callback_slots = (callbacks..block.len()).step_by(pointer_size);
        directory_fields
            .chain(callback_slots)
            .filter(|&offset| {
                block
                    .get(offset..)
                    .and_then(|rest| rest.get(..pointer_size))
                    .is_some_and(|value| value.iter().any(|&byte| byte != 0))
            })
            .collect()
    }

    /// Calculate the size in bytes of the TLS data.
    ///
    /// # Panics
    ///
    /// Panics if the size exceeds `u32`. Use [`Self::try_calculate_size`] for a fallible
    /// calculation.
    #[must_use]
    pub fn calculate_size(&self, num_callbacks: usize) -> usize {
        self.try_calculate_size(num_callbacks)
            .expect("TLS data size overflow: use try_calculate_size()")
    }

    /// Calculate the serialized size in bytes with checked pointer-array arithmetic.
    ///
    /// # Errors
    ///
    /// Returns an error if the size calculation overflows or the total exceeds `u32`.
    pub fn try_calculate_size(&self, num_callbacks: usize) -> Result<usize> {
        Ok(self.layout(num_callbacks)?.total_size)
    }
}

fn checked_va(image_base: u64, rva: u64, context: &str) -> Result<u64> {
    image_base
        .checked_add(rva)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} VA overflow")))
}

fn va_to_rva(va: u64, image_base: u64) -> Result<u32> {
    if va == 0 {
        return Ok(0);
    }
    va.checked_sub(image_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "TLS VA {va:#x} is outside image base {image_base:#x}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_directory_32_size() {
        assert_eq!(TlsDirectory32::SIZE, 24);
    }

    #[test]
    fn test_tls_directory_64_size() {
        assert_eq!(TlsDirectory64::SIZE, 40);
    }

    #[test]
    fn test_tls_directory_32_roundtrip() {
        let original = TlsDirectory32 {
            start_address_of_raw_data: 0x0040_1000,
            end_address_of_raw_data: 0x0040_1100,
            address_of_index: 0x0040_2000,
            address_of_callbacks: 0x0040_3000,
            size_of_zero_fill: 256,
            characteristics: 0,
        };

        let bytes = original.to_bytes();
        let parsed = TlsDirectory32::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_tls_directory_64_roundtrip() {
        let original = TlsDirectory64 {
            start_address_of_raw_data: 0x0000_0001_4000_1000,
            end_address_of_raw_data: 0x0000_0001_4000_1100,
            address_of_index: 0x0000_0001_4000_2000,
            address_of_callbacks: 0x0000_0001_4000_3000,
            size_of_zero_fill: 512,
            characteristics: 0,
        };

        let bytes = original.to_bytes();
        let parsed = TlsDirectory64::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    /// Before the fix, the rebuild pointed `AddressOfIndex` to a new slot in the block. The
    /// code of the image still read the original `_tls_index`.
    #[test]
    fn rebuild_keeps_the_original_index_address() {
        let base = 0x0000_0001_4000_0000;
        let info = TlsInfo {
            directory: Some(TlsDirectory::Tls64(TlsDirectory64 {
                start_address_of_raw_data: base + 0x2000,
                end_address_of_raw_data: base + 0x2010,
                address_of_index: base + 0x2100,
                ..TlsDirectory64::default()
            })),
            callback_rvas: vec![0x1000],
            image_base: base,
        };
        let new_base = 0x0000_0001_8000_0000;
        let builder = TlsBuilder::new(0x3000, new_base, true);
        let (block, _) = builder.try_build_from_info(&info).unwrap();
        let TlsDirectory::Tls64(directory) = TlsDirectory::parse(&block, true).unwrap() else {
            panic!("expected a PE32+ directory");
        };
        assert_eq!(directory.address_of_index, new_base + 0x2100);
        assert_eq!(directory.start_address_of_raw_data, new_base + 0x2000);

        // Without an index, the block gets its own slot.
        let empty = TlsInfo {
            directory: None,
            ..info
        };
        let (block, _) = builder.try_build_from_info(&empty).unwrap();
        let TlsDirectory::Tls64(directory) = TlsDirectory::parse(&block, true).unwrap() else {
            panic!("expected a PE32+ directory");
        };
        assert_eq!(directory.address_of_index, new_base + 0x3000 + 40);
    }

    #[test]
    fn va_offsets_list_the_directory_fields_and_callbacks() {
        let builder = TlsBuilder::new(0x3000, 0x0040_0000, false);
        let (block, _) = builder
            .try_build(0x2000, 0x2010, &[0x1000, 0x1010])
            .unwrap();
        // Start, end, index, callbacks, then two callbacks at offset 28 (24 + 4).
        assert_eq!(builder.va_offsets(&block), [0, 4, 8, 12, 28, 32]);
        let (block, _) = builder.try_build(0, 0, &[]).unwrap();
        assert_eq!(builder.va_offsets(&block), [8]);
    }
}
