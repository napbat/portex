//! PE builder for creating new PE files from scratch.
//!
//! # Example
//!
//! ```no_run
//! use portex::{MachineType, PeBuilder, Subsystem};
//! use portex::section::characteristics;
//!
//! let code = vec![0xCC; 0x100]; // INT3 instructions
//! let data = vec![0u8; 0x50];
//!
//! let pe = PeBuilder::new()
//!     .machine(MachineType::Amd64)
//!     .subsystem(Subsystem::WindowsCui)
//!     .entry_point(0x1000)  // RVA will be adjusted after layout
//!     .add_section(".text", code, characteristics::CODE | characteristics::EXECUTE | characteristics::READ)
//!     .add_section(".data", data, characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE)
//!     .build();
//! ```

use crate::coff::{CoffHeader, MachineType};
use crate::data_dir::DataDirectory;
use crate::dos::{DOS_SIGNATURE, DosHeader};
use crate::optional::{
    OptionalHeader, OptionalHeader32, OptionalHeader64, PE32_MAGIC, PE32PLUS_MAGIC, Subsystem,
};
use crate::pe::PeImage;
use crate::prelude::*;
use crate::section::{Section, SectionHeader};
use crate::{Error, Result};

/// Builder for creating new PE files from scratch.
#[derive(Debug, Clone)]
pub struct PeBuilder {
    machine: MachineType,
    subsystem: Subsystem,
    is_64bit: bool,
    image_base: u64,
    entry_point: u32,
    file_alignment: u32,
    section_alignment: u32,
    dll_characteristics: u16,
    is_dll: bool,
    sections: Vec<(String, Vec<u8>, u32)>, // (name, data, characteristics)
}

impl Default for PeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PeBuilder {
    /// Create a new PE builder with default settings (64-bit console application).
    #[must_use]
    pub fn new() -> Self {
        Self {
            machine: MachineType::Amd64,
            subsystem: Subsystem::WindowsCui,
            is_64bit: true,
            image_base: 0x0000_0001_4000_0000, // Default for 64-bit
            entry_point: 0,
            file_alignment: 0x200,
            section_alignment: 0x1000,
            dll_characteristics: 0x8160, // DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE | HIGH_ENTROPY_VA
            is_dll: false,
            sections: Vec::new(),
        }
    }

    /// Set the target machine type.
    #[must_use]
    pub fn machine(mut self, machine: MachineType) -> Self {
        self.machine = machine;
        // Get the PE32 or PE32+ width from the machine type.
        self.is_64bit = machine.is_64_bit();
        // Use the default image base for a 32-bit image.
        if !self.is_64bit {
            self.image_base = 0x0040_0000; // Default for 32-bit
        }
        self
    }

    /// Set the subsystem, for example GUI or console.
    #[must_use]
    pub fn subsystem(mut self, subsystem: Subsystem) -> Self {
        self.subsystem = subsystem;
        self
    }

    /// Set whether the image is a 64-bit PE (PE32+).
    ///
    /// [`Self::machine`] usually sets this value from the machine type.
    #[must_use]
    pub fn pe32_plus(mut self, is_64bit: bool) -> Self {
        self.is_64bit = is_64bit;
        self
    }

    /// Set the preferred image base (`ImageBase`, a VA).
    #[must_use]
    pub fn image_base(mut self, base: u64) -> Self {
        self.image_base = base;
        self
    }

    /// Set the entry point (`AddressOfEntryPoint`, an RVA).
    #[must_use]
    pub fn entry_point(mut self, rva: u32) -> Self {
        self.entry_point = rva;
        self
    }

    /// Set the file alignment (default: 0x200).
    #[must_use]
    pub fn file_alignment(mut self, alignment: u32) -> Self {
        self.file_alignment = alignment;
        self
    }

    /// Set the section alignment (default: 0x1000).
    #[must_use]
    pub fn section_alignment(mut self, alignment: u32) -> Self {
        self.section_alignment = alignment;
        self
    }

    /// Set the DLL characteristics flags (`DllCharacteristics`).
    #[must_use]
    pub fn dll_characteristics(mut self, flags: u16) -> Self {
        self.dll_characteristics = flags;
        self
    }

    /// Mark the image as a DLL (`true`) or as an executable (`false`).
    #[must_use]
    pub fn dll(mut self, is_dll: bool) -> Self {
        self.is_dll = is_dll;
        self
    }

    /// Add a section with the given name, data, and characteristics.
    #[must_use]
    pub fn add_section(mut self, name: &str, data: Vec<u8>, characteristics: u32) -> Self {
        self.sections
            .push((name.to_string(), data, characteristics));
        self
    }

    /// Build the PE image, or panic if the requested layout is not valid.
    ///
    /// Use [`Self::try_build`] if the values come from an untrusted source.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] returns an error.
    #[must_use]
    pub fn build(self) -> PeImage {
        self.try_build()
            .expect("PE builder failed: use PeBuilder::try_build() to handle invalid settings")
    }

    /// Build the PE image after checks of the machine type, width, alignment and sizes.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidSection`](crate::error::ErrorKind::InvalidSection) if:
    ///
    /// - The image base of a PE32 image does not fit in a `u32`.
    /// - The image base is not aligned to 64 KiB.
    /// - The machine type does not match the width of the optional header.
    /// - There are more sections than
    ///   [`MAX_NUMBER_OF_SECTIONS`](crate::pe::MAX_NUMBER_OF_SECTIONS).
    /// - The data of a section does not fit in a `u32`.
    ///
    /// Also propagates any error from [`PeImage::try_update_layout`].
    pub fn try_build(self) -> Result<PeImage> {
        if !self.is_64bit && self.image_base > u64::from(u32::MAX) {
            return Err(Error::invalid_section(format!(
                "PE32 image base {:#x} exceeds u32",
                self.image_base
            )));
        }
        if self.image_base & 0xffff != 0 {
            return Err(Error::invalid_section(format!(
                "image base {:#x} is not 64-KiB aligned",
                self.image_base
            )));
        }
        if self.machine != MachineType::Unknown && self.machine.is_64_bit() != self.is_64bit {
            return Err(Error::invalid_section(format!(
                "machine {:?} is incompatible with a {} optional header",
                self.machine,
                if self.is_64bit { "PE32+" } else { "PE32" }
            )));
        }
        if self.sections.len() > crate::pe::MAX_NUMBER_OF_SECTIONS {
            return Err(Error::invalid_section(format!(
                "section count {} exceeds the PE image limit of {}",
                self.sections.len(),
                crate::pe::MAX_NUMBER_OF_SECTIONS
            )));
        }
        for (name, data, _) in &self.sections {
            u32::try_from(data.len()).map_err(|_| {
                Error::invalid_section(format!("section '{name}' data exceeds u32"))
            })?;
        }

        // Create DOS header
        let dos_header = Self::create_dos_header();

        // Create COFF header
        let coff_header = self.create_coff_header()?;

        // Create optional header
        let optional_header = self.create_optional_header()?;

        // Create sections
        let sections = self.create_sections();

        // Create the PE image and update the layout.
        let mut pe = PeImage {
            dos_header,
            dos_stub: Self::default_dos_stub(),
            coff_header,
            optional_header,
            sections,
            source_layout: crate::pe::SourceLayout::File,
            runtime_image_base: None,
            header_tail: crate::pe::HeaderBytes::default(),
            optional_padding: crate::pe::HeaderBytes::default(),
        };

        pe.try_update_layout()?;
        Ok(pe)
    }

    fn create_dos_header() -> DosHeader {
        DosHeader {
            e_magic: DOS_SIGNATURE,
            e_cblp: 0x90,
            e_cp: 0x03,
            e_crlc: 0,
            e_cparhdr: 0x04,
            e_minalloc: 0,
            e_maxalloc: 0xFFFF,
            e_ss: 0,
            e_sp: 0xB8,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0x40,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: 0x80, // PE header at offset 0x80
        }
    }

    fn create_coff_header(&self) -> Result<CoffHeader> {
        let mut characteristics = crate::coff::characteristics::EXECUTABLE_IMAGE;
        if self.is_64bit {
            characteristics |= crate::coff::characteristics::LARGE_ADDRESS_AWARE;
        } else {
            characteristics |= crate::coff::characteristics::MACHINE_32BIT;
        }
        if self.is_dll {
            characteristics |= crate::coff::characteristics::DLL;
        }

        let number_of_sections = u16::try_from(self.sections.len())
            .map_err(|_| Error::invalid_section("section count exceeds u16"))?;

        Ok(CoffHeader {
            machine: self.machine as u16,
            number_of_sections,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: if self.is_64bit { 240 } else { 224 },
            characteristics,
        })
    }

    fn create_optional_header(&self) -> Result<OptionalHeader> {
        // 16 data directories (standard)
        let data_directories = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0
            };
            16
        ];

        Ok(if self.is_64bit {
            OptionalHeader::Pe32Plus(OptionalHeader64 {
                magic: PE32PLUS_MAGIC,
                major_linker_version: 14,
                minor_linker_version: 0,
                size_of_code: 0, // Updated by layout
                size_of_initialized_data: 0,
                size_of_uninitialized_data: 0,
                address_of_entry_point: self.entry_point,
                base_of_code: 0,
                image_base: self.image_base,
                section_alignment: self.section_alignment,
                file_alignment: self.file_alignment,
                major_operating_system_version: 6,
                minor_operating_system_version: 0,
                major_image_version: 0,
                minor_image_version: 0,
                major_subsystem_version: 6,
                minor_subsystem_version: 0,
                win32_version_value: 0,
                size_of_image: 0,   // Updated by layout
                size_of_headers: 0, // Updated by layout
                check_sum: 0,
                subsystem: self.subsystem as u16,
                dll_characteristics: self.dll_characteristics,
                size_of_stack_reserve: 0x0010_0000,
                size_of_stack_commit: 0x1000,
                size_of_heap_reserve: 0x0010_0000,
                size_of_heap_commit: 0x1000,
                loader_flags: 0,
                number_of_rva_and_sizes: 16,
                data_directories,
            })
        } else {
            OptionalHeader::Pe32(OptionalHeader32 {
                magic: PE32_MAGIC,
                major_linker_version: 14,
                minor_linker_version: 0,
                size_of_code: 0,
                size_of_initialized_data: 0,
                size_of_uninitialized_data: 0,
                address_of_entry_point: self.entry_point,
                base_of_code: 0,
                base_of_data: 0,
                image_base: u32::try_from(self.image_base)
                    .map_err(|_| Error::invalid_section("PE32 image base exceeds u32"))?,
                section_alignment: self.section_alignment,
                file_alignment: self.file_alignment,
                major_operating_system_version: 6,
                minor_operating_system_version: 0,
                major_image_version: 0,
                minor_image_version: 0,
                major_subsystem_version: 6,
                minor_subsystem_version: 0,
                win32_version_value: 0,
                size_of_image: 0,
                size_of_headers: 0,
                check_sum: 0,
                subsystem: self.subsystem as u16,
                dll_characteristics: self.dll_characteristics,
                size_of_stack_reserve: 0x0010_0000,
                size_of_stack_commit: 0x1000,
                size_of_heap_reserve: 0x0010_0000,
                size_of_heap_commit: 0x1000,
                loader_flags: 0,
                number_of_rva_and_sizes: 16,
                data_directories,
            })
        })
    }

    fn create_sections(&self) -> Vec<Section> {
        self.sections
            .iter()
            .map(|(name, data, characteristics)| {
                let mut header = SectionHeader::default();
                header.set_name(name);
                header.characteristics = *characteristics;
                Section::from_header_and_data(header, data.clone())
            })
            .collect()
    }

    fn default_dos_stub() -> Vec<u8> {
        // Minimal DOS stub: "This program cannot be run in DOS mode.\r\n$".
        // Pad the stub with zeros to 64 bytes (0x40 to 0x80). The PE header then starts at file
        // offset 0x80.
        let msg = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$";
        let mut stub = msg.to_vec();
        stub.resize(64, 0);
        stub
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::section::characteristics;

    #[test]
    fn test_builder_creates_valid_pe() {
        let code = vec![0xCC; 0x100];
        let pe = PeBuilder::new()
            .machine(MachineType::Amd64)
            .subsystem(Subsystem::WindowsCui)
            .entry_point(0x1000)
            .add_section(
                ".text",
                code,
                characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
            )
            .build();

        assert!(pe.is_64bit());
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name(), ".text");
    }

    #[test]
    fn test_builder_32bit() {
        let pe = PeBuilder::new()
            .machine(MachineType::I386)
            .add_section(
                ".text",
                vec![0x90; 0x10],
                characteristics::CODE | characteristics::EXECUTE,
            )
            .build();

        assert!(!pe.is_64bit());
        assert_eq!(pe.coff_header.machine, MachineType::I386 as u16);
    }

    #[test]
    fn test_builder_roundtrip() {
        let pe = PeBuilder::new()
            .machine(MachineType::Amd64)
            .subsystem(Subsystem::WindowsGui)
            .add_section(
                ".text",
                vec![0xCC; 256],
                characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
            )
            .add_section(
                ".data",
                vec![0x00; 64],
                characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
            )
            .build();

        // Build to bytes and parse back
        let bytes = pe.build();
        let parsed = PeImage::parse(&bytes).expect("Should parse built PE");

        assert_eq!(parsed.sections.len(), 2);
        assert_eq!(parsed.sections[0].name(), ".text");
        assert_eq!(parsed.sections[1].name(), ".data");
    }
}
