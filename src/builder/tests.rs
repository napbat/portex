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
