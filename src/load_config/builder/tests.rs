use super::*;

#[test]
fn serialization_reports_unallocatable_size() {
    let config32 = LoadConfigDirectory32 {
        size: u32::MAX,
        ..Default::default()
    };
    assert!(config32.try_to_bytes().is_err());
    let config64 = LoadConfigDirectory64 {
        size: u32::MAX,
        ..Default::default()
    };
    assert!(config64.try_to_bytes().is_err());
    assert!(
        LoadConfigBuilder::new(false)
            .try_build(&LoadConfigDirectory::Config32(config32))
            .is_err()
    );
}
