use super::*;

#[test]
fn overlapping_sources_count_one_time() {
    let mut budget = NameBudget::default();
    budget.add_source(10, 10);
    budget.add_source(15, 10);
    budget.add_source(0, 5);
    assert_eq!(budget.source_bytes, 20);
    budget.add_source(5, 5);
    assert_eq!(budget.source_bytes, 25);
    assert_eq!(budget.ranges.len(), 1);
    budget.add_source(100, 0);
    budget.add_source(40, 1);
    assert_eq!(budget.source_bytes, 26);
}

#[test]
fn output_is_limited_by_the_source() {
    let mut budget = NameBudget::default();
    budget.add_source(0, 1 << 17);
    let limit = usize::try_from((1u64 << 17) * NAME_BYTES_PER_SOURCE_BYTE).unwrap();
    budget.charge(limit, "test").unwrap();
    assert!(budget.charge(1, "test").is_err());
}
