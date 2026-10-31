//! Limits on the names that the import, delay-import and bound-import parsers return.

use crate::prelude::*;
use crate::{Error, Result};

/// Maximum length of a DLL name or a function name in an import, delay-import or bound-import
/// table. This limit is larger than all valid Windows names, also C++ decorated names. It stops
/// unbounded reads on malformed PE files.
pub(crate) const MAX_NAME_LEN: usize = 4096;

/// The parsers can always return this number of name bytes.
const NAME_BUDGET_FLOOR: u64 = 1 << 20;

/// The parsers can return this number of name bytes for each distinct source byte of a name.
///
/// In a normal table, each name occurs one time, so the output has about one byte for each
/// source byte. A malformed table can point many entries at one long name, or at the bytes of
/// one long run with many start offsets. Such a table gets an error, not gigabytes of copies.
const NAME_BYTES_PER_SOURCE_BYTE: u64 = 16;

/// A limit on the name bytes that one parse returns.
///
/// The limit is tied to the source: it is the larger of a fixed floor and
/// [`NAME_BYTES_PER_SOURCE_BYTE`] times the union of the source ranges of all names. Overlapping
/// names thus count their shared bytes only one time.
#[derive(Debug, Default)]
pub(crate) struct NameBudget {
    /// Disjoint source ranges `start..end` of the names, keyed by `start`.
    ranges: BTreeMap<u64, u64>,
    /// The number of bytes in `ranges`.
    source_bytes: u64,
    /// The number of name bytes that the parse returned.
    output_bytes: u64,
}

impl NameBudget {
    /// Record that a name has its source bytes at `start..start + len`.
    ///
    /// Include the terminator and other bytes of the entry in `len`.
    pub(crate) fn add_source(&mut self, start: u64, len: usize) {
        let Ok(len) = u64::try_from(len) else {
            return;
        };
        let mut start = start;
        let mut end = start.saturating_add(len);
        if end == start {
            return;
        }
        // Merge with the range that starts before `start` and reaches it.
        if let Some((&before_start, &before_end)) = self.ranges.range(..start).next_back()
            && before_end >= start
        {
            start = before_start;
            end = end.max(before_end);
            self.remove(before_start, before_end);
        }
        // Merge with the ranges that start in `start..=end`.
        while let Some((&next_start, &next_end)) = self.ranges.range(start..=end).next() {
            end = end.max(next_end);
            self.remove(next_start, next_end);
        }
        self.ranges.insert(start, end);
        self.source_bytes = self.source_bytes.saturating_add(end - start);
    }

    fn remove(&mut self, start: u64, end: u64) {
        self.ranges.remove(&start);
        self.source_bytes = self.source_bytes.saturating_sub(end - start);
    }

    /// Charge `len` output bytes for a name.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error if the output is larger than the budget.
    pub(crate) fn charge(&mut self, len: usize, context: &str) -> Result<()> {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        self.output_bytes = self.output_bytes.saturating_add(len);
        let budget = self
            .source_bytes
            .saturating_mul(NAME_BYTES_PER_SOURCE_BYTE)
            .max(NAME_BUDGET_FLOOR);
        if self.output_bytes > budget {
            return Err(Error::invalid_data_directory(format!(
                "{context} names repeat too many source bytes: more than {budget} name bytes \
                 for {} source bytes",
                self.source_bytes
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
}
