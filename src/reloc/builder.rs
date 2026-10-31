use super::table::{new_block, split_rva};
use super::{Error, RelocationTable, RelocationType, Result};
use crate::prelude::*;

/// Builder for relocation tables.
///
/// This type gives a fluent interface to build relocation tables. The builder keeps a map from
/// each page RVA to its block. Thus each relocation takes logarithmic time, in any order.
///
/// # Example
///
/// ```
/// use portex::reloc::RelocationBuilder;
///
/// let mut builder = RelocationBuilder::new();
///
/// // Add relocations. The builder groups them by page.
/// builder.add_dir64(0x1000);
/// builder.add_dir64(0x1008);
/// builder.add_highlow(0x2000);
///
/// let (data, size) = builder.build();
/// assert!(size > 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RelocationBuilder {
    table: RelocationTable,
    /// The index in `table.blocks` of the first block of each page RVA.
    pages: BTreeMap<u32, usize>,
}

impl RelocationBuilder {
    /// Create a new relocation builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make a builder from an existing relocation table.
    ///
    /// If the table has more than one block for a page, the builder adds new relocations for
    /// that page to the first of these blocks.
    #[must_use]
    pub fn from_table(table: RelocationTable) -> Self {
        let mut pages = BTreeMap::new();
        for (index, block) in table.blocks.iter().enumerate() {
            pages.entry(block.page_rva).or_insert(index);
        }
        Self { table, pages }
    }

    /// Add a relocation entry at a specific RVA.
    pub fn add_relocation(&mut self, rva: u32, reloc_type: RelocationType) -> &mut Self {
        let (page_rva, entry) = split_rva(rva, reloc_type);
        let blocks = &mut self.table.blocks;
        if let Some(block) = self
            .pages
            .get(&page_rva)
            .and_then(|&index| blocks.get_mut(index))
        {
            block.entries.push(entry);
        } else {
            self.pages.insert(page_rva, blocks.len());
            blocks.push(new_block(page_rva, entry));
        }
        self
    }

    /// Add a HIGHLOW (32-bit) relocation.
    pub fn add_highlow(&mut self, rva: u32) -> &mut Self {
        self.add_relocation(rva, RelocationType::HighLow)
    }

    /// Add a DIR64 (64-bit) relocation.
    pub fn add_dir64(&mut self, rva: u32) -> &mut Self {
        self.add_relocation(rva, RelocationType::Dir64)
    }

    /// Get the number of relocations added.
    #[must_use]
    pub fn relocation_count(&self) -> usize {
        self.table.relocation_count()
    }

    /// Calculate the total size when serialized.
    #[must_use]
    pub fn calculate_size(&self) -> usize {
        self.table.normalized().calculate_size()
    }

    /// Build the relocation table. Returns `(data, size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self) -> (Vec<u8>, u32) {
        self.try_build()
            .expect("relocation build failed: use try_build() for fallible serialization")
    }

    /// Build the relocation table, with checked block and table sizes. Returns `(data, size)`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`RelocationTable::try_build`].
    pub fn try_build(&self) -> Result<(Vec<u8>, u32)> {
        let data = self.table.try_build()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("base-relocation table exceeds u32"))?;
        Ok((data, size))
    }

    /// Get the underlying table, normalized.
    #[must_use]
    pub fn into_table(self) -> RelocationTable {
        let mut table = self.table;
        table.normalize();
        table
    }
}
