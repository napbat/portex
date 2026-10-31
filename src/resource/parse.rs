use super::{
    Error, Resource, ResourceDataEntry, ResourceDirectory, ResourceDirectoryEntry,
    ResourceDirectoryHeader, ResourceId, ResourceType, Result, checked_resource_rva,
};
use crate::prelude::*;

/// Maximum number of directory entries that the parser visits, for all tree levels together.
const MAX_VISITED_ENTRIES: usize = 262_144;

/// The name budget of a parse is this factor times the directory size, or
/// [`MIN_NAME_BUDGET`] if that is larger.
const NAME_BUDGET_FACTOR: usize = 8;

/// The smallest name budget of a parse, in bytes.
const MIN_NAME_BUDGET: usize = 1 << 20;

/// The payloads of one load can use this many bytes more than the bytes of their merged
/// ranges, if the merged ranges are smaller.
const MIN_SHARED_PAYLOAD: u64 = 1 << 20;

impl ResourceDirectory {
    /// Parse the resource directory from PE data.
    ///
    /// `rsrc_rva` is the RVA of the resource directory, and `rsrc_size` is its size in bytes.
    /// `read_at_rva(rva, len)` must return `len` bytes at the RVA `rva`. It must return `None`
    /// if it cannot read the range. This function does not load the resource payloads.
    ///
    /// # Errors
    ///
    /// Returns an invalid-RVA error if a directory structure cannot be read.
    ///
    /// Returns an invalid-data-directory error if one of these conditions is true:
    /// - `rsrc_size` is smaller than an `IMAGE_RESOURCE_DIRECTORY`.
    /// - The tree has more than 262,144 entries.
    /// - A structure or a name is outside `rsrc_size`.
    /// - The named entries do not come before the ID entries.
    /// - A type entry or a name entry does not point to a subdirectory.
    /// - A language entry is named or points to a subdirectory.
    /// - A numeric ID has high bits that are not zero.
    /// - A name is not valid UTF-16.
    /// - The reserved field of a data entry is not zero.
    /// - Two entries of one directory have the same ID or the same name. This also makes sure
    ///   that no two resources have the same type, name and language.
    /// - The names use more than the name budget. The budget is 8 times `rsrc_size`, or 1 MiB
    ///   if that is larger. Each decoded name uses its UTF-16 size. Each resource also uses
    ///   the UTF-8 sizes of its type name and its name, because it holds a copy of them.
    pub fn parse<F>(rsrc_rva: u32, rsrc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if usize::try_from(rsrc_size).is_ok_and(|size| size < ResourceDirectoryHeader::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "resource directory is {} bytes, expected at least {}",
                rsrc_size,
                ResourceDirectoryHeader::SIZE
            )));
        }
        let name_budget = usize::try_from(rsrc_size)
            .map_or(usize::MAX, |size| size.saturating_mul(NAME_BUDGET_FACTOR))
            .max(MIN_NAME_BUDGET);
        let mut walker = ResourceTreeWalker {
            rsrc_rva,
            rsrc_size,
            read_at_rva: &read_at_rva,
            visited_entries: 0,
            name_budget,
            resources: Vec::new(),
        };
        let root_header = walker.walk_types()?;
        Ok(Self {
            root_header,
            resources: walker.resources,
        })
    }

    /// Parse the resource directory from PE data, and load the resource data.
    ///
    /// Unlike `parse()`, this function also loads the resource data into each `Resource`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::parse`] and [`Self::try_load_data`].
    pub fn parse_with_data<F>(rsrc_rva: u32, rsrc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut dir = Self::parse(rsrc_rva, rsrc_size, &read_at_rva)?;
        dir.try_load_data(&read_at_rva)?;
        Ok(dir)
    }

    /// Load the data for each resource that does not have data yet.
    ///
    /// Use this function after `parse()` to load the resource data later. The function sets
    /// `data` to an empty vector for a zero-size resource. It leaves `data` as `None` for a
    /// resource that `read_at_rva` cannot read. It also leaves `data` as `None` for a resource
    /// that does not fit in the budget of [`Self::try_load_data`].
    pub fn load_data<F>(&mut self, read_at_rva: F)
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut remaining = self.payload_budget();
        for resource in &mut self.resources {
            if resource.data.is_some() {
                continue;
            }
            if resource.size == 0 {
                resource.data = Some(Vec::new());
                continue;
            }
            let Some(rest) = remaining.checked_sub(u64::from(resource.size)) else {
                continue;
            };
            resource.data = read_at_rva(resource.data_rva, resource.size as usize);
            if resource.data.is_some() {
                remaining = rest;
            }
        }
    }

    /// Load all resource payloads. Stop at the first range that cannot be read.
    ///
    /// `read_at_rva(rva, len)` reads `len` bytes at the RVA `rva`. The function sets `data` to
    /// an empty vector for a zero-size resource. It does not read the data of such a resource.
    ///
    /// The payloads of many resources can share bytes. The function makes sure that the total
    /// size of the loaded payloads is not larger than the size of their merged ranges plus
    /// the larger of that size and 1 MiB.
    ///
    /// # Errors
    ///
    /// Returns an invalid-RVA error if `read_at_rva` cannot read a payload. Returns an
    /// invalid-data-directory error if `read_at_rva` returns a length that is not equal to the
    /// size in the data entry.
    ///
    /// Returns an invalid-data-directory error before the first read if the payloads are
    /// larger than the budget.
    pub fn try_load_data<F>(&mut self, read_at_rva: F) -> Result<()>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let total = self.unloaded_payload_size();
        let budget = self.payload_budget();
        if total > budget {
            return Err(Error::invalid_data_directory(format!(
                "resource payloads use {total:#x} bytes, more than the budget of {budget:#x} bytes"
            )));
        }
        for resource in &mut self.resources {
            if resource.data.is_some() {
                continue;
            }
            resource.data = Some(if resource.size == 0 {
                Vec::new()
            } else {
                crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    resource.data_rva,
                    resource.size as usize,
                    "resource payload",
                )?
            });
        }
        Ok(())
    }

    /// Return the total size of the payloads that are not loaded yet, in bytes.
    pub(crate) fn unloaded_payload_size(&self) -> u64 {
        self.resources
            .iter()
            .filter(|resource| resource.data.is_none())
            .map(|resource| u64::from(resource.size))
            .sum()
    }

    /// Return the number of bytes that the payloads which are not loaded yet can use.
    ///
    /// The budget is the size of the merged payload ranges, plus the larger of that size and
    /// [`MIN_SHARED_PAYLOAD`].
    fn payload_budget(&self) -> u64 {
        let mut ranges: Vec<(u64, u64)> = self
            .resources
            .iter()
            .filter(|resource| resource.data.is_none() && resource.size != 0)
            .map(|resource| {
                let start = u64::from(resource.data_rva);
                (start, start + u64::from(resource.size))
            })
            .collect();
        ranges.sort_unstable();
        let mut merged = 0u64;
        let mut covered_end = 0u64;
        for (start, end) in ranges {
            let start = start.max(covered_end);
            if end > start {
                merged += end - start;
                covered_end = end;
            }
        }
        merged + merged.max(MIN_SHARED_PAYLOAD)
    }

    /// Find all resources of a resource type.
    #[must_use]
    pub fn find_by_type(&self, rt: ResourceType) -> Vec<&Resource> {
        self.resources.iter().filter(|r| r.is_type(rt)).collect()
    }

    /// Get the first manifest resource, if there is one.
    #[must_use]
    pub fn manifest(&self) -> Option<&Resource> {
        self.find_by_type(ResourceType::Manifest).first().copied()
    }

    /// Get the first version information resource, if there is one.
    #[must_use]
    pub fn version_info(&self) -> Option<&Resource> {
        self.find_by_type(ResourceType::Version).first().copied()
    }

    /// Get all icon resources.
    #[must_use]
    pub fn icons(&self) -> Vec<&Resource> {
        self.find_by_type(ResourceType::Icon)
    }

    /// Get all icon group resources.
    #[must_use]
    pub fn icon_groups(&self) -> Vec<&Resource> {
        self.find_by_type(ResourceType::GroupIcon)
    }

    /// Check if the directory has no resources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// Get the number of resources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.resources.len()
    }
}

/// A level of the resource tree. The tree has three levels.
#[derive(Debug, Clone, Copy)]
enum TreeLevel {
    Type,
    Name,
    Language,
}

impl TreeLevel {
    /// Context text for range errors on the directory entries of this level.
    fn entry_context(self) -> &'static str {
        match self {
            Self::Type => "resource type entry",
            Self::Name => "resource name entry",
            Self::Language => "resource language entry",
        }
    }

    /// Context text for errors when the named entries of this level do not come first.
    fn order_context(self) -> &'static str {
        match self {
            Self::Type => "resource type",
            Self::Name => "resource name",
            Self::Language => "resource language",
        }
    }
}

/// A walk over the resource tree, with a limit on the number of entries and on the name
/// bytes. The walk collects the leaf resources.
struct ResourceTreeWalker<'a, F> {
    rsrc_rva: u32,
    rsrc_size: u32,
    read_at_rva: &'a F,
    visited_entries: usize,
    /// The name bytes that the walk can still decode or copy.
    name_budget: usize,
    resources: Vec<Resource>,
}

/// The IDs and names of the entries of one directory, to find duplicate entries.
#[derive(Default)]
struct SiblingIds {
    ids: BTreeSet<u16>,
    names: BTreeSet<String>,
}

impl SiblingIds {
    /// Return an error if a sibling before `id` has the same ID or name.
    fn check(&self, id: &ResourceId, level: TreeLevel) -> Result<()> {
        let duplicate = match id {
            ResourceId::Id(value) => self.ids.contains(value),
            ResourceId::Name(name) => self.names.contains(name),
        };
        if duplicate {
            return Err(Error::invalid_data_directory(format!(
                "duplicate {} entry",
                level.order_context()
            )));
        }
        Ok(())
    }

    /// Record `id` after the walk below its entry. This moves the name, and does not copy it.
    fn insert(&mut self, id: ResourceId) {
        match id {
            ResourceId::Id(value) => self.ids.insert(value),
            ResourceId::Name(name) => self.names.insert(name),
        };
    }
}

/// Return the size of the string of `id` in bytes, or 0 for a numeric ID.
fn name_size(id: &ResourceId) -> usize {
    match id {
        ResourceId::Id(_) => 0,
        ResourceId::Name(name) => name.len(),
    }
}

impl<F> ResourceTreeWalker<'_, F>
where
    F: Fn(u32, usize) -> Option<Vec<u8>>,
{
    /// Walk the root (type) directory and everything below it. Return the root header.
    fn walk_types(&mut self) -> Result<ResourceDirectoryHeader> {
        let root_rva = self.rsrc_rva;
        let root_header = self.read_header(root_rva)?;
        let mut siblings = SiblingIds::default();
        for i in 0..root_header.total_entries() {
            let type_entry = self.read_entry(root_rva, &root_header, i, TreeLevel::Type)?;
            let type_id = self.parse_resource_id(type_entry)?;
            siblings.check(&type_id, TreeLevel::Type)?;

            if !type_entry.is_directory() {
                return Err(Error::invalid_data_directory(
                    "resource type entry must point to a subdirectory",
                ));
            }

            let name_dir_rva = checked_resource_rva(
                self.rsrc_rva,
                self.rsrc_size,
                type_entry.data_offset(),
                ResourceDirectoryHeader::SIZE,
                "resource name directory",
            )?;
            self.walk_names(&type_id, name_dir_rva)?;
            siblings.insert(type_id);
        }
        Ok(root_header)
    }

    /// Walk a level-2 (name) directory and its language directories.
    fn walk_names(&mut self, type_id: &ResourceId, dir_rva: u32) -> Result<()> {
        let header = self.read_header(dir_rva)?;
        let mut siblings = SiblingIds::default();
        for j in 0..header.total_entries() {
            let name_entry = self.read_entry(dir_rva, &header, j, TreeLevel::Name)?;
            let name_id = self.parse_resource_id(name_entry)?;
            siblings.check(&name_id, TreeLevel::Name)?;

            if !name_entry.is_directory() {
                return Err(Error::invalid_data_directory(
                    "resource name entry must point to a subdirectory",
                ));
            }

            let lang_dir_rva = checked_resource_rva(
                self.rsrc_rva,
                self.rsrc_size,
                name_entry.data_offset(),
                ResourceDirectoryHeader::SIZE,
                "resource language directory",
            )?;
            self.walk_languages(type_id, &name_id, lang_dir_rva)?;
            siblings.insert(name_id);
        }
        Ok(())
    }

    /// Walk a level-3 (language) directory, recording one resource per entry.
    fn walk_languages(
        &mut self,
        type_id: &ResourceId,
        name_id: &ResourceId,
        dir_rva: u32,
    ) -> Result<()> {
        let header = self.read_header(dir_rva)?;
        let mut languages = BTreeSet::new();
        // Each resource holds a copy of the type name and of the name.
        let copy_size = name_size(type_id).saturating_add(name_size(name_id));
        for k in 0..header.total_entries() {
            let lang_entry = self.read_entry(dir_rva, &header, k, TreeLevel::Language)?;

            if lang_entry.is_named() {
                return Err(Error::invalid_data_directory(
                    "resource language entry must use an integer identifier",
                ));
            }
            let language = lang_entry.id();

            if lang_entry.is_directory() {
                return Err(Error::invalid_data_directory(
                    "resource language entry must point to a data entry",
                ));
            }

            let data_entry_rva = checked_resource_rva(
                self.rsrc_rva,
                self.rsrc_size,
                lang_entry.data_offset(),
                ResourceDataEntry::SIZE,
                "resource data entry",
            )?;
            let data_entry_data = (self.read_at_rva)(data_entry_rva, ResourceDataEntry::SIZE)
                .ok_or_else(|| Error::invalid_rva(data_entry_rva))?;
            let data_entry = ResourceDataEntry::parse(&data_entry_data)?;
            if data_entry.reserved != 0 {
                return Err(Error::invalid_data_directory(
                    "resource data-entry reserved field must be zero",
                ));
            }
            if !languages.insert(language) {
                return Err(Error::invalid_data_directory(format!(
                    "duplicate resource language entry {language:#x}"
                )));
            }
            self.use_name_budget(copy_size)?;

            self.resources.push(Resource {
                type_id: type_id.clone(),
                name: name_id.clone(),
                language,
                data_rva: data_entry.offset_to_data,
                size: data_entry.size,
                code_page: data_entry.code_page,
                data: None,
            });
        }
        Ok(())
    }

    /// Subtract `bytes` from the name budget.
    fn use_name_budget(&mut self, bytes: usize) -> Result<()> {
        self.name_budget = self.name_budget.checked_sub(bytes).ok_or_else(|| {
            Error::invalid_data_directory("resource names exceed the name budget")
        })?;
        Ok(())
    }

    /// Read the `IMAGE_RESOURCE_DIRECTORY` at `dir_rva`.
    fn read_header(&self, dir_rva: u32) -> Result<ResourceDirectoryHeader> {
        let data = (self.read_at_rva)(dir_rva, ResourceDirectoryHeader::SIZE)
            .ok_or_else(|| Error::invalid_rva(dir_rva))?;
        ResourceDirectoryHeader::parse(&data)
    }

    /// Read entry `index` of the directory at the RVA `dir_rva`.
    ///
    /// This function enforces the limit on visited entries, the directory bounds and the
    /// order of the entries (named entries first).
    fn read_entry(
        &mut self,
        dir_rva: u32,
        header: &ResourceDirectoryHeader,
        index: usize,
        level: TreeLevel,
    ) -> Result<ResourceDirectoryEntry> {
        self.visited_entries += 1;
        if self.visited_entries > MAX_VISITED_ENTRIES {
            return Err(Error::invalid_data_directory(
                "resource tree exceeds the entry limit",
            ));
        }
        let directory_relative = dir_rva
            .checked_sub(self.rsrc_rva)
            .ok_or_else(|| Error::invalid_data_directory("resource directory precedes its base"))?;
        let entry_relative = index
            .checked_mul(ResourceDirectoryEntry::SIZE)
            .and_then(|offset| offset.checked_add(ResourceDirectoryHeader::SIZE))
            .and_then(|offset| u32::try_from(offset).ok())
            .and_then(|offset| directory_relative.checked_add(offset))
            .ok_or_else(|| Error::invalid_data_directory("resource entry offset overflow"))?;
        let entry_rva = checked_resource_rva(
            self.rsrc_rva,
            self.rsrc_size,
            entry_relative,
            ResourceDirectoryEntry::SIZE,
            level.entry_context(),
        )?;
        let entry_data = (self.read_at_rva)(entry_rva, ResourceDirectoryEntry::SIZE)
            .ok_or_else(|| Error::invalid_rva(entry_rva))?;
        let entry = ResourceDirectoryEntry::parse(&entry_data)?;
        validate_resource_entry_order(index, header, entry, level.order_context())?;
        Ok(entry)
    }

    /// Decode the name or numeric ID of a type or name entry. A name uses its UTF-16 size from
    /// the name budget.
    fn parse_resource_id(&mut self, entry: ResourceDirectoryEntry) -> Result<ResourceId> {
        if !entry.is_named() {
            if entry.name_or_id & 0xffff_0000 != 0 {
                return Err(Error::invalid_data_directory(
                    "numeric resource identifier has nonzero reserved bits",
                ));
            }
            return Ok(ResourceId::Id(entry.id()));
        }

        let name_offset = checked_resource_rva(
            self.rsrc_rva,
            self.rsrc_size,
            entry.name_offset(),
            2,
            "resource name length",
        )?;
        // A resource name is a Unicode string with a length prefix.
        let len_data = crate::parse_utils::read_exact_rva(
            self.read_at_rva,
            name_offset,
            2,
            "resource name length",
        )?;
        let len = usize::from(u16::from_le_bytes([len_data[0], len_data[1]]));
        let byte_len = len
            .checked_mul(2)
            .ok_or_else(|| Error::invalid_data_directory("resource name length overflow"))?;
        let string_relative = entry
            .name_offset()
            .checked_add(2)
            .ok_or_else(|| Error::invalid_data_directory("resource name offset overflow"))?;
        let string_rva = checked_resource_rva(
            self.rsrc_rva,
            self.rsrc_size,
            string_relative,
            byte_len,
            "resource name",
        )?;
        self.use_name_budget(byte_len)?;
        let name_data = crate::parse_utils::read_exact_rva(
            self.read_at_rva,
            string_rva,
            byte_len,
            "resource name",
        )?;

        // Convert the UTF-16LE units to a `String`.
        let chars: Vec<u16> = name_data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect();
        let name = String::from_utf16(&chars)
            .map_err(|_| Error::invalid_data_directory("resource name contains invalid UTF-16"))?;
        Ok(ResourceId::Name(name))
    }
}

fn validate_resource_entry_order(
    index: usize,
    header: &ResourceDirectoryHeader,
    entry: ResourceDirectoryEntry,
    context: &str,
) -> Result<()> {
    let should_be_named = index < usize::from(header.number_of_named_entries);
    if entry.is_named() != should_be_named {
        return Err(Error::invalid_data_directory(format!(
            "{context} entries are not ordered with named entries first"
        )));
    }
    Ok(())
}
