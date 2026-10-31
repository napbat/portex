use super::{
    Error, ResourceDataEntry, ResourceDirectory, ResourceDirectoryEntry, ResourceDirectoryHeader,
    ResourceId, ResourceType, Result,
};
use crate::prelude::*;

/// A resource entry that owns its data, used to build a resource directory.
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    /// Resource type (level 1).
    pub type_id: ResourceId,
    /// Resource name or ID (level 2).
    pub name: ResourceId,
    /// Language ID (level 3).
    pub language: u16,
    /// Code page.
    pub code_page: u32,
    /// Resource data.
    pub data: Vec<u8>,
}

impl ResourceEntry {
    /// Create a resource entry with a numeric type and a numeric ID.
    #[must_use]
    pub fn new(type_id: u16, id: u16, language: u16, data: Vec<u8>) -> Self {
        Self {
            type_id: ResourceId::Id(type_id),
            name: ResourceId::Id(id),
            language,
            code_page: 0,
            data,
        }
    }

    /// Create a resource entry with a standard resource type.
    #[must_use]
    pub fn with_type(rt: ResourceType, id: u16, language: u16, data: Vec<u8>) -> Self {
        Self::new(rt.as_u16(), id, language, data)
    }

    /// Create a manifest resource (`RT_MANIFEST`, ID 1, language 0x0409).
    #[must_use]
    pub fn manifest(data: Vec<u8>) -> Self {
        Self::with_type(ResourceType::Manifest, 1, 0x0409, data)
    }

    /// Create a version information resource (`RT_VERSION`, ID 1, language 0x0409).
    #[must_use]
    pub fn version_info(data: Vec<u8>) -> Self {
        Self::with_type(ResourceType::Version, 1, 0x0409, data)
    }
}

/// Builder for a resource directory.
///
/// The PE resource directory is a tree with 3 levels:
/// - Level 1: resource type (for example `RT_ICON`, `RT_MANIFEST`).
/// - Level 2: resource name or ID.
/// - Level 3: language ID.
///
/// `FindResourceW` converts the name that it looks for to uppercase. Then it does a binary
/// search over the named entries, and compares UTF-16 code units. Thus the builder does these
/// steps for type names and for resource names:
/// - [`Self::add`] stores each name in uppercase. It converts each UTF-16 unit with its simple
///   uppercase mapping, as Windows does. A character outside the Basic Multilingual Plane, and
///   a character without a single-character uppercase form (for example `ß`), stay the same.
/// - The build sorts the named entries by their UTF-16 code units.
/// - The build rejects two names that are the same after the conversion to uppercase.
///
/// The uppercase table of Windows can be different for a small number of characters.
///
/// # Example
///
/// ```
/// use portex::{ResourceBuilder, ResourceEntry};
///
/// let mut builder = ResourceBuilder::new();
/// builder.add(ResourceEntry::manifest(b"<assembly/>".to_vec()));
/// let (data, size) = builder.try_build(0x3000)?;
/// assert_eq!(data.len(), size as usize);
/// # Ok::<(), portex::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct ResourceBuilder {
    /// Resources to include.
    entries: Vec<ResourceEntry>,
    /// The fields of the root `IMAGE_RESOURCE_DIRECTORY`. The entry counts are zero.
    root_header: ResourceDirectoryHeader,
}

impl ResourceBuilder {
    /// Create an empty resource builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder from a parsed `ResourceDirectory`.
    ///
    /// Parse the directory with `resources_with_data()` first. This sets the `Resource::data`
    /// field. The builder keeps the fields of [`ResourceDirectory::root_header`], except the
    /// entry counts. Like [`Self::add`], it stores each name in uppercase.
    ///
    /// Returns `None` if the `data` field of a resource is `None`. The loaders set this field
    /// to an empty vector for a zero-size resource.
    #[must_use]
    pub fn from_directory(directory: &ResourceDirectory) -> Option<Self> {
        let mut builder = Self::new();
        builder.set_root_header(directory.root_header);
        for resource in &directory.resources {
            let data = resource.data.as_ref()?.clone();
            builder.add(ResourceEntry {
                type_id: resource.type_id.clone(),
                name: resource.name.clone(),
                language: resource.language,
                code_page: resource.code_page,
                data,
            });
        }
        Some(builder)
    }

    /// Add a resource entry. Store the type name and the resource name in uppercase.
    ///
    /// The build rejects two entries with the same type, name and language. This also applies
    /// to names that are the same only after the conversion to uppercase.
    pub fn add(&mut self, mut entry: ResourceEntry) -> &mut Self {
        uppercase_name(&mut entry.type_id);
        uppercase_name(&mut entry.name);
        self.entries.push(entry);
        self
    }

    /// Set the `Characteristics`, `TimeDateStamp`, `MajorVersion` and `MinorVersion` fields of
    /// the root `IMAGE_RESOURCE_DIRECTORY`.
    ///
    /// The builder ignores the entry counts of `header`. It calculates them. The other
    /// directories of the tree get zero in these fields.
    pub fn set_root_header(&mut self, header: ResourceDirectoryHeader) -> &mut Self {
        self.root_header = ResourceDirectoryHeader {
            number_of_named_entries: 0,
            number_of_id_entries: 0,
            ..header
        };
        self
    }

    /// Get the fields of the root `IMAGE_RESOURCE_DIRECTORY` that [`Self::set_root_header`]
    /// set. The entry counts are zero.
    #[must_use]
    pub fn root_header(&self) -> ResourceDirectoryHeader {
        self.root_header
    }

    /// Add a resource with a standard resource type.
    pub fn add_resource(
        &mut self,
        rt: ResourceType,
        id: u16,
        language: u16,
        data: Vec<u8>,
    ) -> &mut Self {
        self.add(ResourceEntry::with_type(rt, id, language, data))
    }

    /// Add a manifest resource.
    pub fn add_manifest(&mut self, data: Vec<u8>) -> &mut Self {
        self.add(ResourceEntry::manifest(data))
    }

    /// Add a version information resource.
    pub fn add_version_info(&mut self, data: Vec<u8>) -> &mut Self {
        self.add(ResourceEntry::version_info(data))
    }

    /// Calculate the total size of the resource section, in bytes.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_calculate_size`] fails.
    #[must_use]
    pub fn calculate_size(&self) -> usize {
        self.try_calculate_size()
            .expect("resource size overflow: use try_calculate_size()")
    }

    /// Calculate the resource size, in bytes.
    ///
    /// This function checks the tree counts, the UTF-16 lengths, the data lengths and the
    /// relative offsets.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data-directory error if one of these conditions is true:
    /// - More than 262,144 entries were added.
    /// - Two entries have the same type, name and language. The builder compares the names in
    ///   uppercase.
    /// - A name is longer than 65,535 UTF-16 units.
    /// - A payload is larger than `u32::MAX` bytes.
    /// - A directory level has more than 65,535 entries.
    /// - The serialized tree is larger than the 31-bit range of a relative offset.
    pub fn try_calculate_size(&self) -> Result<usize> {
        if self.entries.is_empty() {
            return Ok(0);
        }

        Ok(self.try_compute_layout()?.total_size)
    }

    /// Build the resource directory data.
    ///
    /// `base_rva` is the RVA of the start of the resource directory. Returns
    /// `(data, total_size)`.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_build`] fails.
    #[must_use]
    pub fn build(&self, base_rva: u32) -> (Vec<u8>, u32) {
        self.try_build(base_rva)
            .expect("resource build failed: use try_build() for fallible serialization")
    }

    /// Build the resource tree with checked relative offsets and checked data RVAs.
    ///
    /// `base_rva` is the RVA of the start of the resource directory. Returns
    /// `(data, total_size)`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::try_calculate_size`]. Also returns an
    /// invalid-data-directory error if `base_rva` plus the tree size overflows `u32`, or if a
    /// payload RVA overflows `u32`.
    pub fn try_build(&self, base_rva: u32) -> Result<(Vec<u8>, u32)> {
        if self.entries.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let layout = self.try_compute_layout()?;
        let total_size = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("resource directory exceeds u32"))?;
        base_rva
            .checked_add(total_size)
            .ok_or_else(|| Error::invalid_data_directory("resource data RVA range overflow"))?;
        let mut data = vec![0u8; layout.total_size];

        // Level 1: the root directory lists the types.
        write_table(
            &mut data,
            0,
            id_table_header(self.root_header, layout.types.iter().map(|ty| &ty.id))?,
            layout
                .types
                .iter()
                .map(|ty| subdirectory_entry(&ty.id, ty.name_offset, ty.dir_offset)),
        )?;
        for ty in &layout.types {
            // Level 2: each type directory lists the names.
            write_table(
                &mut data,
                ty.dir_offset,
                id_table_header(
                    ResourceDirectoryHeader::default(),
                    ty.names.iter().map(|name| &name.id),
                )?,
                ty.names
                    .iter()
                    .map(|name| subdirectory_entry(&name.id, name.name_offset, name.dir_offset)),
            )?;
            for name in &ty.names {
                // Level 3: each name directory lists the languages.
                let header = ResourceDirectoryHeader {
                    number_of_id_entries: checked_u16_count(
                        name.languages.len(),
                        "resource language",
                    )?,
                    ..ResourceDirectoryHeader::default()
                };
                write_table(
                    &mut data,
                    name.dir_offset,
                    header,
                    name.languages.iter().map(|lang| ResourceDirectoryEntry {
                        name_or_id: u32::from(lang.language),
                        offset_to_data: lang.data_entry_offset,
                    }),
                )?;
                for lang in &name.languages {
                    write_language_data(&mut data, base_rva, lang)?;
                }
            }
        }

        // Write the name strings.
        for ty in &layout.types {
            if let ResourceIdKey::Name(units) = &ty.id {
                write_string_name(&mut data, ty.name_offset, units)?;
            }
        }
        for name in layout.types.iter().flat_map(|ty| &ty.names) {
            if let ResourceIdKey::Name(units) = &name.id {
                write_string_name(&mut data, name.name_offset, units)?;
            }
        }

        Ok((data, total_size))
    }

    /// Give an offset to each directory table, data entry, name string and payload. Each
    /// offset is relative to the start of the resource directory.
    ///
    /// Call [`Self::validate_entries`] first.
    fn compute_layout(&self) -> Result<ResourceLayout<'_>> {
        // Group the entries by type, then by name.
        let mut grouped: BTreeMap<ResourceIdKey, BTreeMap<ResourceIdKey, Vec<&ResourceEntry>>> =
            BTreeMap::new();
        for entry in &self.entries {
            grouped
                .entry(ResourceIdKey::from(&entry.type_id))
                .or_default()
                .entry(ResourceIdKey::from(&entry.name))
                .or_default()
                .push(entry);
        }

        // The directory tables and data entries come first, in depth-first order.
        let mut offset = table_end(0, grouped.len())?;
        let mut types = Vec::with_capacity(grouped.len());
        for (type_key, names_map) in grouped {
            let type_dir_offset = layout_offset(offset)?;
            offset = table_end(offset, names_map.len())?;
            let mut names = Vec::with_capacity(names_map.len());
            for (name_key, mut entries) in names_map {
                entries.sort_by_key(|entry| entry.language);
                let lang_dir_offset = layout_offset(offset)?;
                offset = table_end(offset, entries.len())?;
                let mut languages = Vec::with_capacity(entries.len());
                for entry in entries {
                    languages.push(LanguageLayout {
                        language: entry.language,
                        data_entry_offset: layout_offset(offset)?,
                        data_offset: 0,
                        data_size: u32::try_from(entry.data.len()).map_err(|_| {
                            Error::invalid_data_directory("resource data exceeds u32")
                        })?,
                        code_page: entry.code_page,
                        data: &entry.data,
                    });
                    offset = layout_add(offset, ResourceDataEntry::SIZE)?;
                }
                names.push(NameLayout {
                    id: name_key,
                    dir_offset: lang_dir_offset,
                    name_offset: 0,
                    languages,
                });
            }
            types.push(TypeLayout {
                id: type_key,
                dir_offset: type_dir_offset,
                name_offset: 0,
                names,
            });
        }

        // The name strings come next: first the type names, then the entry names.
        for ty in &mut types {
            if let ResourceIdKey::Name(units) = &ty.id {
                ty.name_offset = layout_offset(offset)?;
                offset = layout_add(offset, name_string_size(units)?)?;
            }
        }
        for name in types.iter_mut().flat_map(|ty| &mut ty.names) {
            if let ResourceIdKey::Name(units) = &name.id {
                name.name_offset = layout_offset(offset)?;
                offset = layout_add(offset, name_string_size(units)?)?;
            }
        }

        // The payloads come last. Each payload starts on an 8-byte boundary.
        offset = align_8(offset)?;
        for lang in types
            .iter_mut()
            .flat_map(|ty| &mut ty.names)
            .flat_map(|name| &mut name.languages)
        {
            lang.data_offset = layout_offset(offset)?;
            offset = layout_add(offset, align_8(lang.data.len())?)?;
        }

        Ok(ResourceLayout {
            types,
            total_size: offset,
        })
    }

    fn try_compute_layout(&self) -> Result<ResourceLayout<'_>> {
        self.validate_entries()?;
        self.compute_layout()
    }

    fn validate_entries(&self) -> Result<()> {
        const MAX_RESOURCE_ENTRIES: usize = 262_144;
        const MAX_RELATIVE_OFFSET: u64 = 0x7fff_ffff;
        if self.entries.len() > MAX_RESOURCE_ENTRIES {
            return Err(Error::invalid_data_directory(format!(
                "resource count {} exceeds the safety limit {}",
                self.entries.len(),
                MAX_RESOURCE_ENTRIES
            )));
        }

        let grouped = self.group_validated_entries()?;
        let mut total = directory_tree_size(&grouped)?;

        total = total
            .checked_add(7)
            .map(|size| size & !7)
            .ok_or_else(|| Error::invalid_data_directory("resource alignment overflow"))?;
        for entry in &self.entries {
            let aligned = (entry.data.len() as u64)
                .checked_add(7)
                .map(|size| size & !7)
                .ok_or_else(|| Error::invalid_data_directory("resource data size overflow"))?;
            total = checked_u64_add(total, aligned, "resource data")?;
        }
        if total > MAX_RELATIVE_OFFSET {
            return Err(Error::invalid_data_directory(format!(
                "resource directory size {total:#x} exceeds the 31-bit relative-offset format"
            )));
        }
        Ok(())
    }

    /// Validate the name lengths and the payload size of each entry. Make sure that each
    /// type/name/language triple is unique.
    ///
    /// Returns the languages, grouped by type and name.
    fn group_validated_entries(&self) -> Result<GroupedLanguages> {
        let mut grouped = GroupedLanguages::new();
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            validate_resource_id(&entry.type_id, "resource type")?;
            validate_resource_id(&entry.name, "resource name")?;
            u32::try_from(entry.data.len())
                .map_err(|_| Error::invalid_data_directory("resource data exceeds u32"))?;
            let type_key = ResourceIdKey::from(&entry.type_id);
            let name_key = ResourceIdKey::from(&entry.name);
            if !seen.insert((type_key.clone(), name_key.clone(), entry.language)) {
                return Err(Error::invalid_data_directory(format!(
                    "duplicate resource type/name/language entry ({:?}, {:?}, {})",
                    entry.type_id, entry.name, entry.language
                )));
            }
            grouped
                .entry(type_key)
                .or_default()
                .entry(name_key)
                .or_default()
                .push(entry.language);
        }
        Ok(grouped)
    }
}

/// Size in bytes of the tree that `grouped` describes: the directory tables, data entries and
/// name strings. The size does not include the payload data.
fn directory_tree_size(grouped: &GroupedLanguages) -> Result<u64> {
    checked_u16_count(grouped.len(), "resource type")?;

    let mut total = checked_u64_add(
        ResourceDirectoryHeader::SIZE as u64,
        checked_u64_mul(grouped.len(), ResourceDirectoryEntry::SIZE, "resource root")?,
        "resource root",
    )?;
    for (resource_type, names) in grouped {
        checked_u16_count(names.len(), "resource name")?;
        total = checked_u64_add(
            total,
            checked_u64_add(
                ResourceDirectoryHeader::SIZE as u64,
                checked_u64_mul(names.len(), ResourceDirectoryEntry::SIZE, "resource names")?,
                "resource names",
            )?,
            "resource directory",
        )?;
        if let ResourceIdKey::Name(name) = resource_type {
            total = checked_u64_add(total, resource_name_size(name)?, "resource strings")?;
        }
        for (name, languages) in names {
            checked_u16_count(languages.len(), "resource language")?;
            total = checked_u64_add(
                total,
                checked_u64_add(
                    ResourceDirectoryHeader::SIZE as u64,
                    checked_u64_mul(
                        languages.len(),
                        ResourceDirectoryEntry::SIZE,
                        "resource languages",
                    )?,
                    "resource languages",
                )?,
                "resource directory",
            )?;
            total = checked_u64_add(
                total,
                checked_u64_mul(
                    languages.len(),
                    ResourceDataEntry::SIZE,
                    "resource data entries",
                )?,
                "resource data entries",
            )?;
            if let ResourceIdKey::Name(name) = name {
                total = checked_u64_add(total, resource_name_size(name)?, "resource strings")?;
            }
        }
    }
    Ok(total)
}

fn validate_resource_id(id: &ResourceId, context: &str) -> Result<()> {
    if let ResourceId::Name(name) = id {
        let units = name.encode_utf16().count();
        if units > usize::from(u16::MAX) {
            return Err(Error::invalid_data_directory(format!(
                "{context} is {units} UTF-16 units, exceeding u16"
            )));
        }
    }
    Ok(())
}

fn checked_u16_count(count: usize, context: &str) -> Result<u16> {
    u16::try_from(count)
        .map_err(|_| Error::invalid_data_directory(format!("{context} count exceeds u16")))
}

fn layout_offset(offset: usize) -> Result<u32> {
    u32::try_from(offset)
        .map_err(|_| Error::invalid_data_directory("resource layout offset exceeds u32"))
}

/// Return `offset + len`, or an error if the sum overflows `usize`.
fn layout_add(offset: usize, len: usize) -> Result<usize> {
    offset
        .checked_add(len)
        .ok_or_else(|| Error::invalid_data_directory("resource layout offset overflow"))
}

/// Return the end of a directory table that starts at `offset` and has
/// `count` entries.
fn table_end(offset: usize, count: usize) -> Result<usize> {
    let entries = count
        .checked_mul(ResourceDirectoryEntry::SIZE)
        .ok_or_else(|| Error::invalid_data_directory("resource layout offset overflow"))?;
    layout_add(layout_add(offset, ResourceDirectoryHeader::SIZE)?, entries)
}

/// Round `value` up to the next multiple of 8.
fn align_8(value: usize) -> Result<usize> {
    Ok(layout_add(value, 7)? & !7)
}

/// Return the size in bytes of a name string: a `u16` length, then the
/// UTF-16 units.
fn name_string_size(units: &[u16]) -> Result<usize> {
    usize::try_from(resource_name_size(units)?)
        .map_err(|_| Error::invalid_data_directory("resource-name size overflow"))
}

/// Build the header of a directory table whose entries have the identifiers `ids`.
///
/// The header gets the other fields from `template`.
fn id_table_header<'a, I>(
    template: ResourceDirectoryHeader,
    ids: I,
) -> Result<ResourceDirectoryHeader>
where
    I: Iterator<Item = &'a ResourceIdKey> + Clone,
{
    let named = ids
        .clone()
        .filter(|id| matches!(id, ResourceIdKey::Name(_)))
        .count();
    let numeric = ids.filter(|id| matches!(id, ResourceIdKey::Id(_))).count();
    Ok(ResourceDirectoryHeader {
        number_of_named_entries: checked_u16_count(named, "resource named-entry")?,
        number_of_id_entries: checked_u16_count(numeric, "resource ID-entry")?,
        ..template
    })
}

/// Build a directory entry that points to the subdirectory at `dir_offset`.
///
/// A named entry points to its name string at `name_offset`.
fn subdirectory_entry(
    id: &ResourceIdKey,
    name_offset: u32,
    dir_offset: u32,
) -> ResourceDirectoryEntry {
    let name_or_id = match id {
        ResourceIdKey::Id(id) => u32::from(*id),
        ResourceIdKey::Name(_) => 0x8000_0000 | name_offset,
    };
    ResourceDirectoryEntry {
        name_or_id,
        offset_to_data: 0x8000_0000 | dir_offset,
    }
}

/// Copy `bytes` into `data` at `offset`.
///
/// Returns an invalid-data-directory error if the range is outside `data`.
fn write_bytes(data: &mut [u8], offset: usize, bytes: &[u8]) -> Result<()> {
    offset
        .checked_add(bytes.len())
        .and_then(|end| data.get_mut(offset..end))
        .ok_or_else(|| {
            Error::invalid_data_directory("resource layout exceeds the directory buffer")
        })?
        .copy_from_slice(bytes);
    Ok(())
}

/// Write a directory table at `offset`: first `header`, then each entry in order.
fn write_table<I>(
    data: &mut [u8],
    offset: u32,
    header: ResourceDirectoryHeader,
    entries: I,
) -> Result<()>
where
    I: IntoIterator<Item = ResourceDirectoryEntry>,
{
    let mut cursor = offset as usize;
    write_bytes(data, cursor, &header.to_bytes())?;
    cursor = layout_add(cursor, ResourceDirectoryHeader::SIZE)?;
    for entry in entries {
        write_bytes(data, cursor, &entry.to_bytes())?;
        cursor = layout_add(cursor, ResourceDirectoryEntry::SIZE)?;
    }
    Ok(())
}

/// Write the `IMAGE_RESOURCE_DATA_ENTRY` and the payload of `lang`.
///
/// `base_rva` is the RVA of the start of the resource directory.
fn write_language_data(data: &mut [u8], base_rva: u32, lang: &LanguageLayout<'_>) -> Result<()> {
    let data_rva = base_rva
        .checked_add(lang.data_offset)
        .ok_or_else(|| Error::invalid_data_directory("resource data RVA overflow"))?;
    let entry = ResourceDataEntry {
        offset_to_data: data_rva,
        size: lang.data_size,
        code_page: lang.code_page,
        reserved: 0,
    };
    write_bytes(data, lang.data_entry_offset as usize, &entry.to_bytes())?;
    write_bytes(data, lang.data_offset as usize, lang.data)
}

/// Write a name string at `offset`: a `u16` length, then the UTF-16LE units.
fn write_string_name(data: &mut [u8], offset: u32, units: &[u16]) -> Result<()> {
    let count = checked_u16_count(units.len(), "resource-name UTF-16 unit")?;
    let mut bytes = Vec::with_capacity(name_string_size(units)?);
    bytes.extend_from_slice(&count.to_le_bytes());
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    write_bytes(data, offset as usize, &bytes)
}

fn resource_name_size(units: &[u16]) -> Result<u64> {
    let units = units.len();
    checked_u16_count(units, "resource-name UTF-16 unit")?;
    (units as u64)
        .checked_mul(2)
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| Error::invalid_data_directory("resource-name size overflow"))
}

fn checked_u64_mul(count: usize, width: usize, context: &str) -> Result<u64> {
    (count as u64)
        .checked_mul(width as u64)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))
}

fn checked_u64_add(left: u64, right: u64, context: &str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))
}

/// The sort key of a type or name entry.
///
/// In each resource directory, the named entries must come before the numeric IDs. The
/// loader compares the UTF-16 code units of names, and a shorter name comes before a longer
/// name with the same start. The order of `Vec<u16>` is the same.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceIdKey {
    Name(Vec<u16>),
    Id(u16),
}

impl ResourceIdKey {
    fn from(id: &ResourceId) -> Self {
        match id {
            ResourceId::Id(n) => Self::Id(*n),
            ResourceId::Name(s) => Self::Name(s.encode_utf16().collect()),
        }
    }
}

/// Convert a name to uppercase, as `FindResourceW` converts the name that it looks for.
///
/// Windows converts each UTF-16 unit with a table of simple uppercase mappings. Thus a
/// character outside the Basic Multilingual Plane stays the same. A character whose uppercase
/// form has more than one character (for example `ß`) also stays the same.
fn uppercase_name(id: &mut ResourceId) {
    if let ResourceId::Name(name) = id
        && name.chars().any(|c| uppercase_unit(c) != c)
    {
        *name = name.chars().map(uppercase_unit).collect();
    }
}

/// Return the simple uppercase form of `c`, if `c` and the result are each one UTF-16 unit.
/// Otherwise return `c`.
fn uppercase_unit(c: char) -> char {
    if c.len_utf16() != 1 {
        return c;
    }
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) if single.len_utf16() == 1 => single,
        _ => c,
    }
}

/// Layout of one language entry: its data entry and its payload.
#[derive(Debug)]
struct LanguageLayout<'a> {
    language: u16,
    /// Offset of the `IMAGE_RESOURCE_DATA_ENTRY`, relative to the start of
    /// the resource directory.
    data_entry_offset: u32,
    /// Offset of the payload, relative to the start of the resource directory.
    data_offset: u32,
    data_size: u32,
    code_page: u32,
    data: &'a [u8],
}

/// Layout of one name entry and its language directory.
#[derive(Debug)]
struct NameLayout<'a> {
    id: ResourceIdKey,
    /// Offset of the language directory, relative to the start of the
    /// resource directory.
    dir_offset: u32,
    /// Offset of the name string, relative to the start of the resource
    /// directory. The value is zero for a numeric ID.
    name_offset: u32,
    languages: Vec<LanguageLayout<'a>>,
}

/// Layout of one type entry and its name directory.
#[derive(Debug)]
struct TypeLayout<'a> {
    id: ResourceIdKey,
    /// Offset of the name directory, relative to the start of the resource
    /// directory.
    dir_offset: u32,
    /// Offset of the type name string, relative to the start of the resource
    /// directory. The value is zero for a numeric ID.
    name_offset: u32,
    names: Vec<NameLayout<'a>>,
}

/// Layout of the full resource directory.
#[derive(Debug)]
struct ResourceLayout<'a> {
    types: Vec<TypeLayout<'a>>,
    total_size: usize,
}

/// Languages grouped by type key, then name key, used during validation.
type GroupedLanguages = BTreeMap<ResourceIdKey, BTreeMap<ResourceIdKey, Vec<u16>>>;
