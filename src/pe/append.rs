//! Appends of directory tables to sections. See the "Directory updates" section of
//! [`PeImage`].

use super::PeImage;
use crate::layout;
use crate::prelude::*;
use crate::section::characteristics;
use crate::{Error, Result};

/// The alignment of the data that an edit appends to a section, in bytes.
///
/// The structures of the data directories need at most 8-byte alignment (for example the
/// PE32+ `IMAGE_TLS_DIRECTORY64` and `IMAGE_LOAD_CONFIG_DIRECTORY64`).
const APPEND_ALIGNMENT: u32 = 8;

/// The name of the section that an edit adds for data that fits in no existing section.
const APPEND_SECTION_NAME: &str = ".portex";

/// The largest zero fill that an append writes before its data, in bytes.
///
/// An append after a large `VirtualSize` writes the uninitialized data of the section to the
/// file as zeros. `VirtualSize` comes from the file, so this limit stops a header value from
/// selecting the size of an allocation. Above the limit, an append uses another section or
/// returns an error.
const MAX_APPEND_ZERO_FILL: usize = 16 * 1024 * 1024;

/// The result of one append attempt in one section.
enum Attempt<T> {
    /// The data fits. The fields are the changed copy of the image, the RVA of the data and
    /// the value of the build function.
    Done(Box<PeImage>, u32, T),
    /// The data does not fit before the next section.
    NoFit,
    /// The data starts after more than [`MAX_APPEND_ZERO_FILL`] bytes of zero fill.
    LargeZeroFill,
    /// The data needs a writable section, and the section is not writable.
    NotWritable,
    /// The build function failed for the RVA of the attempt.
    BuildFailed(Error),
}

impl PeImage {
    /// Run `update` on a copy of the image, and keep the copy only if `update` succeeds.
    ///
    /// Use this method for an update that changes the image in more than one step. If a step
    /// fails, the image does not change.
    pub(super) fn transact<T>(&mut self, update: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let mut candidate = self.clone();
        let value = update(&mut candidate)?;
        *self = candidate;
        Ok(value)
    }

    /// Update the layout, and return the RVA where an append to a section puts its data.
    ///
    /// The data starts after `VirtualSize`, so that it does not overwrite the uninitialized
    /// data (BSS) of the section. It also starts after the last nonzero raw byte, so that it
    /// does not overwrite data after `VirtualSize`. Zero bytes of raw padding after both
    /// limits get the data. The RVA is aligned to [`APPEND_ALIGNMENT`], so that each structure
    /// in the data is aligned.
    ///
    /// A new section that has no RVA yet, no data and no `VirtualSize` gets the data at its
    /// start. The layout gives such a section a `VirtualSize` of one alignment unit. The data
    /// does not start after that size.
    fn prepare_section_append(&mut self, section_index: usize) -> Result<u32> {
        let header = &self
            .sections
            .get(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?
            .header;
        let new_section = header.virtual_address == 0
            && header.virtual_size == 0
            && self.sections[section_index].data.is_empty();
        self.try_update_layout()?;
        let section = &self.sections[section_index];
        // The loader uses `SizeOfRawData` as the size if `VirtualSize` is 0.
        let virtual_end = if new_section {
            0
        } else if section.header.virtual_size == 0 {
            section.data.len()
        } else {
            section.header.virtual_size as usize
        };
        let used_end = section
            .data
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |index| index + 1);
        u32::try_from(virtual_end.max(used_end))
            .ok()
            .and_then(|offset| layout::checked_align_up(offset, APPEND_ALIGNMENT))
            .and_then(|offset| section.header.virtual_address.checked_add(offset))
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))
    }

    /// Append `data` to a section at the RVA that [`Self::prepare_section_append`] returns.
    ///
    /// This is the append of [`Self::try_append_to_section`]: the caller named the section.
    ///
    /// # Errors
    ///
    /// Returns an error if the layout update fails, or if the data does not fit before the next
    /// section. Then the image does not change.
    pub(super) fn append_to_section_at(
        &mut self,
        section_index: usize,
        data: &[u8],
    ) -> Result<u32> {
        let (rva, ()) =
            self.append_section_data(section_index, true, |_| Ok((data.to_vec(), ())))?;
        Ok(rva)
    }

    /// Build data for an RVA in a section, and append it there.
    ///
    /// See [`Self::append_section_data_with`]. The data does not need a writable section.
    pub(super) fn append_section_data<T>(
        &mut self,
        section_index: usize,
        explicit_target: bool,
        build: impl FnMut(u32) -> Result<(Vec<u8>, T)>,
    ) -> Result<(u32, T)> {
        self.append_section_data_with(section_index, explicit_target, build, |_, _, _| false)
    }

    /// Build data for an RVA in a section, and append it there.
    ///
    /// `build` gets the RVA of the data and returns the bytes and a value for the caller.
    /// `needs_write` gets the image, the index of the section and the value of `build`. It
    /// returns `true` if the data needs a writable section there.
    ///
    /// If the data does not fit before the next section, if it starts after more than
    /// [`MAX_APPEND_ZERO_FILL`] bytes of zero fill, if `build` fails, or if the section is not
    /// writable and the data needs a writable section, the result depends on
    /// `explicit_target`:
    ///
    /// - If the caller named the section (`true`), the method returns an error.
    /// - Otherwise, the method appends the data to the last section. It does not use the last
    ///   section if that section is not readable, has uninitialized data, is discardable or is
    ///   `.rsrc`. It also does not use it if the data needs a writable section and the last
    ///   section is not writable. Then the method adds a new section for the data. The new
    ///   section is writable only if the data needs a writable section.
    ///
    /// The method calls `build` again for each new RVA. A `build` error in the last section or
    /// in the new section is the result.
    ///
    /// The method never moves a section. If it returns an error, the image does not change.
    /// Returns the RVA of the data and the value of `build`.
    pub(super) fn append_section_data_with<T>(
        &mut self,
        section_index: usize,
        explicit_target: bool,
        mut build: impl FnMut(u32) -> Result<(Vec<u8>, T)>,
        needs_write: impl Fn(&Self, usize, &T) -> bool,
    ) -> Result<(u32, T)> {
        let mut needs_writable_section = false;
        match self.try_append_at(section_index, &mut build, &needs_write)? {
            Attempt::Done(image, rva, value) => {
                *self = *image;
                return Ok((rva, value));
            }
            Attempt::BuildFailed(error) if explicit_target => return Err(error),
            Attempt::NoFit if explicit_target => {
                return Err(self.moved_section_error(section_index));
            }
            Attempt::LargeZeroFill if explicit_target => {
                return Err(self.zero_fill_error(section_index));
            }
            Attempt::NotWritable if explicit_target => {
                return Err(self.not_writable_error(section_index));
            }
            Attempt::NotWritable => needs_writable_section = true,
            Attempt::BuildFailed(_) | Attempt::NoFit | Attempt::LargeZeroFill => {}
        }

        if let Some(last) = self.fallback_section_index()
            && last != section_index
        {
            match self.try_append_at(last, &mut build, &needs_write)? {
                Attempt::Done(image, rva, value) => {
                    *self = *image;
                    return Ok((rva, value));
                }
                Attempt::BuildFailed(error) => return Err(error),
                Attempt::NotWritable => needs_writable_section = true,
                Attempt::NoFit | Attempt::LargeZeroFill => {}
            }
        }

        loop {
            let mut flags = characteristics::INITIALIZED_DATA | characteristics::READ;
            if needs_writable_section {
                flags |= characteristics::WRITE;
            }
            let mut candidate = self.clone();
            candidate.try_add_section_with_data(APPEND_SECTION_NAME, Vec::new(), flags)?;
            let index = candidate.sections.len() - 1;
            match candidate.try_append_at(index, &mut build, &needs_write)? {
                Attempt::Done(image, rva, value) => {
                    *self = *image;
                    return Ok((rva, value));
                }
                Attempt::BuildFailed(error) => return Err(error),
                Attempt::NoFit => return Err(candidate.moved_section_error(index)),
                Attempt::LargeZeroFill => return Err(candidate.zero_fill_error(index)),
                Attempt::NotWritable if !needs_writable_section => needs_writable_section = true,
                Attempt::NotWritable => return Err(candidate.not_writable_error(index)),
            }
        }
    }

    /// Try to append the data of `build` to the section at `section_index`, on a copy of the
    /// image.
    ///
    /// # Errors
    ///
    /// Returns an error if the layout update fails, if the index is out of range, or if the
    /// section data is too large. A `build` error is [`Attempt::BuildFailed`], not an error.
    fn try_append_at<T>(
        &self,
        section_index: usize,
        build: &mut impl FnMut(u32) -> Result<(Vec<u8>, T)>,
        needs_write: &impl Fn(&Self, usize, &T) -> bool,
    ) -> Result<Attempt<T>> {
        let mut candidate = self.clone();
        let rva = candidate.prepare_section_append(section_index)?;
        let (data, value) = match build(rva) {
            Ok(output) => output,
            Err(error) => return Ok(Attempt::BuildFailed(error)),
        };
        if needs_write(&candidate, section_index, &value)
            && !candidate.sections[section_index].header.is_writable()
        {
            return Ok(Attempt::NotWritable);
        }
        let addresses: Vec<u32> = candidate
            .sections
            .iter()
            .map(|section| section.header.virtual_address)
            .collect();
        let offset = rva
            .checked_sub(candidate.sections[section_index].header.virtual_address)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(|| Error::invalid_section("the append RVA is not in the section"))?;
        let section = &mut candidate.sections[section_index];
        if offset.saturating_sub(section.data.len()) > MAX_APPEND_ZERO_FILL {
            return Ok(Attempt::LargeZeroFill);
        }
        section.try_write_appended(offset, &data)?;
        candidate.try_update_layout()?;
        let moved = candidate
            .sections
            .iter()
            .map(|section| section.header.virtual_address)
            .ne(addresses);
        if moved {
            return Ok(Attempt::NoFit);
        }
        Ok(Attempt::Done(Box::new(candidate), rva, value))
    }

    /// Return the index of the section that gets appended tables when the caller names no
    /// section and the tables go to one section.
    ///
    /// This is the last section, if the fallback of an append can use it (see
    /// [`Self::append_section_data_with`]). Otherwise the method adds a new readable
    /// `.portex` section, and returns its index.
    ///
    /// # Errors
    ///
    /// Returns an error if the method cannot add the section. Then the image does not change.
    pub(super) fn default_append_section(&mut self) -> Result<usize> {
        if let Some(index) = self.fallback_section_index() {
            return Ok(index);
        }
        self.try_add_section_with_data(
            APPEND_SECTION_NAME,
            Vec::new(),
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )?;
        Ok(self.sections.len() - 1)
    }

    /// Return the index of the last section in RVA order, if an append can use it as the
    /// fallback.
    ///
    /// The section must be readable and have no uninitialized data after its data. It must not
    /// be discardable: a driver can free a discardable section after the load. It must not be
    /// `.rsrc`: resource editors write that section again, and they remove other data in it.
    fn fallback_section_index(&self) -> Option<usize> {
        let (index, section) = self
            .sections
            .iter()
            .enumerate()
            .max_by_key(|(_, section)| section.header.virtual_address)?;
        let header = &section.header;
        let usable = header.is_readable()
            && header.virtual_size as usize <= section.data.len()
            && header.characteristics & characteristics::DISCARDABLE == 0
            && section.name() != ".rsrc";
        usable.then_some(index)
    }

    /// Return the error for an append to a section that moves another section.
    fn moved_section_error(&self, section_index: usize) -> Error {
        Error::invalid_section(format!(
            "the data does not fit in section '{}' before the next section; \
             an append must not move a section",
            self.section_name_at(section_index)
        ))
    }

    /// Return the error for an append that needs more than [`MAX_APPEND_ZERO_FILL`] bytes of
    /// zero fill.
    fn zero_fill_error(&self, section_index: usize) -> Error {
        Error::invalid_section(format!(
            "the data starts after more than {MAX_APPEND_ZERO_FILL} bytes of uninitialized \
             data in section '{}'",
            self.section_name_at(section_index)
        ))
    }

    /// Return the error for an append that needs a writable section.
    fn not_writable_error(&self, section_index: usize) -> Error {
        Error::invalid_section(format!(
            "the data needs a writable section, and section '{}' is not writable",
            self.section_name_at(section_index)
        ))
    }

    /// Return the name of the section at `section_index`, or an empty name.
    fn section_name_at(&self, section_index: usize) -> String {
        self.sections
            .get(section_index)
            .map(|section| section.name().into_owned())
            .unwrap_or_default()
    }
}
