use num_traits::FromPrimitive;

use crate::enums::{DllCharacteristics, ImageDataDirectoryIndex, OptionalHeaderMagic, SubSystem};
use crate::structures::data_directory::DataDirectory;

use std::fmt;

#[derive(Debug)]
pub struct OptionalHeader32 {
    pub magic: OptionalHeaderMagic,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: SubSystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub data_directory: Vec<DataDirectory>,
}

impl OptionalHeader32 {
    pub const fn size() -> usize {
        224
    }
}

impl fmt::Display for OptionalHeader32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = f.width().unwrap_or_default() + 1;
        let offset = "  ".repeat(width);
        write!(f, "{offset}magic: {}\n", self.magic)?;
        write!(
            f,
            "{offset}major_linker_version: 0x{:x}\n",
            self.major_linker_version
        )?;
        write!(
            f,
            "{offset}minor_linker_version: 0x{:x}\n",
            self.minor_linker_version
        )?;
        write!(f, "{offset}size_of_code: 0x{:x}\n", self.size_of_code)?;
        write!(
            f,
            "{offset}size_of_initialized_data: 0x{:x}\n",
            self.size_of_initialized_data
        )?;
        write!(
            f,
            "{offset}size_of_uninitialized_data: 0x{:x}\n",
            self.size_of_uninitialized_data
        )?;
        write!(
            f,
            "{offset}address_of_entry_point: 0x{:x}\n",
            self.address_of_entry_point
        )?;
        write!(f, "{offset}base_of_code: 0x{:x}\n", self.base_of_code)?;
        write!(f, "{offset}base_of_data: 0x{:x}\n", self.base_of_data)?;
        write!(f, "{offset}image_base: 0x{:x}\n", self.image_base)?;
        write!(
            f,
            "{offset}section_alignment: 0x{:x}\n",
            self.section_alignment
        )?;
        write!(f, "{offset}file_alignment: 0x{:x}\n", self.file_alignment)?;
        write!(
            f,
            "{offset}major_operating_system_version: 0x{:x}\n",
            self.major_operating_system_version
        )?;
        write!(
            f,
            "{offset}minor_operating_system_version: 0x{:x}\n",
            self.minor_operating_system_version
        )?;
        write!(
            f,
            "{offset}major_image_version: 0x{:x}\n",
            self.major_image_version
        )?;
        write!(
            f,
            "{offset}minor_image_version: 0x{:x}\n",
            self.minor_image_version
        )?;
        write!(
            f,
            "{offset}major_subsystem_version: 0x{:x}\n",
            self.major_subsystem_version
        )?;
        write!(
            f,
            "{offset}minor_subsystem_version: 0x{:x}\n",
            self.minor_subsystem_version
        )?;
        write!(
            f,
            "{offset}win32_version_value: 0x{:x}\n",
            self.win32_version_value
        )?;
        write!(f, "{offset}size_of_image: 0x{:x}\n", self.size_of_image)?;
        write!(f, "{offset}size_of_headers: 0x{:x}\n", self.size_of_headers)?;
        write!(f, "{offset}check_sum: 0x{:x}\n", self.check_sum)?;
        write!(f, "{offset}subsystem: {}\n", self.subsystem)?;
        write!(
            f,
            "{offset}dll_characteristics: {}\n",
            self.dll_characteristics
        )?;
        write!(
            f,
            "{offset}size_of_stack_reserve: 0x{:x}\n",
            self.size_of_stack_reserve
        )?;
        write!(
            f,
            "{offset}size_of_stack_commit: 0x{:x}\n",
            self.size_of_stack_commit
        )?;
        write!(
            f,
            "{offset}size_of_heap_reserve: 0x{:x}\n",
            self.size_of_heap_reserve
        )?;
        write!(
            f,
            "{offset}size_of_heap_commit: 0x{:x}\n",
            self.size_of_heap_commit
        )?;
        write!(f, "{offset}loader_flags: 0x{:x}\n", self.loader_flags)?;
        write!(f, "{offset}data_directory:\n")?;
        for dd in &self.data_directory[..] {
            write!(f, "{:width$}\n", dd)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct OptionalHeader64 {
    pub magic: OptionalHeaderMagic,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: SubSystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub data_directory: Vec<DataDirectory>,
}

impl OptionalHeader64 {
    pub const fn size() -> usize {
        240
    }
}

impl fmt::Display for OptionalHeader64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = f.width().unwrap_or_default() + 1;
        let offset = "  ".repeat(width);
        write!(f, "{offset}magic: {}\n", self.magic)?;
        write!(
            f,
            "{offset}major_linker_version: 0x{:x}\n",
            self.major_linker_version
        )?;
        write!(
            f,
            "{offset}minor_linker_version: 0x{:x}\n",
            self.minor_linker_version
        )?;
        write!(f, "{offset}size_of_code: 0x{:x}\n", self.size_of_code)?;
        write!(
            f,
            "{offset}size_of_initialized_data: 0x{:x}\n",
            self.size_of_initialized_data
        )?;
        write!(
            f,
            "{offset}size_of_uninitialized_data: 0x{:x}\n",
            self.size_of_uninitialized_data
        )?;
        write!(
            f,
            "{offset}address_of_entry_point: 0x{:x}\n",
            self.address_of_entry_point
        )?;
        write!(f, "{offset}base_of_code: 0x{:x}\n", self.base_of_code)?;
        write!(f, "{offset}image_base: 0x{:x}\n", self.image_base)?;
        write!(
            f,
            "{offset}section_alignment: 0x{:x}\n",
            self.section_alignment
        )?;
        write!(f, "{offset}file_alignment: 0x{:x}\n", self.file_alignment)?;
        write!(
            f,
            "{offset}major_operating_system_version: 0x{:x}\n",
            self.major_operating_system_version
        )?;
        write!(
            f,
            "{offset}minor_operating_system_version: 0x{:x}\n",
            self.minor_operating_system_version
        )?;
        write!(
            f,
            "{offset}major_image_version: 0x{:x}\n",
            self.major_image_version
        )?;
        write!(
            f,
            "{offset}minor_image_version: 0x{:x}\n",
            self.minor_image_version
        )?;
        write!(
            f,
            "{offset}major_subsystem_version: 0x{:x}\n",
            self.major_subsystem_version
        )?;
        write!(
            f,
            "{offset}minor_subsystem_version: 0x{:x}\n",
            self.minor_subsystem_version
        )?;
        write!(
            f,
            "{offset}win32_version_value: 0x{:x}\n",
            self.win32_version_value
        )?;
        write!(f, "{offset}size_of_image: 0x{:x}\n", self.size_of_image)?;
        write!(f, "{offset}size_of_headers: 0x{:x}\n", self.size_of_headers)?;
        write!(f, "{offset}check_sum: 0x{:x}\n", self.check_sum)?;
        write!(f, "{offset}subsystem: {}\n", self.subsystem)?;
        write!(
            f,
            "{offset}dll_characteristics: {}\n",
            self.dll_characteristics
        )?;
        write!(
            f,
            "{offset}size_of_stack_reserve: 0x{:x}\n",
            self.size_of_stack_reserve
        )?;
        write!(
            f,
            "{offset}size_of_stack_commit: 0x{:x}\n",
            self.size_of_stack_commit
        )?;
        write!(
            f,
            "{offset}size_of_heap_reserve: 0x{:x}\n",
            self.size_of_heap_reserve
        )?;
        write!(
            f,
            "{offset}size_of_heap_commit: 0x{:x}\n",
            self.size_of_heap_commit
        )?;
        write!(f, "{offset}loader_flags: 0x{:x}\n", self.loader_flags)?;
        write!(f, "{offset}data_directory:\n")?;
        let width = width + 1;
        for (idx, dd) in self.data_directory.iter().enumerate() {
            if let Some(name) = ImageDataDirectoryIndex::from_usize(idx) {
                write!(f, "{offset}  {}\n{:width$}\n", name, dd)?;
            } else {
                write!(f, "{offset}  0x{:x}\n{:width$}\n", idx, dd)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum OptionalHeader {
    I386(OptionalHeader32),
    AMD64(OptionalHeader64),
}

impl fmt::Display for OptionalHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I386(ref oh) => fmt::Display::fmt(oh, f),
            Self::AMD64(ref oh) => fmt::Display::fmt(oh, f),
        }
    }
}

impl OptionalHeader {
    pub const fn size(&self) -> usize {
        match self {
            Self::I386(_) => OptionalHeader32::size(),
            Self::AMD64(_) => OptionalHeader64::size(),
        }
    }

    pub fn size_of_image(&self) -> usize {
        match self {
            Self::I386(ref i386) => i386.size_of_image as usize,
            Self::AMD64(ref amd64) => amd64.size_of_image as usize,
        }
    }
}
