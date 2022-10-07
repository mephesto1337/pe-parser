use std::fmt;

use crate::enums::SectionCharacteristics;

#[derive(Debug)]
pub enum SectionName<'a> {
    Short(&'a str),
    Offset(usize),
}

impl<'a> fmt::Display for SectionName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short(name) => f.write_str(name),
            Self::Offset(off) => write!(f, "Long name at 0x{:x}", off),
        }
    }
}

#[derive(Debug)]
pub struct SectionHeader<'a> {
    pub name: SectionName<'a>,
    pub physical_address: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: SectionCharacteristics,
}

impl<'a> fmt::Display for SectionHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = "  ".repeat(f.width().unwrap_or_default() + 1);
        write!(f, "{offset}name: {}\n", self.name)?;
        write!(
            f,
            "{offset}physical_address: 0x{:x}\n",
            self.physical_address
        )?;
        write!(f, "{offset}virtual_address: 0x{:x}\n", self.virtual_address)?;
        write!(
            f,
            "{offset}size_of_raw_data: 0x{:x}\n",
            self.size_of_raw_data
        )?;
        write!(
            f,
            "{offset}pointer_to_raw_data: 0x{:x}\n",
            self.pointer_to_raw_data
        )?;
        write!(
            f,
            "{offset}pointer_to_relocations: 0x{:x}\n",
            self.pointer_to_relocations
        )?;
        write!(
            f,
            "{offset}pointer_to_linenumbers: 0x{:x}\n",
            self.pointer_to_linenumbers
        )?;
        write!(
            f,
            "{offset}number_of_relocations: 0x{:x}\n",
            self.number_of_relocations
        )?;
        write!(
            f,
            "{offset}number_of_linenumbers: 0x{:x}\n",
            self.number_of_linenumbers
        )?;
        write!(f, "{offset}characteristics: {}\n", self.characteristics)?;
        Ok(())
    }
}
