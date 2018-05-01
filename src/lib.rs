#![recursion_limit="128"]

#[macro_use] extern crate nom;
#[macro_use] extern crate enum_primitive;
extern crate exe;

#[allow(dead_code)]
#[allow(unused_macros)]

pub mod enums;
pub use enums::*;

pub mod structures;
pub use structures::*;

pub mod parsers;
pub use parsers::*;


impl<'a> exe::Section for SectionHeader<'a> {
    fn get_flags(&self) -> u32 {
        let mut flags = 0u32;

        if self.characteristics & SectionCharacteristic::MemoryRead as u32 != 0 {
            flags |= 4;
        }
        if self.characteristics & SectionCharacteristic::MemoryWrite as u32 != 0 {
            flags |= 2;
        }
        if self.characteristics & SectionCharacteristic::ContainsCode as u32 != 0 {
            flags |= 1;
        }
        if self.characteristics & SectionCharacteristic::MemoryExecute as u32 != 0 {
            flags |= 1;
        }

        flags
    }

    fn get_offset(&self) -> usize {
        self.pointer_to_raw_data as usize
    }

    fn get_size(&self) -> usize {
        self.size_of_raw_data as usize
    }
}

impl<'a> exe::Exe<'a> for PeHeader<'a> {
    type Item = SectionHeader<'a>;

    fn get_number_of_sections(&self) -> usize {
        self.file_header.number_of_sections as usize
    }

    fn get_section_at(&self, idx: usize) -> Option<&Self::Item> {
        self.sections.iter().nth(idx)
    }

    fn get_data(&self, start: usize, len: usize) -> &[u8] {
        &self.data[start .. (start + len)]
    }

    fn parse(i: &'a [u8]) -> Option<Self> {
        match parse_pe_header(i) {
            Ok((_, pe)) => Some(pe),
            Err(_) => None
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
