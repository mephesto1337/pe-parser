use nom::bytes::complete::{take, take_until1};
use nom::combinator::{map_opt, map_parser};
use nom::error::context;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;

use crate::enums::SectionCharacteristics;
use crate::structures::Name;
use crate::{NomError, Parse};

use std::fmt;

#[derive(Debug)]
pub struct SectionHeader<'a> {
    pub name: Name<'a>,
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

fn parse_section_name<'a, E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Name<'a>, E>
where
    E: NomError<'a>,
{
    let (rest, raw_name) = context(
        "Section name",
        map_opt(map_parser(take(8usize), take_until1(&b"\0"[..])), |s| {
            std::str::from_utf8(s).ok()
        }),
    )(input)?;
    if raw_name.starts_with('/') {
        match u64::from_str_radix(&raw_name[1..], 10) {
            Ok(rva) => Ok((rest, Name::Rva(rva))),
            Err(_) => Err(nom::Err::Failure(E::from_error_kind(
                &input[1..],
                nom::error::ErrorKind::Digit,
            ))),
        }
    } else {
        Ok((rest, Name::String(raw_name)))
    }
}

impl<'a> Parse<'a> for SectionHeader<'a> {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (
            rest,
            (
                name,
                physical_address,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                pointer_to_linenumbers,
                number_of_relocations,
                number_of_linenumbers,
                characteristics,
            ),
        ) = context(
            "Section header",
            tuple((
                parse_section_name,
                le_u32,
                le_u32,
                le_u32,
                le_u32,
                le_u32,
                le_u32,
                le_u16,
                le_u16,
                SectionCharacteristics::parse,
            )),
        )(input)?;

        Ok((
            rest,
            Self {
                name,
                physical_address,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                pointer_to_relocations,
                pointer_to_linenumbers,
                number_of_relocations,
                number_of_linenumbers,
                characteristics,
            },
        ))
    }
}

impl<'a> SectionHeader<'a> {
    pub fn contains(&self, rva: u64) -> bool {
        let virtual_size = self.physical_address as u64;
        let start = self.virtual_address as u64;
        let end = start + virtual_size;

        start <= rva && rva < end
    }

    pub fn offset(&self, rva: u64) -> usize {
        assert!(self.contains(rva));
        rva as usize - self.virtual_address as usize
    }
}
