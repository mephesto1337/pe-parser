use nom::error::context;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;

use crate::{NomError, Parse};

use crate::enums::{FileCharacteristics, FileMachine};

use std::fmt;

#[derive(Debug)]
pub struct FileHeader {
    pub machine: FileMachine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: FileCharacteristics,
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = "  ".repeat(f.width().unwrap_or_default() + 1);
        write!(f, "{offset}machine: {}\n", self.machine)?;
        write!(
            f,
            "{offset}number_of_sections: 0x{:x}\n",
            self.number_of_sections
        )?;
        let time = chrono::DateTime::<chrono::Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp(self.time_date_stamp as i64, 0),
            chrono::Utc,
        );
        write!(f, "{offset}time_date_stamp: {:?}\n", time)?;
        write!(
            f,
            "{offset}pointer_to_symbol_table: 0x{:x}\n",
            self.pointer_to_symbol_table
        )?;
        write!(
            f,
            "{offset}number_of_symbols: 0x{:x}\n",
            self.number_of_symbols
        )?;
        write!(
            f,
            "{offset}size_of_optional_header: 0x{:x}\n",
            self.size_of_optional_header
        )?;
        write!(f, "{offset}characteristics: {}\n", self.characteristics)
    }
}

impl<'a> Parse<'a> for FileHeader {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (
            rest,
            (
                machine,
                number_of_sections,
                time_date_stamp,
                pointer_to_symbol_table,
                number_of_symbols,
                size_of_optional_header,
                characteristics,
            ),
        ) = context(
            "File header",
            tuple((
                FileMachine::parse,
                le_u16,
                le_u32,
                le_u32,
                le_u32,
                le_u16,
                FileCharacteristics::parse,
            )),
        )(input)?;

        Ok((
            rest,
            Self {
                machine,
                number_of_sections,
                time_date_stamp,
                pointer_to_symbol_table,
                number_of_symbols,
                size_of_optional_header,
                characteristics,
            },
        ))
    }
}
