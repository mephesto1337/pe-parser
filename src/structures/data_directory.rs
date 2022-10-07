use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::tuple;

use crate::{NomError, Parse};

use std::fmt;

mod import_descriptor;
pub use import_descriptor::{ImportByName, ImportDescriptor};

#[derive(Debug)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl fmt::Display for DataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = "  ".repeat(f.width().unwrap_or_default() + 1);
        write!(f, "{offset}virtual_address: 0x{:x}\n", self.virtual_address)?;
        write!(f, "{offset}size: 0x{:x}\n", self.size)
    }
}

impl<'a> Parse<'a> for DataDirectory {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (virtual_address, size)) =
            context("Data directory", tuple((le_u32, le_u32)))(input)?;
        Ok((
            rest,
            Self {
                virtual_address,
                size,
            },
        ))
    }
}
