use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::tuple;

use crate::{NomError, Parse};

use std::fmt;

#[derive(Debug)]
pub struct ImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

impl fmt::Display for ImportDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = "  ".repeat(f.width().unwrap_or_default() + 1);

        write!(
            f,
            "{offset}original_first_thunk: {}\n",
            self.original_first_thunk
        )?;
        let time = chrono::DateTime::<chrono::Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp(self.time_date_stamp as i64, 0),
            chrono::Utc,
        );
        write!(f, "{offset}time_date_stamp: {}\n", time)?;
        write!(f, "{offset}forwarder_chain: {}\n", self.forwarder_chain)?;
        write!(f, "{offset}name: {}\n", self.name)?;
        write!(f, "{offset}first_thunk: {}\n", self.first_thunk)
    }
}

impl<'a> Parse<'a> for ImportDescriptor {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (original_first_thunk, time_date_stamp, forwarder_chain, name, first_thunk)) =
            context(
                "Import descriptor",
                tuple((le_u32, le_u32, le_u32, le_u32, le_u32)),
            )(input)?;

        Ok((
            rest,
            Self {
                original_first_thunk,
                time_date_stamp,
                forwarder_chain,
                name,
                first_thunk,
            },
        ))
    }
}
