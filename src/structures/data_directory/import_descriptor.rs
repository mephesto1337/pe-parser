use nom::bytes::complete::take_while1;
use nom::combinator::{map, map_opt};
use nom::error::context;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;

use crate::structures::Name;
use crate::{NomError, Parse};

use std::fmt;

#[derive(Debug)]
pub struct ImportDescriptor<'a> {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: Name<'a>,
    pub first_thunk: u32,
}

impl<'a> fmt::Display for ImportDescriptor<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = "  ".repeat(f.width().unwrap_or_default() + 1);

        write!(
            f,
            "{offset}original_first_thunk: 0x{:x}\n",
            self.original_first_thunk
        )?;
        let time = chrono::DateTime::<chrono::Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp(self.time_date_stamp as i64, 0),
            chrono::Utc,
        );
        write!(f, "{offset}time_date_stamp: {}\n", time)?;
        write!(f, "{offset}forwarder_chain: 0x{:x}\n", self.forwarder_chain)?;
        write!(f, "{offset}name: {}\n", self.name)?;
        write!(f, "{offset}first_thunk: 0x{:x}\n", self.first_thunk)
    }
}

impl<'a> Parse<'a> for ImportDescriptor<'a> {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (original_first_thunk, time_date_stamp, forwarder_chain, name, first_thunk)) =
            context(
                "Import descriptor",
                tuple((
                    le_u32,
                    le_u32,
                    le_u32,
                    map(le_u32, |x| Name::Rva(x as u64)),
                    le_u32,
                )),
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

#[derive(Debug)]
pub struct ImportByName<'a> {
    pub hint: u16,
    pub name: &'a str,
}

impl<'a> fmt::Display for ImportByName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} Hint[{}]", self.name, self.hint)
    }
}

impl<'a> Parse<'a> for ImportByName<'a> {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (hint, name)) = context(
            "Import by name",
            tuple((
                le_u16,
                map_opt(take_while1(|b| b != 0), |b| std::str::from_utf8(b).ok()),
            )),
        )(input)?;

        Ok((rest, Self { hint, name }))
    }
}
