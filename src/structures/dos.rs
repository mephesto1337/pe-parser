use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::{be_u16, le_u16, le_u32};
use nom::sequence::tuple;

use crate::parsers::count_fixed;
use crate::{NomError, Parse};

use std::fmt;

#[derive(Debug)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

impl fmt::Display for DosHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = "  ".repeat(f.width().unwrap_or_default() + 1);
        write!(f, "{offset}magic: 0x{:04x}\n", self.e_magic)?;
        write!(f, "{offset}lfanew: 0x{:x}\n", self.e_lfanew)
    }
}

impl<'a> Parse<'a> for DosHeader {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (
            rest,
            (
                e_magic,
                e_cblp,
                e_cp,
                e_crlc,
                e_cparhdr,
                e_minalloc,
                e_maxalloc,
                e_ss,
                e_sp,
                e_csum,
                e_ip,
                e_cs,
                e_lfarlc,
                e_ovno,
                e_res,
                e_oemid,
                e_oeminfo,
                e_res2,
                e_lfanew,
            ),
        ) = context(
            "Image DOS header",
            tuple((
                verify(be_u16, |magic: &u16| &magic.to_be_bytes() == b"MZ"),
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                le_u16,
                count_fixed(le_u16),
                le_u16,
                le_u16,
                count_fixed(le_u16),
                le_u32,
            )),
        )(input)?;

        Ok((
            rest,
            Self {
                e_magic,
                e_cblp,
                e_cp,
                e_crlc,
                e_cparhdr,
                e_minalloc,
                e_maxalloc,
                e_ss,
                e_sp,
                e_csum,
                e_ip,
                e_cs,
                e_lfarlc,
                e_ovno,
                e_res,
                e_oemid,
                e_oeminfo,
                e_res2,
                e_lfanew,
            },
        ))
    }
}
