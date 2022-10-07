use nom::combinator::verify;
use nom::error::context;
use nom::multi::count;
use nom::number::complete::be_u32;
use nom::sequence::tuple;

use crate::{NomError, Parse};

use std::fmt;

use super::{FileHeader, OptionalHeader, SectionHeader};

pub struct PeHeader<'a> {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<SectionHeader<'a>>,
}

impl<'a> fmt::Debug for PeHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeHeader")
            .field("signature", &self.signature)
            .field("file_header", &self.file_header)
            .field("optional_header", &self.optional_header)
            .field("sections", &self.sections)
            .finish()
    }
}

impl<'a> fmt::Display for PeHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = f.width().unwrap_or_default() + 1;
        let offset = "  ".repeat(width);
        write!(f, "{offset}signature: 0x{:08x}\n", self.signature)?;
        write!(f, "{offset}file_header:\n{:width$}\n", self.file_header)?;
        write!(
            f,
            "{offset}optional_header:\n{:width$}\n",
            self.optional_header
        )?;
        write!(f, "{offset}sections:\n")?;
        for section in &self.sections {
            write!(f, "{:width$}\n", section)?;
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for PeHeader<'a> {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (signature, file_header, optional_header)) = context(
            "PE header",
            tuple((
                verify(be_u32, |magic| &magic.to_be_bytes() == b"PE\0\0"),
                FileHeader::parse,
                OptionalHeader::parse,
            )),
        )(input)?;
        if optional_header.size() != file_header.size_of_optional_header as usize {
            let e = E::from_error_kind(input, nom::error::ErrorKind::Verify);
            return Err(nom::Err::Failure(E::add_context(
                input,
                "Optional header does not match",
                e,
            )));
        }
        let (_rest, sections) = context(
            "PE header/sections",
            count(
                SectionHeader::parse,
                file_header.number_of_sections as usize,
            ),
        )(rest)?;
        eprintln!(
            "Will take {} bytes out of {}",
            optional_header.size_of_image(),
            input.len()
        );

        Ok((
            rest,
            Self {
                signature,
                file_header,
                optional_header,
                sections,
            },
        ))
    }
}
