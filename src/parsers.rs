use nom::branch::alt;
use nom::bytes::complete::{take, take_until1};
use nom::combinator::{map, map_opt, map_parser, verify};
use nom::error::{context, ParseError};
use nom::multi::{count, length_count};
use nom::number::complete::{be_u16, be_u32, le_u16, le_u32, le_u64, le_u8};
use nom::sequence::tuple;

use crate::enums::{
    DllCharacteristics, FileCharacteristics, FileMachine, OptionalHeaderMagic,
    SectionCharacteristics, SubSystem,
};
use crate::structures::{
    DataDirectory, DosHeader, FileHeader, OptionalHeader, OptionalHeader32, OptionalHeader64,
    PeHeader, SectionHeader, SectionName,
};
use crate::{NomError, Parse};

fn count_fixed<I, O, E, F, const N: usize>(mut f: F) -> impl FnMut(I) -> nom::IResult<I, [O; N], E>
where
    I: Clone + PartialEq,
    F: nom::Parser<I, O, E>,
    E: ParseError<I>,
{
    move |i: I| {
        use std::mem::MaybeUninit;
        let mut input = i;
        let mut array: [MaybeUninit<O>; N] = MaybeUninit::uninit_array();

        for elt in array.iter_mut() {
            let input_ = input.clone();
            let (rest, o) = f.parse(input_)?;
            elt.write(o);
            input = rest;
        }

        Ok((input, unsafe { MaybeUninit::array_assume_init(array) }))
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

impl<'a> Parse<'a> for OptionalHeader32 {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (
            rest,
            (
                (
                    magic,
                    major_linker_version,
                    minor_linker_version,
                    size_of_code,
                    size_of_initialized_data,
                    size_of_uninitialized_data,
                    address_of_entry_point,
                    base_of_code,
                    base_of_data,
                    image_base,
                    section_alignment,
                    file_alignment,
                    major_operating_system_version,
                    minor_operating_system_version,
                ),
                (
                    major_image_version,
                    minor_image_version,
                    major_subsystem_version,
                    minor_subsystem_version,
                    win32_version_value,
                    size_of_image,
                    size_of_headers,
                    check_sum,
                    subsystem,
                    dll_characteristics,
                    size_of_stack_reserve,
                    size_of_stack_commit,
                    size_of_heap_reserve,
                    size_of_heap_commit,
                    loader_flags,
                    data_directory,
                ),
            ),
        ) = context(
            "Optional header 32",
            tuple((
                tuple((
                    verify(OptionalHeaderMagic::parse, |magic| {
                        magic == &OptionalHeaderMagic::Header32
                    }),
                    le_u8,
                    le_u8,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u16,
                    le_u16,
                )),
                tuple((
                    le_u16,
                    le_u16,
                    le_u16,
                    le_u16,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    SubSystem::parse,
                    DllCharacteristics::parse,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    length_count(
                        verify(le_u32, |count: &u32| count <= &16),
                        DataDirectory::parse,
                    ),
                )),
            )),
        )(input)?;

        if size_of_image % file_alignment != 0 {
            return Err(nom::Err::Failure(E::add_context(
                input,
                "Optional header 32",
                E::add_context(
                    input,
                    "`size_of_image` is not aligned with `file_alignment`",
                    E::from_error_kind(input, nom::error::ErrorKind::Verify),
                ),
            )));
        }

        Ok((
            rest,
            Self {
                magic,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                address_of_entry_point,
                base_of_code,
                base_of_data,
                image_base,
                section_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_subsystem_version,
                minor_subsystem_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                check_sum,
                subsystem,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                data_directory,
            },
        ))
    }
}

impl<'a> Parse<'a> for OptionalHeader64 {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (
            rest,
            (
                (
                    magic,
                    major_linker_version,
                    minor_linker_version,
                    size_of_code,
                    size_of_initialized_data,
                    size_of_uninitialized_data,
                    address_of_entry_point,
                    base_of_code,
                    image_base,
                    section_alignment,
                    file_alignment,
                    major_operating_system_version,
                    minor_operating_system_version,
                    major_image_version,
                ),
                (
                    minor_image_version,
                    major_subsystem_version,
                    minor_subsystem_version,
                    win32_version_value,
                    size_of_image,
                    size_of_headers,
                    check_sum,
                    subsystem,
                    dll_characteristics,
                    size_of_stack_reserve,
                    size_of_stack_commit,
                    size_of_heap_reserve,
                    size_of_heap_commit,
                    loader_flags,
                    data_directory,
                ),
            ),
        ) = context(
            "Optional header 64",
            tuple((
                tuple((
                    verify(OptionalHeaderMagic::parse, |magic| {
                        magic == &OptionalHeaderMagic::Header64
                    }),
                    le_u8,
                    le_u8,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u64,
                    le_u32,
                    le_u32,
                    le_u16,
                    le_u16,
                    le_u16,
                )),
                tuple((
                    le_u16,
                    le_u16,
                    le_u16,
                    le_u32,
                    le_u32,
                    le_u32,
                    le_u32,
                    SubSystem::parse,
                    DllCharacteristics::parse,
                    le_u64,
                    le_u64,
                    le_u64,
                    le_u64,
                    le_u32,
                    length_count(
                        verify(le_u32, |count: &u32| count <= &16),
                        DataDirectory::parse,
                    ),
                )),
            )),
        )(input)?;

        if size_of_image % file_alignment != 0 {
            return Err(nom::Err::Failure(E::add_context(
                input,
                "Optional header 32",
                E::add_context(
                    input,
                    "`size_of_image` is not aligned with `file_alignment`",
                    E::from_error_kind(input, nom::error::ErrorKind::Verify),
                ),
            )));
        }
        Ok((
            rest,
            Self {
                magic,
                major_linker_version,
                minor_linker_version,
                size_of_code,
                size_of_initialized_data,
                size_of_uninitialized_data,
                address_of_entry_point,
                base_of_code,
                image_base,
                section_alignment,
                file_alignment,
                major_operating_system_version,
                minor_operating_system_version,
                major_image_version,
                minor_image_version,
                major_subsystem_version,
                minor_subsystem_version,
                win32_version_value,
                size_of_image,
                size_of_headers,
                check_sum,
                subsystem,
                dll_characteristics,
                size_of_stack_reserve,
                size_of_stack_commit,
                size_of_heap_reserve,
                size_of_heap_commit,
                loader_flags,
                data_directory,
            },
        ))
    }
}

impl<'a> Parse<'a> for OptionalHeader {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context(
            "Optional header",
            alt((
                map(OptionalHeader32::parse, |oh| Self::I386(oh)),
                map(OptionalHeader64::parse, |oh| Self::AMD64(oh)),
            )),
        )(input)
    }
}

impl<'a> Parse<'a> for SectionName<'a> {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
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
            match usize::from_str_radix(&raw_name[1..], 10) {
                Ok(offset) => Ok((rest, Self::Offset(offset))),
                Err(_) => Err(nom::Err::Failure(E::from_error_kind(
                    &input[1..],
                    nom::error::ErrorKind::Digit,
                ))),
            }
        } else {
            Ok((rest, Self::Short(raw_name)))
        }
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
                SectionName::parse,
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
        let (rest, data) = take(input.len().min(optional_header.size_of_image()))(input)?;

        Ok((
            rest,
            Self {
                data,
                signature,
                file_header,
                optional_header,
                sections,
            },
        ))
    }
}
