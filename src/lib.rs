#![feature(maybe_uninit_uninit_array, maybe_uninit_array_assume_init)]

#[macro_use]
extern crate exe;

#[allow(unused_macros)]
use libc::{c_void, size_t};

pub mod enums;
pub use enums::*;

pub mod structures;
pub use structures::*;

mod parsers;

pub trait NomError<'a>:
    nom::error::ParseError<&'a [u8]> + nom::error::ContextError<&'a [u8]>
{
}

impl<'a> NomError<'a> for nom::error::Error<&'a [u8]> {}
impl<'a> NomError<'a> for nom::error::VerboseError<&'a [u8]> {}

pub trait Parse<'a>: Sized {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>;
}

impl<'a> exe::Section for SectionHeader<'a> {
    fn get_flags(&self) -> u32 {
        let mut flags = 0u32;

        if self.characteristics.memory_read {
            flags |= 4;
        }
        if self.characteristics.memory_write {
            flags |= 2;
        }
        if self.characteristics.contains_code {
            flags |= 1;
        }
        if self.characteristics.memory_execute {
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

impl<'a> exe::Exe<'a> for Pe<'a> {
    type Item = SectionHeader<'a>;

    fn get_number_of_sections(&self) -> usize {
        self.pe_header.file_header.number_of_sections as usize
    }

    fn get_section_at(&self, idx: usize) -> Option<&Self::Item> {
        self.pe_header.sections.iter().nth(idx)
    }

    fn get_section_name_at(&self, idx: usize) -> Option<&str> {
        match self.pe_header.sections.iter().nth(idx) {
            Some(s) => match s.name {
                Name::String(name) => Some(name),
                Name::Rva(_rva) => {
                    todo!("Get long section name");
                }
            },
            None => None,
        }
    }

    fn get_data(&self, start: usize, len: usize) -> &[u8] {
        &self.data[start..][..len]
    }

    fn get_info(&self) -> exe::Info {
        exe::Info {
            os: String::from("windows"),
            arch: String::from(match &self.pe_header.file_header.machine {
                FileMachine::MachineIA64 => "ia",
                FileMachine::MachineI386 | FileMachine::MachineAMD64 => "x86",
            }),
            bits: match &self.pe_header.file_header.machine {
                FileMachine::MachineI386 => 32,
                FileMachine::MachineIA64 | FileMachine::MachineAMD64 => 64,
            },
        }
    }

    fn parse(i: &'a [u8]) -> Option<Self> {
        match Parse::parse::<nom::error::VerboseError<&'a [u8]>>(i) {
            Ok((_, pe)) => Some(pe),
            Err(_) => None,
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_pe_parse_dos<'a>(i: *const u8, len: size_t) -> *const c_void {
    let buf = unsafe { ::std::slice::from_raw_parts(i as *const u8, len) };

    match <PeHeader as Parse>::parse::<nom::error::VerboseError<&'a [u8]>>(buf) {
        Ok((_, dos)) => Box::into_raw(Box::new(dos)) as *const c_void,
        Err(e) => {
            eprintln!("{:?}", e);
            ::std::ptr::null::<c_void>()
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_pe_parse<'a>(i: *const u8, len: size_t) -> *const c_void {
    let buf = unsafe { ::std::slice::from_raw_parts(i as *const u8, len) };

    match <DosHeader as Parse>::parse::<nom::error::VerboseError<&'a [u8]>>(buf) {
        Ok((_, dos)) => {
            let off = dos.e_lfanew as usize;
            match <PeHeader as Parse>::parse::<nom::error::VerboseError<&'a [u8]>>(&buf[off..]) {
                Ok((_, pe)) => Box::into_raw(Box::new(pe)) as *const c_void,
                Err(_) => ::std::ptr::null::<c_void>(),
            }
        }
        Err(_) => ::std::ptr::null::<c_void>(),
    }
}

// generate_c_api!(
//     PeHeader<'a>,
//     rs_pe_get_info,
//     rs_pe_free_info,
//     rs_pe_get_number_of_sections,
//     rs_pe_get_section_at,
//     rs_pe_get_data,
//     rs_pe_free_section,
//     rs_pe_free_exe
// );
