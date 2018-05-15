#![recursion_limit="128"]

#[macro_use] extern crate nom;
#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate exe;
extern crate libc;

#[allow(dead_code)]
#[allow(unused_macros)]

use libc::{size_t, uint8_t, c_void};

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

    fn get_section_name_at(&self, idx: usize) -> Option<&str> {
        match self.sections.iter().nth(idx) {
            Some(s) => Some(s.name),
            None => None
        }
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

#[no_mangle]
pub extern fn rs_pe_parse_dos<'a>(i: *const uint8_t, len: size_t) -> *const c_void {
    let buf = unsafe { ::std::slice::from_raw_parts(i as *const u8, len) };

    match parse_dos_header(buf) {
        Ok((_, dos)) => Box::into_raw(Box::new(dos)) as *const c_void,
        Err(e) => {
            eprintln!("{:?}", e.into_error_kind());
            ::std::ptr::null::<c_void>()   
        }
    }
}

#[no_mangle]
pub extern fn rs_pe_parse<'a>(i: *const uint8_t, len: size_t) -> *const c_void {
    let buf = unsafe { ::std::slice::from_raw_parts(i as *const u8, len) };

    match parse_dos_header(buf) {
        Ok((_, dos)) => {
            let off = dos.e_lfanew as usize;
            match parse_pe_header(&buf[off..]) {
                Ok((_, pe)) => Box::into_raw(Box::new(pe)) as *const c_void,
                Err(e) => {
                    eprintln!("{:?}", e.into_error_kind());
                    ::std::ptr::null::<c_void>()
                }
            }
        },
        Err(e) => {
            eprintln!("{:?}", e.into_error_kind());
            ::std::ptr::null::<c_void>()   
        }
    }
}

generate_c_api!(SectionHeader<'a>, PeHeader<'a>,
    rs_pe_get_flags,
    rs_pe_get_offset,
    rs_pe_get_size,
    rs_pe_get_number_of_sections,
    rs_pe_get_section_at,
    rs_pe_get_section_name_at,
    rs_pe_get_data,
    rs_pe_free_exe
);
