use crate::enums::{
    DllCharacteristics, FileMachine, OptionalHeaderMagic, SectionCharacteristics, SubSystem,
};

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

#[derive(Debug)]
pub struct FileHeader {
    pub machine: FileMachine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct OptionalHeader32 {
    pub magic: OptionalHeaderMagic,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: SubSystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub data_directory: Vec<DataDirectory>,
}

impl OptionalHeader32 {
    pub const fn size() -> usize {
        224
    }
}

#[derive(Debug)]
pub struct OptionalHeader64 {
    pub magic: OptionalHeaderMagic,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: SubSystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub data_directory: Vec<DataDirectory>,
}

impl OptionalHeader64 {
    pub const fn size() -> usize {
        240
    }
}

#[derive(Debug)]
pub enum OptionalHeader {
    I386(OptionalHeader32),
    AMD64(OptionalHeader64),
}

impl OptionalHeader {
    pub const fn size(&self) -> usize {
        match self {
            Self::I386(_) => OptionalHeader32::size(),
            Self::AMD64(_) => OptionalHeader32::size(),
        }
    }

    pub fn size_of_image(&self) -> usize {
        match self {
            Self::I386(ref i386) => i386.size_of_image as usize,
            Self::AMD64(ref amd64) => amd64.size_of_image as usize,
        }
    }
}

#[derive(Debug)]
pub enum SectionName<'a> {
    Short(&'a str),
    Offset(usize),
}

#[derive(Debug)]
pub struct SectionHeader<'a> {
    pub name: SectionName<'a>,
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

#[derive(Debug)]
pub struct PeHeader<'a> {
    pub data: &'a [u8],
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<SectionHeader<'a>>,
}
