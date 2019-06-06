use enums::*;
use nom::*;
use structures::*;

fn parse_dos_magic(i: &[u8]) -> IResult<&[u8], u16> {
    let (r, t) = tag!(i, "MZ")?;
    match le_u16(t) {
        Ok((_, m)) => Ok((r, m)),
        Err(e) => Err(e),
    }
}

named!(pub parse_dos_header<DosHeader>,
    do_parse!(
            _e_magic:    parse_dos_magic
        >>  _e_cblp:     le_u16
        >>  _e_cp:       le_u16
        >>  _e_crlc:     le_u16
        >>  _e_cparhdr:  le_u16
        >>  _e_minalloc: le_u16
        >>  _e_maxalloc: le_u16
        >>  _e_ss:       le_u16
        >>  _e_sp:       le_u16
        >>  _e_csum:     le_u16
        >>  _e_ip:       le_u16
        >>  _e_cs:       le_u16
        >>  _e_lfarlc:   le_u16
        >>  _e_ovno:     le_u16
        >>  _e_res:      count_fixed!(u16, le_u16, 4)
        >>  _e_oemid:    le_u16
        >>  _e_oeminfo:  le_u16
        >>  _e_res2:     count_fixed!(u16, le_u16, 10)
        >>  _e_lfanew:   le_u32
        >>  (DosHeader {
            e_magic:    _e_magic,
            e_cblp:     _e_cblp,
            e_cp:       _e_cp,
            e_crlc:     _e_crlc,
            e_cparhdr:  _e_cparhdr,
            e_minalloc: _e_minalloc,
            e_maxalloc: _e_maxalloc,
            e_ss:       _e_ss,
            e_sp:       _e_sp,
            e_csum:     _e_csum,
            e_ip:       _e_ip,
            e_cs:       _e_cs,
            e_lfarlc:   _e_lfarlc,
            e_ovno:     _e_ovno,
            e_res:      _e_res,
            e_oemid:    _e_oemid,
            e_oeminfo:  _e_oeminfo,
            e_res2:     _e_res2,
            e_lfanew:   _e_lfanew,
        })
    )
);

named!(pub parse_file_header<FileHeader>,
    do_parse!(
            _machine:                   parse_file_machine
        >>  _number_of_sections:        le_u16
        >>  _time_date_stamp:           le_u32
        >>  _pointer_to_symbol_table:   le_u32
        >>  _number_of_symbols:         le_u32
        >>  _size_of_optional_header:   le_u16
        >>  _characteristics:           le_u16
        >>  ( FileHeader {
                machine:                    _machine,
                number_of_sections:         _number_of_sections,
                time_date_stamp:            _time_date_stamp,
                pointer_to_symbol_table:    _pointer_to_symbol_table,
                number_of_symbols:          _number_of_symbols,
                size_of_optional_header:    _size_of_optional_header,
                characteristics:            _characteristics,

        })
    )
);

named!(pub parse_data_directory<DataDirectory>,
    do_parse!(
            _virtual_address:   le_u32
        >>  _size:              le_u32
        >>  ( DataDirectory {
            virtual_address:    _virtual_address,
            size:               _size

        })
    )
);

named!(
    parse_optional_header32<OptionalHeader32>,
    do_parse!(
        _magic: parse_optional_header_magic
            >> _major_linker_version: le_u8
            >> _minor_linker_version: le_u8
            >> _size_of_code: le_u32
            >> _size_of_initialized_data: le_u32
            >> _size_of_uninitialized_data: le_u32
            >> _address_of_entry_point: le_u32
            >> _base_of_code: le_u32
            >> _base_of_data: le_u32
            >> _image_base: le_u32
            >> _section_alignment: le_u32
            >> _file_alignment: le_u32
            >> _major_operating_system_version: le_u16
            >> _minor_operating_system_version: le_u16
            >> _major_image_version: le_u16
            >> _minor_image_version: le_u16
            >> _major_subsystem_version: le_u16
            >> _minor_subsystem_version: le_u16
            >> _win32_version_value: le_u32
            >> _size_of_image: le_u32
            >> _size_of_headers: le_u32
            >> _check_sum: le_u32
            >> _subsystem: parse_subsystem
            >> _dll_characteristics: parse_dll_characteristics
            >> _size_of_stack_reserve: le_u32
            >> _size_of_stack_commit: le_u32
            >> _size_of_heap_reserve: le_u32
            >> _size_of_heap_commit: le_u32
            >> _loader_flags: le_u32
            >> _number_of_rva_and_sizes: verify!(le_u32, |x| x == 16u32)
            >> _data_directory: count!(parse_data_directory, 16)
            >> (OptionalHeader32 {
                magic: _magic,
                major_linker_version: _major_linker_version,
                minor_linker_version: _minor_linker_version,
                size_of_code: _size_of_code,
                size_of_initialized_data: _size_of_initialized_data,
                size_of_uninitialized_data: _size_of_uninitialized_data,
                address_of_entry_point: _address_of_entry_point,
                base_of_code: _base_of_code,
                base_of_data: _base_of_data,
                image_base: _image_base,
                section_alignment: _section_alignment,
                file_alignment: _file_alignment,
                major_operating_system_version: _major_operating_system_version,
                minor_operating_system_version: _minor_operating_system_version,
                major_image_version: _major_image_version,
                minor_image_version: _minor_image_version,
                major_subsystem_version: _major_subsystem_version,
                minor_subsystem_version: _minor_subsystem_version,
                win32_version_value: _win32_version_value,
                size_of_image: _size_of_image,
                size_of_headers: _size_of_headers,
                check_sum: _check_sum,
                subsystem: _subsystem,
                dll_characteristics: _dll_characteristics,
                size_of_stack_reserve: _size_of_stack_reserve,
                size_of_stack_commit: _size_of_stack_commit,
                size_of_heap_reserve: _size_of_heap_reserve,
                size_of_heap_commit: _size_of_heap_commit,
                loader_flags: _loader_flags,
                number_of_rva_and_sizes: _number_of_rva_and_sizes,
                data_directory: _data_directory,
            })
    )
);

named!(
    parse_optional_header64<OptionalHeader64>,
    do_parse!(
        _magic: parse_optional_header_magic
            >> _major_linker_version: le_u8
            >> _minor_linker_version: le_u8
            >> _size_of_code: le_u32
            >> _size_of_initialized_data: le_u32
            >> _size_of_uninitialized_data: le_u32
            >> _address_of_entry_point: le_u32
            >> _base_of_code: le_u32
            >> _image_base: le_u64
            >> _section_alignment: le_u32
            >> _file_alignment: le_u32
            >> _major_operating_system_version: le_u16
            >> _minor_operating_system_version: le_u16
            >> _major_image_version: le_u16
            >> _minor_image_version: le_u16
            >> _major_subsystem_version: le_u16
            >> _minor_subsystem_version: le_u16
            >> _win32_version_value: le_u32
            >> _size_of_image: le_u32
            >> _size_of_headers: le_u32
            >> _check_sum: le_u32
            >> _subsystem: parse_subsystem
            >> _dll_characteristics: parse_dll_characteristics
            >> _size_of_stack_reserve: le_u64
            >> _size_of_stack_commit: le_u64
            >> _size_of_heap_reserve: le_u64
            >> _size_of_heap_commit: le_u64
            >> _loader_flags: le_u32
            >> _number_of_rva_and_sizes: verify!(le_u32, |x| x == 16u32)
            >> _data_directory: count!(parse_data_directory, 16)
            >> (OptionalHeader64 {
                magic: _magic,
                major_linker_version: _major_linker_version,
                minor_linker_version: _minor_linker_version,
                size_of_code: _size_of_code,
                size_of_initialized_data: _size_of_initialized_data,
                size_of_uninitialized_data: _size_of_uninitialized_data,
                address_of_entry_point: _address_of_entry_point,
                base_of_code: _base_of_code,
                image_base: _image_base,
                section_alignment: _section_alignment,
                file_alignment: _file_alignment,
                major_operating_system_version: _major_operating_system_version,
                minor_operating_system_version: _minor_operating_system_version,
                major_image_version: _major_image_version,
                minor_image_version: _minor_image_version,
                major_subsystem_version: _major_subsystem_version,
                minor_subsystem_version: _minor_subsystem_version,
                win32_version_value: _win32_version_value,
                size_of_image: _size_of_image,
                size_of_headers: _size_of_headers,
                check_sum: _check_sum,
                subsystem: _subsystem,
                dll_characteristics: _dll_characteristics,
                size_of_stack_reserve: _size_of_stack_reserve,
                size_of_stack_commit: _size_of_stack_commit,
                size_of_heap_reserve: _size_of_heap_reserve,
                size_of_heap_commit: _size_of_heap_commit,
                loader_flags: _loader_flags,
                number_of_rva_and_sizes: _number_of_rva_and_sizes,
                data_directory: _data_directory,
            })
    )
);

pub fn parse_optional_header(i: &[u8]) -> IResult<&[u8], OptionalHeader> {
    let (_, m) = parse_optional_header_magic(i)?;

    match m {
        OptionalHeaderMagic::Header64 => {
            let (rest, oh) = parse_optional_header64(i)?;
            Ok((rest, OptionalHeader::AMD64(oh)))
        }
        _ => {
            let (rest, oh) = parse_optional_header32(i)?;
            Ok((rest, OptionalHeader::I386(oh)))
        }
    }
}

named!(pub parse_section_header<SectionHeader>,
    do_parse!(
            _name:                      take_str!(8)
        >>  _physical_address:          le_u32
        >>  _virtual_address:           le_u32
        >>  _size_of_raw_data:          le_u32
        >>  _pointer_to_raw_data:       le_u32
        >>  _pointer_to_relocations:    le_u32
        >>  _pointer_to_linenumbers:    le_u32
        >>  _number_of_relocations:     le_u16
        >>  _number_of_linenumbers:     le_u16
        >>  _characteristics:           le_u32
        >>  ( SectionHeader {
            name:                      _name,
            physical_address:          _physical_address,
            virtual_address:           _virtual_address,
            size_of_raw_data:          _size_of_raw_data,
            pointer_to_raw_data:       _pointer_to_raw_data,
            pointer_to_relocations:    _pointer_to_relocations,
            pointer_to_linenumbers:    _pointer_to_linenumbers,
            number_of_relocations:     _number_of_relocations,
            number_of_linenumbers:     _number_of_linenumbers,
            characteristics:           _characteristics,
        })
    )
);

fn parse_pe_magic(i: &[u8]) -> IResult<&[u8], u32> {
    let (r, t) = tag!(i, "PE\0\0")?;
    match le_u32(t) {
        Ok((_, m)) => Ok((r, m)),
        Err(e) => Err(e),
    }
}

pub fn parse_pe_header<'a>(i: &'a [u8]) -> IResult<&'a [u8], PeHeader<'a>> {
    do_parse!(
        i,
        _signature: parse_pe_magic
            >> _file_header: parse_file_header
            >> _optional_header: parse_optional_header
            >> _sections:
                count!(
                    parse_section_header,
                    _file_header.number_of_sections as usize
                )
            >> (PeHeader {
                data: i,
                signature: _signature,
                file_header: _file_header,
                optional_header: _optional_header,
                sections: _sections
            })
    )
}
