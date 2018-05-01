use enum_primitive::FromPrimitive;
use nom;

macro_rules! parse_u8_enum {
    ($funcname:ident, $enum:ident) => (
        pub fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match le_u8(i) {
                Ok((rest, x)) => {
                    match $enum::from_u8(x) {
                        Some(y) => Ok((rest, y)),
                        None    => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf)))
                    }
                },
                Err(e) => Err(e)
            }
        }
    )
}

macro_rules! parse_u16_enum {
    ($funcname:ident, $enum:ident) => (
        pub fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match nom::le_u16(i) {
                Ok((rest, x)) => {
                    match $enum::from_u16(x) {
                        Some(y) => Ok((rest, y)),
                        None    => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf)))
                    }
                },
                Err(e) => Err(e)
            }
        }
    )
}

macro_rules! parse_u32_enum {
    ($funcname:ident, $enum:ident) => (
        pub fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match nom::le_u32(i) {
                Ok((rest, x)) => {
                    match $enum::from_u32(x) {
                        Some(y) => Ok((rest, y)),
                        None    => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf)))
                    }
                },
                Err(e) => Err(e)
            }
        }
    )
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum FileMachine {
    MachineI386     = 0x014c,
    MachineIA64     = 0x0200,
    MachineAMD64    = 0x8664
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum OptionalHeaderMagic {
    Header32    = 0x10b,
    Header64    = 0x20b,
    HeaderRom   = 0x107
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum SubSystem {
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    OS2Cui = 5,
    PosixCui = 7,
    WindowsCeGui = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum DllCharacteristic {
    Reserved1 = 0x0001,
    Reserved2 = 0x0002,
    Reserved3 = 0x0004,
    Reserved4 = 0x0008,
    DynamicBase = 0x0040,
    ForceIntegrity = 0x0080,
    NxCompat = 0x0100,
    NoIsolation = 0x0200,
    NoSeh = 0x0400,
    NoBind = 0x0800,
    Reserved5 = 0x1000,
    WdmDriver = 0x2000,
    Reserved6 = 0x4000,
    TerminalServerAware = 0x8000,
}
}

parse_u16_enum!(parse_file_machine, FileMachine);
parse_u16_enum!(parse_subsystem, SubSystem);
parse_u16_enum!(parse_optional_header_magic, OptionalHeaderMagic);

pub fn parse_dll_characteristics(i: &[u8]) -> nom::IResult<&[u8], Vec<DllCharacteristic>> {
    let (r, c) = nom::le_u16(i)?;
    let flags = (0..16)
        .map(|x| 1u16 << (x as usize))
        .filter(|x| c & *x == *x)
        .map(|x| DllCharacteristic::from_u16(x))
        .filter(|x| x.is_some())
        .map(|x| x.unwrap())
        .collect();
    Ok((r, flags))
}
