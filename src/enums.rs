use enum_primitive::FromPrimitive;
use nom;

#[allow(unused_macros)]
macro_rules! parse_u8_enum {
    ($funcname:ident, $enum:ident) => {
        pub fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match le_u8(i) {
                Ok((rest, x)) => match $enum::from_u8(x) {
                    Some(y) => Ok((rest, y)),
                    None => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf))),
                },
                Err(e) => Err(e),
            }
        }
    };
}

#[allow(unused_macros)]
macro_rules! parse_u16_enum {
    ($funcname:ident, $enum:ident) => {
        pub fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match nom::le_u16(i) {
                Ok((rest, x)) => match $enum::from_u16(x) {
                    Some(y) => Ok((rest, y)),
                    None => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf))),
                },
                Err(e) => Err(e),
            }
        }
    };
}

#[allow(unused_macros)]
macro_rules! parse_u32_enum {
    ($funcname:ident, $enum:ident) => {
        pub fn $funcname(i: &[u8]) -> nom::IResult<&[u8], $enum> {
            match nom::le_u32(i) {
                Ok((rest, x)) => match $enum::from_u32(x) {
                    Some(y) => Ok((rest, y)),
                    None => Err(nom::Err::Error(error_position!(i, nom::ErrorKind::NoneOf))),
                },
                Err(e) => Err(e),
            }
        }
    };
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

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u32)]
pub enum SectionCharacteristic {
    Reserved1 = 0x0000_0001,
    Reserved2 = 0x0000_0002,
    Reserved3 = 0x0000_0004,
    TypeNoPad = 0x0000_0008,
    Reserved4 = 0x0000_0010,
    ContainsCode = 0x0000_0020,
    ContainsInitializedData = 0x0000_0040,
    ContainsUninitializedData = 0x0000_0080,
    LinkOther = 0x0000_0100,
    LinkInfo = 0x0000_0200,
    Reserved5 = 0x0000_0400,
    LinkRemoved = 0x0000_0800,
    LinkComdat = 0x0000_1000,
    Reserved6 = 0x0000_2000,
    NoDeferSpeculativeExceptions = 0x0000_4000,
    GlobalPointerReferences = 0x0000_8000,
    Reserved7 = 0x0001_0000,
    MemoryPurgeable = 0x0002_0000,
    MemoryLocked = 0x0004_0000,
    MemoryPreload = 0x0008_0000,
    Align1Bytes = 0x0010_0000,
    Align2Bytes = 0x0020_0000,
    Align4Bytes = 0x0030_0000,
    Align8Bytes = 0x0040_0000,
    Align16Bytes = 0x0050_0000,
    Align32Bytes = 0x0060_0000,
    Align64Bytes = 0x0070_0000,
    Align128Bytes = 0x0080_0000,
    Align256Bytes = 0x0090_0000,
    Align512Bytes = 0x00A0_0000,
    Align1024Bytes = 0x00B0_0000,
    Align2048Bytes = 0x00C0_0000,
    Align4096Bytes = 0x00D0_0000,
    Align8192Bytes = 0x00E0_0000,
    LinkNRelecOverflow = 0x0100_0000,
    MemoryDiscardable = 0x0200_0000,
    MemoryNotCached = 0x0400_0000,
    MemoryNotPaged = 0x0800_0000,
    MemoryShared = 0x1000_0000,
    MemoryExecute = 0x2000_0000,
    MemoryRead = 0x4000_0000,
    MemoryWrite = 0x8000_0000,
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
