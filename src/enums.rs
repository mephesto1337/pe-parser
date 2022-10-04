use std::fmt;

use crate::{NomError, Parse};

use enum_primitive_derive::Primitive;
use nom::{
    combinator::map_opt,
    error::context,
    number::complete::{be_u16, be_u32, le_u16},
};
use num_traits::FromPrimitive;

#[derive(Debug, PartialEq, Primitive)]
#[repr(u16)]
pub enum FileMachine {
    MachineI386 = 0x014c,
    MachineIA64 = 0x0200,
    MachineAMD64 = 0x8664,
}

#[derive(Debug, PartialEq, Primitive)]
#[repr(u16)]
pub enum OptionalHeaderMagic {
    Header32 = 0x10b,
    Header64 = 0x20b,
    HeaderRom = 0x107,
}

#[derive(Debug, PartialEq, Primitive)]
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

#[repr(u16)]
enum DllCharacteristicsRaw {
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

pub struct DllCharacteristics {
    pub reserved1: bool,
    pub reserved2: bool,
    pub reserved3: bool,
    pub reserved4: bool,
    pub dynamic_base: bool,
    pub force_integrity: bool,
    pub nx_compat: bool,
    pub no_isolation: bool,
    pub no_seh: bool,
    pub no_bind: bool,
    pub reserved5: bool,
    pub wdm_driver: bool,
    pub reserved6: bool,
    pub terminal_server_aware: bool,
}

impl fmt::Debug for DllCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg_struct = f.debug_struct("DllCharacteristics");

        if self.reserved1 {
            dbg_struct.field("reserved1", &self.reserved1);
        }
        if self.reserved2 {
            dbg_struct.field("reserved2", &self.reserved2);
        }
        if self.reserved3 {
            dbg_struct.field("reserved3", &self.reserved3);
        }
        if self.reserved4 {
            dbg_struct.field("reserved4", &self.reserved4);
        }
        if self.dynamic_base {
            dbg_struct.field("dynamic_base", &self.dynamic_base);
        }
        if self.force_integrity {
            dbg_struct.field("force_integrity", &self.force_integrity);
        }
        if self.nx_compat {
            dbg_struct.field("nx_compat", &self.nx_compat);
        }
        if self.no_isolation {
            dbg_struct.field("no_isolation", &self.no_isolation);
        }
        if self.no_seh {
            dbg_struct.field("no_seh", &self.no_seh);
        }
        if self.no_bind {
            dbg_struct.field("no_bind", &self.no_bind);
        }
        if self.reserved5 {
            dbg_struct.field("reserved5", &self.reserved5);
        }
        if self.wdm_driver {
            dbg_struct.field("wdm_driver", &self.wdm_driver);
        }
        if self.reserved6 {
            dbg_struct.field("reserved6", &self.reserved6);
        }
        if self.terminal_server_aware {
            dbg_struct.field("terminal_server_aware", &self.terminal_server_aware);
        }
        dbg_struct.finish_non_exhaustive()
    }
}

impl<'a> Parse<'a> for DllCharacteristics {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, flags) = context("Dll characteristics", be_u16)(input)?;
        let reserved1 = flags & DllCharacteristicsRaw::Reserved1 as u16 != 0;
        let reserved2 = flags & DllCharacteristicsRaw::Reserved2 as u16 != 0;
        let reserved3 = flags & DllCharacteristicsRaw::Reserved3 as u16 != 0;
        let reserved4 = flags & DllCharacteristicsRaw::Reserved4 as u16 != 0;
        let dynamic_base = flags & DllCharacteristicsRaw::DynamicBase as u16 != 0;
        let force_integrity = flags & DllCharacteristicsRaw::ForceIntegrity as u16 != 0;
        let nx_compat = flags & DllCharacteristicsRaw::NxCompat as u16 != 0;
        let no_isolation = flags & DllCharacteristicsRaw::NoIsolation as u16 != 0;
        let no_seh = flags & DllCharacteristicsRaw::NoSeh as u16 != 0;
        let no_bind = flags & DllCharacteristicsRaw::NoBind as u16 != 0;
        let reserved5 = flags & DllCharacteristicsRaw::Reserved5 as u16 != 0;
        let wdm_driver = flags & DllCharacteristicsRaw::WdmDriver as u16 != 0;
        let reserved6 = flags & DllCharacteristicsRaw::Reserved6 as u16 != 0;
        let terminal_server_aware = flags & DllCharacteristicsRaw::TerminalServerAware as u16 != 0;
        Ok((
            rest,
            Self {
                reserved1,
                reserved2,
                reserved3,
                reserved4,
                dynamic_base,
                force_integrity,
                nx_compat,
                no_isolation,
                no_seh,
                no_bind,
                reserved5,
                wdm_driver,
                reserved6,
                terminal_server_aware,
            },
        ))
    }
}

#[repr(u32)]
pub enum SectionCharacteristicsRaw {
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

pub struct SectionCharacteristics {
    pub reserved_1: bool,
    pub reserved_2: bool,
    pub reserved_3: bool,
    pub type_no_pad: bool,
    pub reserved_4: bool,
    pub contains_code: bool,
    pub contains_initialized_data: bool,
    pub contains_uninitialized_data: bool,
    pub link_other: bool,
    pub link_info: bool,
    pub reserved_5: bool,
    pub link_removed: bool,
    pub link_comdat: bool,
    pub reserved_6: bool,
    pub no_defer_speculative_exceptions: bool,
    pub global_pointer_references: bool,
    pub reserved_7: bool,
    pub memory_purgeable: bool,
    pub memory_locked: bool,
    pub memory_preload: bool,
    pub align_1_bytes: bool,
    pub align_2_bytes: bool,
    pub align_4_bytes: bool,
    pub align_8_bytes: bool,
    pub align_16_bytes: bool,
    pub align_32_bytes: bool,
    pub align_64_bytes: bool,
    pub align_128_bytes: bool,
    pub align_256_bytes: bool,
    pub align_512_bytes: bool,
    pub align_1024_bytes: bool,
    pub align_2048_bytes: bool,
    pub align_4096_bytes: bool,
    pub align_8192_bytes: bool,
    pub link_n_relec_overflow: bool,
    pub memory_discardable: bool,
    pub memory_not_cached: bool,
    pub memory_not_paged: bool,
    pub memory_shared: bool,
    pub memory_execute: bool,
    pub memory_read: bool,
    pub memory_write: bool,
}

impl fmt::Debug for SectionCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg_struct = f.debug_struct("SectionCharacteristics");

        if self.reserved_1 {
            dbg_struct.field("reserved_1", &self.reserved_1);
        }
        if self.reserved_2 {
            dbg_struct.field("reserved_2", &self.reserved_2);
        }
        if self.reserved_3 {
            dbg_struct.field("reserved_3", &self.reserved_3);
        }
        if self.type_no_pad {
            dbg_struct.field("type_no_pad", &self.type_no_pad);
        }
        if self.reserved_4 {
            dbg_struct.field("reserved_4", &self.reserved_4);
        }
        if self.contains_code {
            dbg_struct.field("contains_code", &self.contains_code);
        }
        if self.contains_initialized_data {
            dbg_struct.field("contains_initialized_data", &self.contains_initialized_data);
        }
        if self.contains_uninitialized_data {
            dbg_struct.field(
                "contains_uninitialized_data",
                &self.contains_uninitialized_data,
            );
        }
        if self.link_other {
            dbg_struct.field("link_other", &self.link_other);
        }
        if self.link_info {
            dbg_struct.field("link_info", &self.link_info);
        }
        if self.reserved_5 {
            dbg_struct.field("reserved_5", &self.reserved_5);
        }
        if self.link_removed {
            dbg_struct.field("link_removed", &self.link_removed);
        }
        if self.link_comdat {
            dbg_struct.field("link_comdat", &self.link_comdat);
        }
        if self.reserved_6 {
            dbg_struct.field("reserved_6", &self.reserved_6);
        }
        if self.no_defer_speculative_exceptions {
            dbg_struct.field(
                "no_defer_speculative_exceptions",
                &self.no_defer_speculative_exceptions,
            );
        }
        if self.global_pointer_references {
            dbg_struct.field("global_pointer_references", &self.global_pointer_references);
        }
        if self.reserved_7 {
            dbg_struct.field("reserved_7", &self.reserved_7);
        }
        if self.memory_purgeable {
            dbg_struct.field("memory_purgeable", &self.memory_purgeable);
        }
        if self.memory_locked {
            dbg_struct.field("memory_locked", &self.memory_locked);
        }
        if self.memory_preload {
            dbg_struct.field("memory_preload", &self.memory_preload);
        }
        if self.align_1_bytes {
            dbg_struct.field("align_1_bytes", &self.align_1_bytes);
        }
        if self.align_2_bytes {
            dbg_struct.field("align_2_bytes", &self.align_2_bytes);
        }
        if self.align_4_bytes {
            dbg_struct.field("align_4_bytes", &self.align_4_bytes);
        }
        if self.align_8_bytes {
            dbg_struct.field("align_8_bytes", &self.align_8_bytes);
        }
        if self.align_16_bytes {
            dbg_struct.field("align_16_bytes", &self.align_16_bytes);
        }
        if self.align_32_bytes {
            dbg_struct.field("align_32_bytes", &self.align_32_bytes);
        }
        if self.align_64_bytes {
            dbg_struct.field("align_64_bytes", &self.align_64_bytes);
        }
        if self.align_128_bytes {
            dbg_struct.field("align_128_bytes", &self.align_128_bytes);
        }
        if self.align_256_bytes {
            dbg_struct.field("align_256_bytes", &self.align_256_bytes);
        }
        if self.align_512_bytes {
            dbg_struct.field("align_512_bytes", &self.align_512_bytes);
        }
        if self.align_1024_bytes {
            dbg_struct.field("align_1024_bytes", &self.align_1024_bytes);
        }
        if self.align_2048_bytes {
            dbg_struct.field("align_2048_bytes", &self.align_2048_bytes);
        }
        if self.align_4096_bytes {
            dbg_struct.field("align_4096_bytes", &self.align_4096_bytes);
        }
        if self.align_8192_bytes {
            dbg_struct.field("align_8192_bytes", &self.align_8192_bytes);
        }
        if self.link_n_relec_overflow {
            dbg_struct.field("link_n_relec_overflow", &self.link_n_relec_overflow);
        }
        if self.memory_discardable {
            dbg_struct.field("memory_discardable", &self.memory_discardable);
        }
        if self.memory_not_cached {
            dbg_struct.field("memory_not_cached", &self.memory_not_cached);
        }
        if self.memory_not_paged {
            dbg_struct.field("memory_not_paged", &self.memory_not_paged);
        }
        if self.memory_shared {
            dbg_struct.field("memory_shared", &self.memory_shared);
        }
        if self.memory_execute {
            dbg_struct.field("memory_execute", &self.memory_execute);
        }
        if self.memory_read {
            dbg_struct.field("memory_read", &self.memory_read);
        }
        if self.memory_write {
            dbg_struct.field("memory_write", &self.memory_write);
        }

        dbg_struct.finish_non_exhaustive()
    }
}

impl<'a> Parse<'a> for FileMachine {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context("File machine", map_opt(le_u16, Self::from_u16))(input)
    }
}

impl<'a> Parse<'a> for SubSystem {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context("SubSystem", map_opt(le_u16, Self::from_u16))(input)
    }
}

impl<'a> Parse<'a> for OptionalHeaderMagic {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context("Optional header magic", map_opt(le_u16, Self::from_u16))(input)
    }
}

impl<'a> Parse<'a> for SectionCharacteristics {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, flags) = context("Section characteristics", be_u32)(input)?;
        let reserved_1 = flags & SectionCharacteristicsRaw::Reserved1 as u32 != 0;
        let reserved_2 = flags & SectionCharacteristicsRaw::Reserved2 as u32 != 0;
        let reserved_3 = flags & SectionCharacteristicsRaw::Reserved3 as u32 != 0;
        let type_no_pad = flags & SectionCharacteristicsRaw::TypeNoPad as u32 != 0;
        let reserved_4 = flags & SectionCharacteristicsRaw::Reserved4 as u32 != 0;
        let contains_code = flags & SectionCharacteristicsRaw::ContainsCode as u32 != 0;
        let contains_initialized_data =
            flags & SectionCharacteristicsRaw::ContainsInitializedData as u32 != 0;
        let contains_uninitialized_data =
            flags & SectionCharacteristicsRaw::ContainsUninitializedData as u32 != 0;
        let link_other = flags & SectionCharacteristicsRaw::LinkOther as u32 != 0;
        let link_info = flags & SectionCharacteristicsRaw::LinkInfo as u32 != 0;
        let reserved_5 = flags & SectionCharacteristicsRaw::Reserved5 as u32 != 0;
        let link_removed = flags & SectionCharacteristicsRaw::LinkRemoved as u32 != 0;
        let link_comdat = flags & SectionCharacteristicsRaw::LinkComdat as u32 != 0;
        let reserved_6 = flags & SectionCharacteristicsRaw::Reserved6 as u32 != 0;
        let no_defer_speculative_exceptions =
            flags & SectionCharacteristicsRaw::NoDeferSpeculativeExceptions as u32 != 0;
        let global_pointer_references =
            flags & SectionCharacteristicsRaw::GlobalPointerReferences as u32 != 0;
        let reserved_7 = flags & SectionCharacteristicsRaw::Reserved7 as u32 != 0;
        let memory_purgeable = flags & SectionCharacteristicsRaw::MemoryPurgeable as u32 != 0;
        let memory_locked = flags & SectionCharacteristicsRaw::MemoryLocked as u32 != 0;
        let memory_preload = flags & SectionCharacteristicsRaw::MemoryPreload as u32 != 0;
        let align_1_bytes = flags & SectionCharacteristicsRaw::Align1Bytes as u32 != 0;
        let align_2_bytes = flags & SectionCharacteristicsRaw::Align2Bytes as u32 != 0;
        let align_4_bytes = flags & SectionCharacteristicsRaw::Align4Bytes as u32 != 0;
        let align_8_bytes = flags & SectionCharacteristicsRaw::Align8Bytes as u32 != 0;
        let align_16_bytes = flags & SectionCharacteristicsRaw::Align16Bytes as u32 != 0;
        let align_32_bytes = flags & SectionCharacteristicsRaw::Align32Bytes as u32 != 0;
        let align_64_bytes = flags & SectionCharacteristicsRaw::Align64Bytes as u32 != 0;
        let align_128_bytes = flags & SectionCharacteristicsRaw::Align128Bytes as u32 != 0;
        let align_256_bytes = flags & SectionCharacteristicsRaw::Align256Bytes as u32 != 0;
        let align_512_bytes = flags & SectionCharacteristicsRaw::Align512Bytes as u32 != 0;
        let align_1024_bytes = flags & SectionCharacteristicsRaw::Align1024Bytes as u32 != 0;
        let align_2048_bytes = flags & SectionCharacteristicsRaw::Align2048Bytes as u32 != 0;
        let align_4096_bytes = flags & SectionCharacteristicsRaw::Align4096Bytes as u32 != 0;
        let align_8192_bytes = flags & SectionCharacteristicsRaw::Align8192Bytes as u32 != 0;
        let link_n_relec_overflow =
            flags & SectionCharacteristicsRaw::LinkNRelecOverflow as u32 != 0;
        let memory_discardable = flags & SectionCharacteristicsRaw::MemoryDiscardable as u32 != 0;
        let memory_not_cached = flags & SectionCharacteristicsRaw::MemoryNotCached as u32 != 0;
        let memory_not_paged = flags & SectionCharacteristicsRaw::MemoryNotPaged as u32 != 0;
        let memory_shared = flags & SectionCharacteristicsRaw::MemoryShared as u32 != 0;
        let memory_execute = flags & SectionCharacteristicsRaw::MemoryExecute as u32 != 0;
        let memory_read = flags & SectionCharacteristicsRaw::MemoryRead as u32 != 0;
        let memory_write = flags & SectionCharacteristicsRaw::MemoryWrite as u32 != 0;

        Ok((
            rest,
            Self {
                reserved_1,
                reserved_2,
                reserved_3,
                type_no_pad,
                reserved_4,
                contains_code,
                contains_initialized_data,
                contains_uninitialized_data,
                link_other,
                link_info,
                reserved_5,
                link_removed,
                link_comdat,
                reserved_6,
                no_defer_speculative_exceptions,
                global_pointer_references,
                reserved_7,
                memory_purgeable,
                memory_locked,
                memory_preload,
                align_1_bytes,
                align_2_bytes,
                align_4_bytes,
                align_8_bytes,
                align_16_bytes,
                align_32_bytes,
                align_64_bytes,
                align_128_bytes,
                align_256_bytes,
                align_512_bytes,
                align_1024_bytes,
                align_2048_bytes,
                align_4096_bytes,
                align_8192_bytes,
                link_n_relec_overflow,
                memory_discardable,
                memory_not_cached,
                memory_not_paged,
                memory_shared,
                memory_execute,
                memory_read,
                memory_write,
            },
        ))
    }
}
