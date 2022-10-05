use std::fmt;

use crate::{NomError, Parse};

use enum_primitive_derive::Primitive;
use nom::{
    combinator::map_opt,
    error::context,
    number::complete::{be_u32, le_u16},
};
use num_traits::FromPrimitive;

#[derive(Debug, PartialEq, Primitive)]
#[repr(u16)]
pub enum FileMachine {
    MachineI386 = 0x014c,
    MachineIA64 = 0x0200,
    MachineAMD64 = 0x8664,
}

impl fmt::Display for FileMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MachineAMD64 => f.write_str("amd64"),
            Self::MachineIA64 => f.write_str("ia64"),
            Self::MachineI386 => f.write_str("i386"),
        }
    }
}

#[derive(Debug, PartialEq, Primitive)]
#[repr(u16)]
enum FileCharacteristicsRaw {
    /// Relocation information was stripped from the file. The file must be loaded at its preferred
    /// base address. If the base address is not available, the loader reports an error.
    ImageFileRelocsStripped = 0x0001,

    /// The file is executable (there are no unresolved external references).
    ImageFileExecutableImage = 0x0002,

    /// COFF line numbers were stripped from the file.
    ImageFileLineNumsStripped = 0x0004,

    /// COFF symbol table entries were stripped from file.
    ImageFileLocalSymsStripped = 0x0008,

    /// Aggressively trim the working set. This value is obsolete.
    ImageFileAggresiveWsTrim = 0x0010,

    /// The application can handle addresses larger than 2 GB.
    ImageFileLargeAddressAware = 0x0020,

    /// The bytes of the word are reversed. This flag is obsolete.
    ImageFileBytesReversedLo = 0x0080,

    /// The computer supports 32-bit words.
    ImageFile32bitMachine = 0x0100,

    /// Debugging information was removed and stored separately in another file.
    ImageFileDebugStripped = 0x0200,

    /// If the image is on removable media, copy it to and run it from the swap file.
    ImageFileRemovableRunFromSwap = 0x0400,

    /// If the image is on the network, copy it to and run it from the swap file.
    ImageFileNetRunFromSwap = 0x0800,

    /// The image is a system file.
    ImageFileSystem = 0x1000,

    /// The image is a DLL file. While it is an executable file, it cannot be run directly.
    ImageFileDll = 0x2000,

    /// The file should be run only on a uniprocessor computer.
    ImageFileUpSystemOnly = 0x4000,

    /// The bytes of the word are reversed. This flag is obsolete.
    ImageFileBytesReversedHi = 0x8000,
}

/// The characteristics of the image. This member can be one or more of the following values.
pub struct FileCharacteristics {
    /// Relocation information was stripped from the file. The file must be loaded at its preferred
    /// base address. If the base address is not available, the loader reports an error.
    pub image_file_relocs_stripped: bool,

    /// The file is executable (there are no unresolved external references).
    pub image_file_executable_image: bool,

    /// COFF line numbers were stripped from the file.
    pub image_file_line_nums_stripped: bool,

    /// COFF symbol table entries were stripped from file.
    pub image_file_local_syms_stripped: bool,

    /// Aggressively trim the working set. This value is obsolete.
    pub image_file_aggresive_ws_trim: bool,

    /// The application can handle addresses larger than 2 GB.
    pub image_file_large_address_aware: bool,

    /// The bytes of the word are reversed. This flag is obsolete.
    pub image_file_bytes_reversed_lo: bool,

    /// The computer supports 32-bit words.
    pub image_file_32_bit_machine: bool,

    /// Debugging information was removed and stored separately in another file.
    pub image_file_debug_stripped: bool,

    /// If the image is on removable media, copy it to and run it from the swap file.
    pub image_file_removable_run_from_swap: bool,

    /// If the image is on the network, copy it to and run it from the swap file.
    pub image_file_net_run_from_swap: bool,

    /// The image is a system file.
    pub image_file_system: bool,

    /// The image is a DLL file. While it is an executable file, it cannot be run directly.
    pub image_file_dll: bool,

    /// The file should be run only on a uniprocessor computer.
    pub image_file_up_system_only: bool,

    /// The bytes of the word are reversed. This flag is obsolete.
    pub image_file_bytes_reversed_hi: bool,
}

impl<'a> Parse<'a> for FileCharacteristics {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, flags) = context("Image characteristics", le_u16)(input)?;
        let image_file_relocs_stripped =
            flags & FileCharacteristicsRaw::ImageFileRelocsStripped as u16 != 0;
        let image_file_executable_image =
            flags & FileCharacteristicsRaw::ImageFileExecutableImage as u16 != 0;
        let image_file_line_nums_stripped =
            flags & FileCharacteristicsRaw::ImageFileLineNumsStripped as u16 != 0;
        let image_file_local_syms_stripped =
            flags & FileCharacteristicsRaw::ImageFileLocalSymsStripped as u16 != 0;
        let image_file_aggresive_ws_trim =
            flags & FileCharacteristicsRaw::ImageFileAggresiveWsTrim as u16 != 0;
        let image_file_large_address_aware =
            flags & FileCharacteristicsRaw::ImageFileLargeAddressAware as u16 != 0;
        let image_file_bytes_reversed_lo =
            flags & FileCharacteristicsRaw::ImageFileBytesReversedLo as u16 != 0;
        let image_file_32_bit_machine =
            flags & FileCharacteristicsRaw::ImageFile32bitMachine as u16 != 0;
        let image_file_debug_stripped =
            flags & FileCharacteristicsRaw::ImageFileDebugStripped as u16 != 0;
        let image_file_removable_run_from_swap =
            flags & FileCharacteristicsRaw::ImageFileRemovableRunFromSwap as u16 != 0;
        let image_file_net_run_from_swap =
            flags & FileCharacteristicsRaw::ImageFileNetRunFromSwap as u16 != 0;
        let image_file_system = flags & FileCharacteristicsRaw::ImageFileSystem as u16 != 0;
        let image_file_dll = flags & FileCharacteristicsRaw::ImageFileDll as u16 != 0;
        let image_file_up_system_only =
            flags & FileCharacteristicsRaw::ImageFileUpSystemOnly as u16 != 0;
        let image_file_bytes_reversed_hi =
            flags & FileCharacteristicsRaw::ImageFileBytesReversedHi as u16 != 0;

        Ok((
            rest,
            Self {
                image_file_relocs_stripped,
                image_file_executable_image,
                image_file_line_nums_stripped,
                image_file_local_syms_stripped,
                image_file_aggresive_ws_trim,
                image_file_large_address_aware,
                image_file_bytes_reversed_lo,
                image_file_32_bit_machine,
                image_file_debug_stripped,
                image_file_removable_run_from_swap,
                image_file_net_run_from_swap,
                image_file_system,
                image_file_dll,
                image_file_up_system_only,
                image_file_bytes_reversed_hi,
            },
        ))
    }
}

impl fmt::Debug for FileCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg_struct = f.debug_struct("FileCharacteristics");
        if self.image_file_relocs_stripped {
            dbg_struct.field(
                "image_file_relocs_stripped",
                &self.image_file_relocs_stripped,
            );
        }
        if self.image_file_executable_image {
            dbg_struct.field(
                "image_file_executable_image",
                &self.image_file_executable_image,
            );
        }
        if self.image_file_line_nums_stripped {
            dbg_struct.field(
                "image_file_line_nums_stripped",
                &self.image_file_line_nums_stripped,
            );
        }
        if self.image_file_local_syms_stripped {
            dbg_struct.field(
                "image_file_local_syms_stripped",
                &self.image_file_local_syms_stripped,
            );
        }
        if self.image_file_aggresive_ws_trim {
            dbg_struct.field(
                "image_file_aggresive_ws_trim",
                &self.image_file_aggresive_ws_trim,
            );
        }
        if self.image_file_large_address_aware {
            dbg_struct.field(
                "image_file_large_address_aware",
                &self.image_file_large_address_aware,
            );
        }
        if self.image_file_bytes_reversed_lo {
            dbg_struct.field(
                "image_file_bytes_reversed_lo",
                &self.image_file_bytes_reversed_lo,
            );
        }
        if self.image_file_32_bit_machine {
            dbg_struct.field("image_file_32_bit_machine", &self.image_file_32_bit_machine);
        }
        if self.image_file_debug_stripped {
            dbg_struct.field("image_file_debug_stripped", &self.image_file_debug_stripped);
        }
        if self.image_file_removable_run_from_swap {
            dbg_struct.field(
                "image_file_removable_run_from_swap",
                &self.image_file_removable_run_from_swap,
            );
        }
        if self.image_file_net_run_from_swap {
            dbg_struct.field(
                "image_file_net_run_from_swap",
                &self.image_file_net_run_from_swap,
            );
        }
        if self.image_file_system {
            dbg_struct.field("image_file_system", &self.image_file_system);
        }
        if self.image_file_dll {
            dbg_struct.field("image_file_dll", &self.image_file_dll);
        }
        if self.image_file_up_system_only {
            dbg_struct.field("image_file_up_system_only", &self.image_file_up_system_only);
        }
        if self.image_file_bytes_reversed_hi {
            dbg_struct.field(
                "image_file_bytes_reversed_hi",
                &self.image_file_bytes_reversed_hi,
            );
        }
        dbg_struct.finish_non_exhaustive()
    }
}

impl fmt::Display for FileCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut comma = "";
        if self.image_file_relocs_stripped {
            write!(f, "{}relocs_stripped", comma)?;
            comma = ",";
        }
        if self.image_file_executable_image {
            write!(f, "{}executable_image", comma)?;
            comma = ",";
        }
        if self.image_file_line_nums_stripped {
            write!(f, "{}line_nums_stripped", comma)?;
            comma = ",";
        }
        if self.image_file_local_syms_stripped {
            write!(f, "{}local_syms_stripped", comma)?;
            comma = ",";
        }
        if self.image_file_aggresive_ws_trim {
            write!(f, "{}aggresive_ws_trim", comma)?;
            comma = ",";
        }
        if self.image_file_large_address_aware {
            write!(f, "{}large_address_aware", comma)?;
            comma = ",";
        }
        if self.image_file_bytes_reversed_lo {
            write!(f, "{}bytes_reversed_lo", comma)?;
            comma = ",";
        }
        if self.image_file_32_bit_machine {
            write!(f, "{}32_bit_machine", comma)?;
            comma = ",";
        }
        if self.image_file_debug_stripped {
            write!(f, "{}debug_stripped", comma)?;
            comma = ",";
        }
        if self.image_file_removable_run_from_swap {
            write!(f, "{}removable_run_from_swap", comma)?;
            comma = ",";
        }
        if self.image_file_net_run_from_swap {
            write!(f, "{}net_run_from_swap", comma)?;
            comma = ",";
        }
        if self.image_file_system {
            write!(f, "{}system", comma)?;
            comma = ",";
        }
        if self.image_file_dll {
            write!(f, "{}dll", comma)?;
            comma = ",";
        }
        if self.image_file_up_system_only {
            write!(f, "{}up_system_only", comma)?;
            comma = ",";
        }
        if self.image_file_bytes_reversed_hi {
            write!(f, "{}bytes_reversed_hi", comma)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Primitive)]
#[repr(u16)]
pub enum OptionalHeaderMagic {
    Header32 = 0x10b,
    Header64 = 0x20b,
    HeaderRom = 0x107,
}

impl fmt::Display for OptionalHeaderMagic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header32 => write!(f, "32 bits (0x{:x})", *self as u16),
            Self::Header64 => write!(f, "64 bits (0x{:x})", *self as u16),
            Self::HeaderRom => write!(f, "ROM (0x{:x})", *self as u16),
        }
    }
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

impl fmt::Display for SubSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => f.write_str("native"),
            Self::WindowsGui => f.write_str("windows gui"),
            Self::WindowsCui => f.write_str("windows cui"),
            Self::OS2Cui => f.write_str("OS2 cui"),
            Self::PosixCui => f.write_str("posix cui"),
            Self::WindowsCeGui => f.write_str("windows CE gui"),
            Self::EfiApplication => f.write_str("EFI application"),
            Self::EfiBootServiceDriver => f.write_str("EFI boot service driver"),
            Self::EfiRuntimeDriver => f.write_str("EFI runtime driver"),
            Self::EfiRom => f.write_str("EFI ROM"),
            Self::Xbox => f.write_str("Xbox"),
            Self::WindowsBootApplication => f.write_str("Windows boot application"),
        }
    }
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

impl fmt::Display for DllCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut comma = "";
        if self.reserved1 {
            write!(f, "{}reserved1", comma)?;
            comma = ",";
        }
        if self.reserved2 {
            write!(f, "{}reserved2", comma)?;
            comma = ",";
        }
        if self.reserved3 {
            write!(f, "{}reserved3", comma)?;
            comma = ",";
        }
        if self.reserved4 {
            write!(f, "{}reserved4", comma)?;
            comma = ",";
        }
        if self.dynamic_base {
            write!(f, "{}dynamic_base", comma)?;
            comma = ",";
        }
        if self.force_integrity {
            write!(f, "{}force_integrity", comma)?;
            comma = ",";
        }
        if self.nx_compat {
            write!(f, "{}nx_compat", comma)?;
            comma = ",";
        }
        if self.no_isolation {
            write!(f, "{}no_isolation", comma)?;
            comma = ",";
        }
        if self.no_seh {
            write!(f, "{}no_seh", comma)?;
            comma = ",";
        }
        if self.no_bind {
            write!(f, "{}no_bind", comma)?;
            comma = ",";
        }
        if self.reserved5 {
            write!(f, "{}reserved5", comma)?;
            comma = ",";
        }
        if self.wdm_driver {
            write!(f, "{}wdm_driver", comma)?;
            comma = ",";
        }
        if self.reserved6 {
            write!(f, "{}reserved6", comma)?;
            comma = ",";
        }
        if self.terminal_server_aware {
            write!(f, "{}terminal_server_aware", comma)?;
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for DllCharacteristics {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, flags) = context("Dll characteristics", le_u16)(input)?;
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

impl fmt::Display for SectionCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut comma = "";
        if self.reserved_1 {
            write!(f, "{}reserved_1", comma)?;
            comma = ",";
        }
        if self.reserved_2 {
            write!(f, "{}reserved_2", comma)?;
            comma = ",";
        }
        if self.reserved_3 {
            write!(f, "{}reserved_3", comma)?;
            comma = ",";
        }
        if self.type_no_pad {
            write!(f, "{}type_no_pad", comma)?;
            comma = ",";
        }
        if self.reserved_4 {
            write!(f, "{}reserved_4", comma)?;
            comma = ",";
        }
        if self.contains_code {
            write!(f, "{}contains_code", comma)?;
            comma = ",";
        }
        if self.contains_initialized_data {
            write!(f, "{}contains_initialized_data", comma)?;
            comma = ",";
        }
        if self.contains_uninitialized_data {
            write!(f, "{}contains_uninitialized_data", comma)?;
            comma = ",";
        }
        if self.link_other {
            write!(f, "{}link_other", comma)?;
            comma = ",";
        }
        if self.link_info {
            write!(f, "{}link_info", comma)?;
            comma = ",";
        }
        if self.reserved_5 {
            write!(f, "{}reserved_5", comma)?;
            comma = ",";
        }
        if self.link_removed {
            write!(f, "{}link_removed", comma)?;
            comma = ",";
        }
        if self.link_comdat {
            write!(f, "{}link_comdat", comma)?;
            comma = ",";
        }
        if self.reserved_6 {
            write!(f, "{}reserved_6", comma)?;
            comma = ",";
        }
        if self.no_defer_speculative_exceptions {
            write!(f, "{}no_defer_speculative_exceptions", comma)?;
            comma = ",";
        }
        if self.global_pointer_references {
            write!(f, "{}global_pointer_references", comma)?;
            comma = ",";
        }
        if self.reserved_7 {
            write!(f, "{}reserved_7", comma)?;
            comma = ",";
        }
        if self.memory_purgeable {
            write!(f, "{}memory_purgeable", comma)?;
            comma = ",";
        }
        if self.memory_locked {
            write!(f, "{}memory_locked", comma)?;
            comma = ",";
        }
        if self.memory_preload {
            write!(f, "{}memory_preload", comma)?;
            comma = ",";
        }
        if self.align_1_bytes {
            write!(f, "{}align_1_bytes", comma)?;
            comma = ",";
        }
        if self.align_2_bytes {
            write!(f, "{}align_2_bytes", comma)?;
            comma = ",";
        }
        if self.align_4_bytes {
            write!(f, "{}align_4_bytes", comma)?;
            comma = ",";
        }
        if self.align_8_bytes {
            write!(f, "{}align_8_bytes", comma)?;
            comma = ",";
        }
        if self.align_16_bytes {
            write!(f, "{}align_16_bytes", comma)?;
            comma = ",";
        }
        if self.align_32_bytes {
            write!(f, "{}align_32_bytes", comma)?;
            comma = ",";
        }
        if self.align_64_bytes {
            write!(f, "{}align_64_bytes", comma)?;
            comma = ",";
        }
        if self.align_128_bytes {
            write!(f, "{}align_128_bytes", comma)?;
            comma = ",";
        }
        if self.align_256_bytes {
            write!(f, "{}align_256_bytes", comma)?;
            comma = ",";
        }
        if self.align_512_bytes {
            write!(f, "{}align_512_bytes", comma)?;
            comma = ",";
        }
        if self.align_1024_bytes {
            write!(f, "{}align_1024_bytes", comma)?;
            comma = ",";
        }
        if self.align_2048_bytes {
            write!(f, "{}align_2048_bytes", comma)?;
            comma = ",";
        }
        if self.align_4096_bytes {
            write!(f, "{}align_4096_bytes", comma)?;
            comma = ",";
        }
        if self.align_8192_bytes {
            write!(f, "{}align_8192_bytes", comma)?;
            comma = ",";
        }
        if self.link_n_relec_overflow {
            write!(f, "{}link_n_relec_overflow", comma)?;
            comma = ",";
        }
        if self.memory_discardable {
            write!(f, "{}memory_discardable", comma)?;
            comma = ",";
        }
        if self.memory_not_cached {
            write!(f, "{}memory_not_cached", comma)?;
            comma = ",";
        }
        if self.memory_not_paged {
            write!(f, "{}memory_not_paged", comma)?;
            comma = ",";
        }
        if self.memory_shared {
            write!(f, "{}memory_shared", comma)?;
            comma = ",";
        }
        if self.memory_execute {
            write!(f, "{}memory_execute", comma)?;
            comma = ",";
        }
        if self.memory_read {
            write!(f, "{}memory_read", comma)?;
            comma = ",";
        }
        if self.memory_write {
            write!(f, "{}memory_write", comma)?;
        }
        Ok(())
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
