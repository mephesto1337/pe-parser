mod dos;
pub use dos::DosHeader;

mod file_header;
pub use file_header::FileHeader;

mod data_directory;
pub use data_directory::{DataDirectory, ImportDescriptor};

mod optional_header;
pub use optional_header::{OptionalHeader, OptionalHeader32, OptionalHeader64};

mod section;
pub use section::{SectionHeader, SectionName};

mod pe;
pub use pe::PeHeader;

pub struct Pe<'a> {
    data: &'a [u8],
    dos_header: DosHeader,
    pe_header: PeHeader<'a>,
    import_table: Vec<ImportDescriptor>,
}

impl<'a> Pe<'a> {
    fn get_section_containing_rva(&'a self, rva: u32, size: u32) -> Option<&'a SectionHeader<'a>> {
        for section in &self.pe_header.sections {
            if section.virtual_address <= rva
                && rva.checked_add(size)? < section.virtual_address + section.size_of_raw_data
            {
                return Some(section);
            }
        }
        None
    }

    pub fn get_data(&'a self, rva: u32, size: u32) -> Option<&'a [u8]> {
        let section = self.get_section_containing_rva(rva, size)?;
        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;

        self.data.get(start..end)
    }
}
