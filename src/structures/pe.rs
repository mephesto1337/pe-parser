use std::fmt;

use super::{FileHeader, OptionalHeader, SectionHeader};

pub struct PeHeader<'a> {
    pub data: &'a [u8],
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<SectionHeader<'a>>,
}

impl<'a> fmt::Debug for PeHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeHeader")
            .field("signature", &self.signature)
            .field("file_header", &self.file_header)
            .field("optional_header", &self.optional_header)
            .field("sections", &self.sections)
            .finish()
    }
}

impl<'a> fmt::Display for PeHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = f.width().unwrap_or_default() + 1;
        let offset = "  ".repeat(width);
        write!(f, "{offset}signature: 0x{:08x}\n", self.signature)?;
        write!(f, "{offset}file_header:\n{:width$}\n", self.file_header)?;
        write!(
            f,
            "{offset}optional_header:\n{:width$}\n",
            self.optional_header
        )?;
        write!(f, "{offset}sections:\n")?;
        for section in &self.sections {
            write!(f, "{:width$}\n", section)?;
        }

        Ok(())
    }
}
