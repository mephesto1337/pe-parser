use std::fmt;

#[derive(Debug)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl fmt::Display for DataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = "  ".repeat(f.width().unwrap_or_default() + 1);
        write!(f, "{offset}virtual_address: 0x{:x}\n", self.virtual_address)?;
        write!(f, "{offset}size: 0x{:x}\n", self.size)
    }
}
