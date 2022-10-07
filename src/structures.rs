use std::fmt;

use crate::enums::ImageDataDirectoryIndex;
use crate::{NomError, Parse};

use nom::bytes::complete::take;
use nom::combinator::verify;
use nom::error::context;
use nom::multi::many1;
use nom::number::complete::{le_u32, le_u64};

mod dos;
pub use dos::DosHeader;

mod file_header;
pub use file_header::FileHeader;

mod data_directory;
pub use data_directory::{DataDirectory, ImportByName, ImportDescriptor};

mod optional_header;
pub use optional_header::{OptionalHeader, OptionalHeader32, OptionalHeader64};

mod section;
pub use section::SectionHeader;

mod pe;
pub use pe::PeHeader;

#[derive(Debug)]
pub enum Name<'a> {
    String(&'a str),
    Rva(u64),
}

impl<'a> fmt::Display for Name<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => f.write_str(s),
            Self::Rva(rva) => write!(f, "0x{:x}", rva),
        }
    }
}

#[derive(Debug)]
enum ImportSymbol<'a> {
    Ordinal(u64),
    Name(&'a str),
}

pub struct Pe<'a> {
    pub(super) data: &'a [u8],
    pub(super) dos_header: DosHeader,
    pub(super) pe_header: PeHeader<'a>,
    import_table: Vec<(&'a str, Vec<ImportSymbol<'a>>)>,
}

fn get_section_containing_rva<'a, 'b, E>(
    pe_header: &'b PeHeader<'a>,
    rva: u64,
) -> Result<&'b SectionHeader<'a>, nom::Err<E>>
where
    E: NomError<'a>,
{
    for section in pe_header.sections.iter() {
        if section.contains(rva) {
            return Ok(section);
        }
    }
    Err(nom::Err::Error(E::from_error_kind(
        &b""[..],
        nom::error::ErrorKind::NoneOf,
    )))
}

fn get_data<'a, 'b, E>(
    pe_header: &'b PeHeader<'a>,
    data: &'a [u8],
    rva: u64,
    size: Option<u64>,
) -> Result<&'a [u8], nom::Err<E>>
where
    E: NomError<'a>,
{
    let section = get_section_containing_rva(pe_header, rva)?;
    let offset = section.offset(rva);

    let section_data =
        &data[section.pointer_to_raw_data as usize..][..section.size_of_raw_data as usize];

    if let Some(size) = size {
        Ok(&section_data[offset..][..size as usize])
    } else {
        Ok(&section_data[offset..])
    }
}

fn get_string<'a, 'b, E>(
    pe_header: &'b PeHeader<'a>,
    data: &'a [u8],
    rva: u64,
) -> Result<&'a str, nom::Err<E>>
where
    E: NomError<'a>,
{
    let string_data = get_data(pe_header, data, rva, None)?;

    let raw_string = string_data.split(|b| *b == 0).next().ok_or_else(|| {
        nom::Err::Error(E::add_context(
            string_data,
            "String is not nul-terminated",
            E::from_error_kind(string_data, nom::error::ErrorKind::Verify),
        ))
    })?;

    let string = std::str::from_utf8(raw_string).map_err(|_| {
        nom::Err::Error(E::add_context(
            raw_string,
            "String is not valid UTF8",
            E::from_error_kind(raw_string, nom::error::ErrorKind::Verify),
        ))
    })?;

    Ok(string)
}

impl<'a> Parse<'a> for Pe<'a> {
    fn parse<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (_, dos_header) = DosHeader::parse(input)?;
        let (_, pe_header) = PeHeader::parse(&input[dos_header.e_lfanew as usize..])?;

        // ImageDataDirectoryIndex::EntryExport

        // ImageDataDirectoryIndex::EntryImport
        let import_table = if let Some(data_dir) = pe_header
            .optional_header
            .get_data_directory(ImageDataDirectoryIndex::EntryImport)
        {
            let data = get_data(
                &pe_header,
                input,
                data_dir.virtual_address as u64,
                Some(data_dir.size as u64),
            )?;
            let (_, import_descriptors) = context(
                "Import table descriptors",
                many1(verify(ImportDescriptor::parse, |id| id.first_thunk != 0)),
            )(data)?;

            let mut import_table = Vec::with_capacity(import_descriptors.len());
            for import_desc in &import_descriptors {
                eprintln!("import_desc:\n{}", import_desc);
                let rva = match import_desc.name {
                    Name::Rva(rva) => rva,
                    _ => unreachable!(),
                };
                let module_name = get_string(&pe_header, input, rva)?;
                eprintln!("Getting symbols from {}", module_name);
                let symbols_data =
                    get_data(&pe_header, input, import_desc.first_thunk as u64, None)?;

                let symbols = if matches!(pe_header.optional_header, OptionalHeader::AMD64(_)) {
                    let (_, rvas) = context(
                        "Thunk Data 64 for import symbols",
                        many1(verify(le_u64, |rva| *rva != 0)),
                    )(symbols_data)?;
                    eprintln!("Got {} thunks", rvas.len());

                    let mut symbols = Vec::new();
                    const IMAGE_ORDINAL_FLAG: u64 = 1u64 << 63;
                    for rva in rvas {
                        eprintln!("RVA: 0x{:x}", rva);
                        if rva & IMAGE_ORDINAL_FLAG != 0 {
                            eprintln!("Got import by Ordinal(0x{:x})", rva & !IMAGE_ORDINAL_FLAG);
                            symbols.push(ImportSymbol::Ordinal(rva & !IMAGE_ORDINAL_FLAG));
                        } else {
                            let data = get_data(&pe_header, input, rva, None)?;
                            let (_, import) = ImportByName::parse(data)?;
                            eprintln!("Got import by Name({:?})", import.name);
                            symbols.push(ImportSymbol::Name(import.name));
                        }
                    }
                    symbols
                } else {
                    todo!();
                    let (_, rvas) = context(
                        "Thunk Data 32 for import symbols",
                        many1(verify(le_u32, |rva| *rva != 0)),
                    )(symbols_data)?;

                    let mut symbols = Vec::new();
                    const IMAGE_ORDINAL_FLAG: u32 = 1u32 << 31;
                    for rva in rvas {
                        if rva & IMAGE_ORDINAL_FLAG != 0 {
                            symbols.push(ImportSymbol::Ordinal((rva & !IMAGE_ORDINAL_FLAG) as u64));
                        } else {
                            let name = get_string(&pe_header, input, rva as u64 + 2)?;
                            symbols.push(ImportSymbol::Name(name));
                        }
                    }
                    symbols
                };

                import_table.push((module_name, symbols));
            }

            import_table
        } else {
            Vec::new()
        };

        // ImageDataDirectoryIndex::EntryResource

        // ImageDataDirectoryIndex::EntryException

        // ImageDataDirectoryIndex::EntrySecurity

        // ImageDataDirectoryIndex::EntryBasereloc

        // ImageDataDirectoryIndex::EntryDebug

        // ImageDataDirectoryIndex::EntryArchitecture

        // ImageDataDirectoryIndex::EntryGlobalptr

        // ImageDataDirectoryIndex::EntryTls

        // ImageDataDirectoryIndex::EntryLoadConfig

        // ImageDataDirectoryIndex::EntryBoundImport

        // ImageDataDirectoryIndex::EntryIat

        // ImageDataDirectoryIndex::EntryDelayImport

        // ImageDataDirectoryIndex::EntryComDescriptor

        let (rest, data) = take(pe_header.optional_header.size_of_image().min(input.len()))(input)?;

        Ok((
            rest,
            Self {
                data,
                dos_header,
                pe_header,
                import_table,
            },
        ))
    }
}

impl<'a> fmt::Display for Pe<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = f.width().unwrap_or_default() + 1;
        let offset = "  ".repeat(width);

        write!(f, "{offset}dos_header:\n{:width$}", self.dos_header)?;
        write!(f, "{offset}pe_header:\n{:width$}", self.pe_header)?;
        write!(f, "{offset}import_table:\n")?;
        for (module, symbols) in &self.import_table {
            for symbol in symbols {
                match symbol {
                    ImportSymbol::Ordinal(ord) => write!(f, "{offset}  {}!0x{:x}\n", *module, ord)?,
                    ImportSymbol::Name(name) => write!(f, "{offset}  {}!{}\n", *module, name)?,
                }
            }
            write!(f, "\n")?;
        }
        Ok(())
    }
}
