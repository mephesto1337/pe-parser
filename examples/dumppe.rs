use pe::{DosHeader, Parse, PeHeader};

use clap::{App, Arg};
use std::convert::From;
use std::fs;
use std::io::{self, Read};

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("Parse error")]
    Parsing(nom::Err<nom::error::VerboseError<Vec<u8>>>),

    #[error("IO error : {0}")]
    IO(#[from] io::Error),
}

impl From<nom::Err<nom::error::VerboseError<&'_ [u8]>>> for Error {
    fn from(e: nom::Err<nom::error::VerboseError<&'_ [u8]>>) -> Self {
        fn to_owned(
            mut e: nom::error::VerboseError<&'_ [u8]>,
        ) -> nom::error::VerboseError<Vec<u8>> {
            nom::error::VerboseError {
                errors: e
                    .errors
                    .drain(..)
                    .map(|(input, ek)| (input[..16].to_owned(), ek))
                    .collect(),
            }
        }
        match e {
            nom::Err::Incomplete(n) => Self::Parsing(nom::Err::Incomplete(n)),
            nom::Err::Error(e) => Self::Parsing(nom::Err::Error(to_owned(e))),
            nom::Err::Failure(e) => Self::Parsing(nom::Err::Failure(to_owned(e))),
        }
    }
}

fn main() -> Result<(), Error> {
    let args = App::new("dumppe")
        .version("1.0")
        .author("Thomas WACHE")
        .arg(Arg::with_name("pe").index(1))
        .get_matches_safe()
        .expect("Bad arguments");

    let pefilename = args.value_of("pe").expect("PE argument is mandatory");
    let mut buf: Vec<u8> = Vec::new();
    let mut file = fs::File::open(pefilename)?;
    let pefilesize = file.read_to_end(&mut buf)?;

    println!("Loaded {} bytes from {}", pefilesize, pefilename);

    let (_, dh) = DosHeader::parse::<nom::error::VerboseError<&[u8]>>(&buf[..])?;
    println!("DOS:\n{}", &dh);
    let (_, pe) = PeHeader::parse::<nom::error::VerboseError<&[u8]>>(&buf[dh.e_lfanew as usize..])?;
    println!("PE:\n{}", &pe);
    Ok(())
}
