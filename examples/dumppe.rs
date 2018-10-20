extern crate clap;
extern crate pe;
#[macro_use]
extern crate failure;
extern crate nom;

use clap::{App, Arg};
use pe::*;
use std::convert::From;
use std::fs;
use std::io::{self, Read};

#[derive(Fail, Debug)]
enum Error {
    #[fail(display = "Parse error : {:?}", _0)]
    ParseError(nom::ErrorKind),

    #[fail(display = "IO error : {}", _0)]
    IOError(io::Error),

    #[fail(display = "Args error : {}", _0)]
    ArgsError(clap::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IOError(e)
    }
}

impl From<clap::Error> for Error {
    fn from(e: clap::Error) -> Error {
        Error::ArgsError(e)
    }
}

fn run() -> Result<(), Error> {
    let args = App::new("dumppe")
        .version("1.0")
        .author("Thomas WACHE")
        .arg(Arg::with_name("pe").index(1))
        .get_matches_safe()?;
    if let Some(pefilename) = args.value_of("pe") {
        let mut buf: Vec<u8> = Vec::new();
        let mut file = fs::File::open(pefilename)?;
        let pefilesize = file.read_to_end(&mut buf)?;

        println!("Loaded {} bytes from {}", pefilesize, pefilename);

        match parse_dos_header(&buf.as_slice()) {
            Ok((_, dh)) => {
                println!("DOS = {:#?}", dh);
                let off = dh.e_lfanew as usize;
                match parse_pe_header(&buf.as_slice()[off..]) {
                    Ok((_, ph)) => {
                        println!("PE = {:#?}", ph);
                        Ok(())
                    }
                    Err(e) => Err(Error::ParseError(e.into_error_kind())),
                }
            }
            Err(e) => Err(Error::ParseError(e.into_error_kind())),
        }
    } else {
        Err(Error::ArgsError(clap::Error {
            message: String::from("pe argument must be privided"),
            kind: clap::ErrorKind::EmptyValue,
            info: None,
        }))
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => println!("{}", e),
    }
}
