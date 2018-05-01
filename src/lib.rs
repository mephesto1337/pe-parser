#![recursion_limit="128"]

#[macro_use] extern crate nom;
#[macro_use] extern crate enum_primitive;

#[allow(dead_code)]
#[allow(unused_macros)]

pub mod enums;
pub use enums::*;

pub mod structures;
pub use structures::*;

pub mod parsers;
pub use parsers::*;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
