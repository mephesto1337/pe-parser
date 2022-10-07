use nom::error::ParseError;
use nom::Parser;

pub(crate) fn count_fixed<I, O, E, F, const N: usize>(
    mut f: F,
) -> impl FnMut(I) -> nom::IResult<I, [O; N], E>
where
    I: Clone + PartialEq,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    move |i: I| {
        use std::mem::MaybeUninit;
        let mut input = i;
        let mut array: [MaybeUninit<O>; N] = MaybeUninit::uninit_array();

        for elt in array.iter_mut() {
            let input_ = input.clone();
            let (rest, o) = f.parse(input_)?;
            elt.write(o);
            input = rest;
        }

        Ok((input, unsafe { MaybeUninit::array_assume_init(array) }))
    }
}
