#[cfg(test)]
use parser::{Grammar, pairs};

macro_rules! full_test {
    ($T:ident, $input:expr $(,)?) => {{
        use pest_typed::TypedParser as _;
        let input = $input;
        match Grammar::try_parse::<pairs::$T>(input) {
            Ok(_res) => {
                // println!("{:#?}", _res);
            }
            Err(e) => {
                eprintln!("Failed to parse input :\n{}", $input);
                // eprintln!("{}", e);
                panic!("\n{}\n", e);
            }
        }
    }};
}

#[test]
fn main() {
    full_test!(
        main,
        "\
pattern CVE-2018-21000

patt {
    p[
       $T: ty,
       $I: ty 
    ] = #[mir] fn _ (..) -> _ ; #~[unsafe]
}
"
    );
}
