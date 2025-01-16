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
fn cve_2018_21000() {
    full_test!(
        main,
        "\
pattern CVE-2018-21000

util {
    use alloc::vec::Vec;
    use core::ptr::non_null::NonNull;
    use core::ptr::unique::Unique;
    use alloc::raw_vec::Cap;
    use alloc::raw_vec::RawVecInner;
    use alloc::raw_vec::RawVec;
    use alloc::alloc::Global;
    use core::marker::PhantomData;

    p_misordered_para[
        $T1: ty,
        $T2: ty,
        $T3: ty,
        $Op: binop
    ] = #[mir] unsafe fn _ (..) -> _ {
        let $from_vec: Vec::<$T1> = _;
        let mut $from_vec_mut_borrow: &mut Vec::<$T1> = &mut $from_vec;
        let mut $from_vec_non_null: NonNull::<u8> = copy (*$from_vec_mut_borrow).buf.inner.ptr.pointer;
        let mut $from_vec_const_ptr: *const u8 = copy ($from_vec_non_null.pointer);
        let mut $from_vec_mut_ptr: *mut u8 =copy $from_vec_const_ptr as *mut u8 (PtrToPtr);
        let mut $from_vec_inmutable_borrow: &Vec::<$T1> = &$from_vec;
        let mut $from_vec_cap: usize = copy (*$from_vec_inmutable_borrow).buf.inner.cap.0;
        let mut $from_vec_len: usize = copy (*$from_vec_inmutable_borrow).len;
        let mut $tsize: usize = SizeOf($T2);
        let mut $to_vec_cap: usize = $Op(move $from_vec_cap, copy $tsize);
        let mut $to_vec_len: usize = $Op(move $from_vec_len, copy $tsize);
        let mut $to_vec_wrong_cap: Cap = #[Ctor] Cap(copy $to_vec_len);
        let mut $to_vec_mut_ptr: *mut $T3 = copy $from_vec_mut_ptr as *mut $T3 (PtrToPtr);
        let mut $to_vec_const_ptr: *const u8 = copy $to_vec_mut_ptr as *const u8 (PtrToPtr);
        let mut $to_vec_non_null: NonNull::<u8> = NonNull::<u8> { 
            pointer: copy $to_vec_const_ptr 
        };
        let mut $to_vec_unique: Unique::<u8> = Unique::<u8> { 
            pointer: move $to_vec_non_null, 
            _marker: const PhantomData::<u8>
        };
        let mut $to_vec_raw_inner: RawVecInner = RawVecInner { 
            ptr: move $to_vec_unique, 
            cap: copy $to_vec_wrong_cap, 
            alloc: const Global
        };
        let mut $to_vec_raw: RawVec::<$T3> = RawVec::<$T3> {
            inner: move $to_vec_raw_inner, 
            _marker: const PhantomData::<$T3> 
        };
        let mut $to_vec: Vec::<$T3> = Vec::<$T3> { 
            buf: move $to_vec_raw, 
            len: copy $to_vec_cap 
        };
    }
}

patt {
    p1[$T: ty] = p_reversed_para[
        $T1 = u8,
        $T2 = $T,
        $T3 = $T,
        $Op = Div
    ]

    p2[$T: ty] = p_reversed_para[
        $T1 = $T,
        $T2 = $T,
        $T3 = u8,
        $Op = Mul
    ]
}
"
    );
}

#[test]
fn cve_2019_15548() {
    full_test!(
        main,
        "\
pattern CVE-2019-15548-MIR

patt {
    use ncurses::instr;
    use libc::c_char;
    use std::string::String;

    // Only work for crate::ll::instr or ncures::instr
    p1[
        $T: ty,
    ] = #[mir] fn _ (..) -> _ {
        let $src: &String = _;
        let $bytes: &[u8] = String::as_bytes(move $src);
        let $ptr: *const u8 = slice::as_ptr(copy $bytes);
        let $dst: *const c_char = copy $ptr as *const c_char (Transmute);
        let $ret: $T = $crate::ll::instr(move $dst);
    }

    // Pass a string ptr to $c_func
    p2 = #[mir] fn _ (..) -> _ {
        let $ptr: *const c_char = _;
        _ = $c_func(move $ptr);
    }
}
"
    );
}

#[test]
fn cve_2019_16138() {
    full_test!(
        main,
        "\
pattern CVE-2019-16138

patt {
    use std::vec::Vec;

    p[
        $T: ty
    ] = #[mir] pub fn _ (..) -> _ {
        let $vec: Vec<$T> = std::vec::Vec::with_capacity(_);
        let $vec_ref: &mut Vec<$T> = &mut $vec;
        _ = std::vec::Vec::set_len(move $vec_ref, _);
    }
}
"
    );
}

#[test]
fn cve_2020_25016() {
    full_test!(
        main,
        "\
pattern CVE-2020-25016

patt {
    p_unsound_cast_const[
        $T: ty
    ] = #[mir] fn _ (..) -> _ {
        let $from_slice: &[$T] = _;
        let $from_raw: *const [$T] = &raw const *$from_slice;
        let $from_len: usize = PtrMetadata(copy $from_slice);
        let $ty_size: usize = SizeOf($T);
        let $to_ptr: *const u8 = copy $from_raw as *const u8 (PtrToPtr);
        let $to_len: usize = Mul(move $from_len, move $ty_size);
        let $to_raw: *const [u8] = *const [u8] from (copy $to_ptr, copy $to_len);
        let $to_slice: &[u8] = &*$to_raw;
    } #~[safety = safe]

    p_unsound_cast_mut[
        $T: ty
    ] = #[mir] fn _ (..) -> _ {
        let $from_slice_mut: &mut [$T] = _;
        let $from_raw_mut: *mut [$T] = &raw mut *$from_slice_mut;
        let $from_len_mut: usize = PtrMetadata(copy $from_slice_mut);
        let $ty_size_mut: usize = SizeOf($T);
        let $to_ptr_mut: *mut u8 = copy $from_raw_mut as *mut u8 (PtrToPtr);
        let $to_len_mut: usize = Mul(move $from_len_mut, move $ty_size_mut);
        let $to_raw_mut: *mut [u8] = *mut [u8] from (copy $to_ptr_mut, copy $to_len_mut);
        let $to_slice_mut: &mut [u8] = &mut *$to_raw_mut;
    } #~[safety = safe]
}

// Here, the metavariable $T is placed in square brackets, which is also for later constraints on T. The specific content of the constraint is: the type $T does not have unsafe trait constraints (except Send, Sync)
// (Since the expression of this constraint requires rustc code/encapsulation in the rpl standard library, it is not reflected in this example)
"
    );
}

#[test]
fn cve_2020_35881() {
    full_test!(
        main,
        "\
pattern CVE-2020-35881

patt {
    p_wrong_assumption_of_fat_pointer_layout_const_const = #[mir] fn _ (..) -> _ {
        let $ptr: *const $T = _;
        let $ref_to_ptr: &*const $T = &$ptr;
        let $ptr_to_ptr_t: *const *const $T = &raw const (*$ref_to_ptr);
        let $ptr_to_ptr: *const *const () = move $ptr_to_ptr_t as *const *const () (Transmute);
        let $data_ptr: *const () = _;
    }

    p_wrong_assumption_of_fat_pointer_layout_const_mut = #[mir] fn _ (..) -> _ {
        let $ptr: *const $T = _;
        let $ref_to_ptr: &mut *const $T = &mut $ptr;
        let $ptr_to_ptr_t: *mut *const $T = &raw mut (*$ref_to_ptr);
        let $ptr_to_ptr: *mut *mut () = move $ptr_to_ptr_t as *mut *mut () (Transmute);
        let $data_ptr: *mut () = _;
    }
    
    p_wrong_assumption_of_fat_pointer_layout_mut_const = #[mir] fn _ (..) -> _ {
        let $ptr: *mut $T = _;
        let $ref_to_ptr: &*mut $T = &$ptr;
        let $ptr_to_ptr_t: *const *mut $T = &raw const (*$ref_to_ptr);
        let $ptr_to_ptr: *const *mut () = move $ptr_to_ptr_t as *const *mut () (Transmute);
        let $data_ptr: *const () = _;
    }
    
    p_wrong_assumption_of_fat_pointer_layout_mut_mut = #[mir] fn _ (..) -> _ {
        let $ptr: *mut $T = _;
        let $ref_to_ptr: &mut *mut $T = &mut $ptr;
        let $ptr_to_ptr_t: *mut *mut $T = &raw mut (*$ref_to_ptr);
        let $ptr_to_ptr: *mut *mut () = move $ptr_to_ptr_t as *mut *mut () (Transmute);
        let $data_ptr: *mut () = _;
    }
}
"
    );
}

#[test]
fn cve_2020_35888() {
    full_test!(
        main,
        "\
pattern CVE-2020-35888

patt {
    p_move[
        $T: ty,
    ] = #[mir, warning] pub fn _ (..) -> _ {
        let $raw_ptr: *mut $T = _;
        let $value: $T = _;
        drop((*$raw_ptr));
        (*$raw_ptr) = move $value;
    }
}
"
    );
}

fn cve_2020_35892_35893() {
    full_test!(
        main,
        r#"
pattern CVE-2020-35892-3

patt {
    use core::ops::range::Range<usize>;

    // how to express constraints on meta variables?
    // 1. use a where clause (how to define a where clause?)
    // 2. use a predicate (how to define a predicate?)
    p[
        $T: ty,
        $SlabT: ty
    ] where $SlabT: Adt 
    = #[mir] fn _ (..) -> _ {
        let $self: &mut $SlabT;
        let $len: usize = copy (*$self).len;
        let $range: Range<usize> = Range { start: const 0_usize, end: move $len };
        let $iter: Range<usize> = move $range;
        loop {
            let $iter_mut: &mut Range<usize> = &mut $iter;
            let $start_ref: &usize = &(*$iter_mut).start;
            let $start: usize = copy *$start_ref;
            let $end_ref: &usize = &(*$iter_mut).end;
            let $end: usize = copy *$end_ref;
            let $cmp: bool = Lt(move $start, move $end);
            let $opt: Option<usize>;
            switchInt(move $cmp) {
                false => $opt = #[lang = "None"],
                _ => {
                    let $x1: usize = copy (*$iter_mut).start;
                    let $x2: usize = core::iter::range::Step::forward_unchecked(copy $x1, const 1_usize);
                    (*$iter_mut).start = move $x2;
                    $opt: Option<usize> = #[lang = "Some"](copy $x1);
                }
            }
            let $discr: isize = discriminant(move $opt);
            switchInt(move $discr) {
                0_isize => break,
                1_isize => {
                    let $x: usize = copy (move $opt as Some).0;
                    let $base: *mut $T = copy (*$self).mem;
                    let $offset: isize = copy $x as isize (IntToInt);
                    let $elem_ptr: *mut $T = Offset(copy $base, copy $offset);
                    let _ = core::ptr::drop_in_place(copy $elem_ptr);
                }
            }
        }
    }
}
"#
    );
}