//! Unit coverage for the byte-level walk. Python's twin is conformance
//! Section WF; the two are kept case for case.

use super::{walk_first_item, WalkFault};
use crate::cbor::{CborErrorKind, CborFault};

// RFC 8949 initial bytes, named so each case reads as the shape it plants.
const UINT_0: u8 = 0x00;
const UINT_INDEFINITE: u8 = 0x1f;
const RESERVED_AI_28: u8 = 0x1c;
const BYTES_1: u8 = 0x41;
const BYTES_FOUR_BYTE_LENGTH: u8 = 0x5a;
const BYTES_EIGHT_BYTE_LENGTH: u8 = 0x5b;
const BYTES_INDEFINITE: u8 = 0x5f;
const TEXT_1: u8 = 0x61;
const TEXT_3: u8 = 0x63;
const TEXT_INDEFINITE: u8 = 0x7f;
const ARRAY_1: u8 = 0x81;
const ARRAY_2: u8 = 0x82;
const ARRAY_INDEFINITE: u8 = 0x9f;
const MAP_1: u8 = 0xa1;
const MAP_INDEFINITE: u8 = 0xbf;
const TAG_1: u8 = 0xc1;
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
/// Tag 3 (negative bignum): a second tag number, to prove rule 4 isn't
/// pinned to one tag rather than "any tag".
const TAG_3_BIGNUM_NEGATIVE: u8 = 0xc3;
const SIMPLE_16: u8 = 0xf0;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;
const UNDEFINED: u8 = 0xf7;
const SIMPLE_ONE_BYTE: u8 = 0xf8;
const FLOAT16: u8 = 0xf9;
const FLOAT32: u8 = 0xfa;
const FLOAT64: u8 = 0xfb;
const BREAK_BYTE: u8 = 0xff;
const ASCII_A: u8 = b'a';
const INVALID_UTF8: u8 = 0xff;
const UTF8_TWO_BYTE_LEAD: u8 = 0xc3;
const UTF8_CONTINUATION: u8 = 0xa9;
/// A one-byte simple-value argument: 32 is the first value RFC 8949 allows in that form.
const SIMPLE_ARG_32: u8 = 0x20;
/// Deeper than ciborium's recursion limit (256), which the walk does not share.
const DEPTH_BEYOND_CIBORIUM_LIMIT: usize = 300;
/// Major 1 (negative int), additional-info 31: RFC 8949 §3.2 permits the
/// indefinite form only for strings, arrays, maps and (as the break code)
/// major 7 -- never for an integer.
const NINT_INDEFINITE: u8 = 0x3f;
/// Major 6 (tag), additional-info 31: same rule, and a tag's indefinite
/// form must be rejected as malformed rather than read as `WalkFault::Tag`.
const TAG_INDEFINITE: u8 = 0xdf;
/// Reserved additional-info values 29 and 30 (28 already covered above).
const RESERVED_AI_29: u8 = 0x1d;
const RESERVED_AI_30: u8 = 0x1e;
/// Any byte works here: these tests check the argument-length HEAD, not the
/// payload's content.
const FILL_BYTE: u8 = 0x00;
/// Major 2 (byte string), additional-info 25: a two-byte length argument.
const BYTES_TWO_BYTE_LENGTH: u8 = 0x59;
/// `0x0100` read big-endian is 256; a little-endian fold would misread it as 1.
const LENGTH_HIGH_BYTE: u8 = 0x01;
const LENGTH_LOW_BYTE: u8 = 0x00;
const BIG_ENDIAN_PAYLOAD_LEN: usize = 256;
/// The two-byte length head itself: one initial byte plus two argument bytes.
const BIG_ENDIAN_HEAD_LEN: usize = 3;
/// Major 0 heads carrying a one-, two-, four- and eight-byte argument.
const UINT_ONE_BYTE_ARG: u8 = 0x18;
const UINT_TWO_BYTE_ARG: u8 = 0x19;
const UINT_FOUR_BYTE_ARG: u8 = 0x1a;
const UINT_EIGHT_BYTE_ARG: u8 = 0x1b;
/// The first length a four-byte argument is needed for: one past `u16::MAX`.
const FOUR_BYTE_PAYLOAD_LEN: u32 = 65_536;

fn io(offset: usize) -> WalkFault {
    WalkFault::Malformed(CborFault {
        kind: CborErrorKind::Io,
        offset: Some(offset),
    })
}

fn syntax(offset: usize) -> WalkFault {
    WalkFault::Malformed(CborFault {
        kind: CborErrorKind::Syntax,
        offset: Some(offset),
    })
}

#[test]
fn a_well_formed_item_returns_the_offset_one_past_it() {
    assert_eq!(walk_first_item(&[UINT_0]), Ok(1));
    for simple in [FALSE, TRUE, NULL] {
        assert_eq!(walk_first_item(&[simple]), Ok(1));
    }
    assert_eq!(walk_first_item(&[TEXT_1, ASCII_A]), Ok(2));
    assert_eq!(walk_first_item(&[MAP_1, TEXT_1, ASCII_A, UINT_0]), Ok(4));
    assert_eq!(
        walk_first_item(&[MAP_INDEFINITE, TEXT_1, ASCII_A, UINT_0, BREAK_BYTE]),
        Ok(5)
    );
    assert_eq!(
        walk_first_item(&[TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK_BYTE]),
        Ok(4)
    );
    // Byte-string chunks too, and a definite container closing inside an
    // indefinite one before that one's break (PR #673 review).
    assert_eq!(
        walk_first_item(&[BYTES_INDEFINITE, BYTES_1, ASCII_A, BREAK_BYTE]),
        Ok(4)
    );
    assert_eq!(
        walk_first_item(&[ARRAY_INDEFINITE, ARRAY_1, UINT_0, BREAK_BYTE]),
        Ok(4)
    );
}

#[test]
fn only_the_first_item_is_walked() {
    assert_eq!(walk_first_item(&[UINT_0, UNDEFINED]), Ok(1));
}

#[test]
fn running_out_of_input_is_an_io_fault() {
    assert_eq!(walk_first_item(&[]), Err(io(0)));
    assert_eq!(walk_first_item(&[TEXT_3, ASCII_A]), Err(io(0)));
    assert_eq!(walk_first_item(&[MAP_1, TEXT_1]), Err(io(1)));
    assert_eq!(walk_first_item(&[ARRAY_INDEFINITE, UINT_0]), Err(io(2)));
    assert_eq!(walk_first_item(&[FLOAT16, UINT_0]), Err(io(0)));
    let mut overrun = vec![BYTES_FOUR_BYTE_LENGTH];
    overrun.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(walk_first_item(&overrun), Err(io(0)));
    // An eight-byte length takes `payload_end`'s `usize::try_from` and
    // `checked_add` path, which a four-byte one cannot reach on 64-bit.
    let mut overrun = vec![BYTES_EIGHT_BYTE_LENGTH];
    overrun.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(walk_first_item(&overrun), Err(io(0)));
}

#[test]
fn reserved_additional_info_and_misplaced_indefinite_forms_are_syntax_faults() {
    assert_eq!(walk_first_item(&[RESERVED_AI_28]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[RESERVED_AI_29]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[RESERVED_AI_30]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[UINT_INDEFINITE]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[NINT_INDEFINITE]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[TAG_INDEFINITE]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[BREAK_BYTE]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[ARRAY_1, BREAK_BYTE]), Err(syntax(1)));
}

#[test]
fn undefined_and_unassigned_simple_values_are_malformed() {
    assert_eq!(walk_first_item(&[UNDEFINED]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[SIMPLE_16]), Err(syntax(0)));
    assert_eq!(
        walk_first_item(&[SIMPLE_ONE_BYTE, SIMPLE_ARG_32]),
        Err(syntax(0))
    );
}

#[test]
fn a_nested_indefinite_chunk_is_malformed() {
    let nested = [
        TEXT_INDEFINITE,
        TEXT_INDEFINITE,
        TEXT_1,
        ASCII_A,
        BREAK_BYTE,
        BREAK_BYTE,
    ];
    assert_eq!(walk_first_item(&nested), Err(syntax(1)));
}

#[test]
fn a_chunk_of_another_major_type_is_malformed() {
    let mixed = [TEXT_INDEFINITE, BYTES_1, ASCII_A, BREAK_BYTE];
    assert_eq!(walk_first_item(&mixed), Err(syntax(1)));
}

#[test]
fn invalid_utf8_is_malformed_in_a_string_and_in_a_chunk() {
    assert_eq!(walk_first_item(&[TEXT_1, INVALID_UTF8]), Err(syntax(0)));
    let chunked = [TEXT_INDEFINITE, TEXT_1, INVALID_UTF8, BREAK_BYTE];
    assert_eq!(walk_first_item(&chunked), Err(syntax(1)));
}

/// RFC 8949 §3.2.3 makes each chunk a text string in its own right, so a
/// sequence split across two chunks is invalid. ciborium agrees: measured
/// on 2026-09-15, it rejects the same bytes as `Syntax` at the first chunk.
#[test]
fn a_utf8_sequence_split_across_chunks_is_malformed() {
    let split = [
        TEXT_INDEFINITE,
        TEXT_1,
        UTF8_TWO_BYTE_LEAD,
        TEXT_1,
        UTF8_CONTINUATION,
        BREAK_BYTE,
    ];
    assert_eq!(walk_first_item(&split), Err(syntax(1)));
}

#[test]
fn a_tag_of_any_number_is_rule_four() {
    assert_eq!(
        walk_first_item(&[TAG_1, UINT_0]),
        Err(WalkFault::Tag { offset: 0 })
    );
    assert_eq!(
        walk_first_item(&[TAG_BIGNUM_POSITIVE, BYTES_1, ASCII_A]),
        Err(WalkFault::Tag { offset: 0 })
    );
    assert_eq!(
        walk_first_item(&[TAG_3_BIGNUM_NEGATIVE, BYTES_1, ASCII_A]),
        Err(WalkFault::Tag { offset: 0 })
    );
}

#[test]
fn a_float_is_rule_four() {
    assert_eq!(
        walk_first_item(&[FLOAT16, UINT_0, UINT_0]),
        Err(WalkFault::Float { offset: 0 })
    );
    let float32 = [FLOAT32, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE];
    assert_eq!(
        walk_first_item(&float32),
        Err(WalkFault::Float { offset: 0 })
    );
    let float64 = [
        FLOAT64, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE,
        FILL_BYTE,
    ];
    assert_eq!(
        walk_first_item(&float64),
        Err(WalkFault::Float { offset: 0 })
    );
}

#[test]
fn well_formedness_outranks_rule_four_anywhere_in_the_item() {
    assert_eq!(
        walk_first_item(&[ARRAY_2, TAG_1, UINT_0, UNDEFINED]),
        Err(syntax(3))
    );
    assert_eq!(
        walk_first_item(&[ARRAY_2, UNDEFINED, TAG_1, UINT_0]),
        Err(syntax(1))
    );
}

#[test]
fn the_first_rule_four_fault_is_the_one_reported() {
    let both = [ARRAY_2, FLOAT16, UINT_0, UINT_0, TAG_1, UINT_0];
    assert_eq!(walk_first_item(&both), Err(WalkFault::Float { offset: 1 }));
}

#[test]
fn an_indefinite_map_cannot_end_between_a_key_and_its_value() {
    let half = [MAP_INDEFINITE, TEXT_1, ASCII_A, BREAK_BYTE];
    assert_eq!(walk_first_item(&half), Err(syntax(3)));
}

#[test]
fn nesting_has_no_depth_cap_of_its_own() {
    let mut deep = vec![ARRAY_1; DEPTH_BEYOND_CIBORIUM_LIMIT];
    deep.push(UINT_0);
    assert_eq!(walk_first_item(&deep), Ok(DEPTH_BEYOND_CIBORIUM_LIMIT + 1));
}

/// `read_head` folds a multi-byte argument big-endian
/// (`(acc << 8) | byte`); a little-endian fold would read `0x01 0x00` as 1
/// rather than 256 and return `Ok(4)`, ending the item one payload byte in,
/// where the exactly-sized payload ends it at 259.
#[test]
fn a_two_byte_length_argument_is_read_big_endian() {
    let mut body = vec![BYTES_TWO_BYTE_LENGTH, LENGTH_HIGH_BYTE, LENGTH_LOW_BYTE];
    body.extend(std::iter::repeat_n(FILL_BYTE, BIG_ENDIAN_PAYLOAD_LEN));
    assert_eq!(
        walk_first_item(&body),
        Ok(BIG_ENDIAN_HEAD_LEN + BIG_ENDIAN_PAYLOAD_LEN)
    );
}

/// Every argument width consumes exactly its own bytes. Each integer sits in
/// a two-item array ahead of a one-byte item, so a head read one byte short
/// ends the array early and one read a byte long runs out of input. Until
/// the PR #673 review only the two-byte width had a case, and
/// `AI_FOUR_BYTES => 3` in `read_head` passed every test in the crate while
/// rejecting any record with a field of 64 KiB or more.
#[test]
fn each_argument_width_consumes_exactly_its_own_bytes() {
    for (head, arg_len) in [
        (UINT_ONE_BYTE_ARG, 1),
        (UINT_TWO_BYTE_ARG, 2),
        (UINT_FOUR_BYTE_ARG, 4),
        (UINT_EIGHT_BYTE_ARG, 8),
    ] {
        let mut body = vec![ARRAY_2, head];
        body.extend(std::iter::repeat_n(FILL_BYTE, arg_len));
        body.push(UINT_0);
        assert_eq!(
            walk_first_item(&body),
            Ok(body.len()),
            "argument width {arg_len}"
        );
    }
}

/// The same width as a string LENGTH, where a misread argument moves the end
/// of the payload rather than the end of an array.
#[test]
fn a_four_byte_length_argument_spans_its_whole_payload() {
    let mut body = vec![BYTES_FOUR_BYTE_LENGTH];
    body.extend_from_slice(&FOUR_BYTE_PAYLOAD_LEN.to_be_bytes());
    body.extend(std::iter::repeat_n(
        FILL_BYTE,
        usize::try_from(FOUR_BYTE_PAYLOAD_LEN).expect("fits usize"),
    ));
    assert_eq!(walk_first_item(&body), Ok(body.len()));
}
