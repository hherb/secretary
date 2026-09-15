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
const SIMPLE_16: u8 = 0xf0;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;
const UNDEFINED: u8 = 0xf7;
const SIMPLE_ONE_BYTE: u8 = 0xf8;
const FLOAT16: u8 = 0xf9;
const BREAK_BYTE: u8 = 0xff;
const ASCII_A: u8 = b'a';
const INVALID_UTF8: u8 = 0xff;
const UTF8_TWO_BYTE_LEAD: u8 = 0xc3;
const UTF8_CONTINUATION: u8 = 0xa9;
/// A one-byte simple-value argument: 32 is the first value RFC 8949 allows in that form.
const SIMPLE_ARG_32: u8 = 0x20;
/// Deeper than ciborium's recursion limit (256), which the walk does not share.
const DEPTH_BEYOND_CIBORIUM_LIMIT: usize = 300;

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
}

#[test]
fn reserved_additional_info_and_misplaced_indefinite_forms_are_syntax_faults() {
    assert_eq!(walk_first_item(&[RESERVED_AI_28]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[UINT_INDEFINITE]), Err(syntax(0)));
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
}

#[test]
fn a_float_is_rule_four() {
    assert_eq!(
        walk_first_item(&[FLOAT16, UINT_0, UINT_0]),
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
