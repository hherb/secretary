//! The byte-level walk `record::decode` runs first (#641) changes WHICH error a
//! rejected record reports and never WHETHER a record is accepted.
//!
//! `legacy_decode` is the pre-#641 pipeline, step for step: parse, rule-4 walk
//! over the parsed tree, interpret, re-encode and compare. Why the claim holds:
//! a legacy accept requires the input to be byte-identical to this crate's
//! canonical re-encoding, which never emits a tag, a float, `undefined`, an
//! indefinite item or invalid UTF-8, so no input the walk rejects was ever
//! accepted. The property test checks that argument rather than trusting it.

use std::collections::BTreeMap;

use proptest::prelude::*;

use crate::cbor::{from_secret_reader, walk_first_item, CborErrorKind, CborFault, SecretValueTree};
use crate::vault::canonical::reject_floats_and_tags;
use crate::vault::record::{
    decode, decode_value, encode, Record, RecordError, RecordField, RecordFieldValue,
    RECORD_UUID_LEN,
};

/// A canonical record every mutation starts from.
const LOGIN_RECORD: &[u8] = include_bytes!("../../fuzz/seeds/record/login.cbor");
/// Mutations per case: few enough that most inputs stay near a valid record,
/// where acceptance can actually differ.
const MAX_MUTATIONS: usize = 3;
/// More cases than proptest's default 256: each is cheap, and the inputs that
/// could tell the pipelines apart are rare.
const PROPTEST_CASES: u32 = 4096;

// RFC 8949 bytes for the four measured ciborium leniencies.
const MAP_1: u8 = 0xa1;
const UNDEFINED: u8 = 0xf7;
/// Major 7, additional-info 24: the two-byte simple form.
const SIMPLE_TWO_BYTE: u8 = 0xf8;
/// Simple value 20 (`false`), which RFC 8949 §3.3 allows only in one byte.
const SIMPLE_ARG_FALSE: u8 = 0x14;
/// A byte-string head carrying nine bytes: a bignum one byte wider than u64.
const BYTES_9: u8 = 0x49;
const BIGNUM_WIDER_THAN_U64: [u8; 9] = [0x01, 0, 0, 0, 0, 0, 0, 0, 0];
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
const BYTES_1: u8 = 0x41;
const TEXT_1: u8 = 0x61;
const TEXT_INDEFINITE: u8 = 0x7f;
const BREAK: u8 = 0xff;
const UINT_0: u8 = 0x00;
const ASCII_A: u8 = b'a';
// A UTF-8 sequence split across two indefinite-length chunks (RFC 8949
// §3.2.3 makes each chunk a text string in its own right).
const UTF8_TWO_BYTE_LEAD: u8 = 0xc3;
const UTF8_CONTINUATION: u8 = 0xa9;
/// Where the first chunk's head sits in that key, after the map and
/// indefinite-string heads: the offset both pipelines report.
const SPLIT_UTF8_CHUNK_AT: usize = 2;

fn legacy_decode(bytes: &[u8]) -> Result<Record, RecordError> {
    let parsed = from_secret_reader(bytes).map_err(RecordError::CborDecode)?;
    let parsed = SecretValueTree::new(parsed);
    reject_floats_and_tags(parsed.as_value(), "<root>")?;
    let record = decode_value(parsed.as_value())?;
    let re_encoded = encode(&record)?;
    if re_encoded.expose() != bytes {
        return Err(RecordError::NonCanonicalEncoding);
    }
    Ok(record)
}

#[derive(Debug, Clone)]
enum Mutation {
    Overwrite { at: usize, byte: u8 },
    Insert { at: usize, byte: u8 },
    Truncate { len: usize },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Overwrite { at, byte }),
        (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Insert { at, byte }),
        any::<usize>().prop_map(|len| Mutation::Truncate { len }),
    ]
}

fn apply(bytes: &mut Vec<u8>, mutation: &Mutation) {
    match *mutation {
        Mutation::Overwrite { at, byte } if !bytes.is_empty() => {
            let i = at % bytes.len();
            bytes[i] = byte;
        }
        Mutation::Insert { at, byte } => {
            let i = at % (bytes.len() + 1);
            bytes.insert(i, byte);
        }
        Mutation::Truncate { len } => bytes.truncate(len % (bytes.len() + 1)),
        Mutation::Overwrite { .. } => {}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    #[test]
    fn the_walk_never_changes_whether_a_record_is_accepted(
        mutations in proptest::collection::vec(mutation(), 0..=MAX_MUTATIONS)
    ) {
        let mut bytes = LOGIN_RECORD.to_vec();
        for m in &mutations {
            apply(&mut bytes, m);
        }
        let accepted = legacy_decode(&bytes).is_ok();
        prop_assert_eq!(accepted, decode(&bytes).is_ok());
        // An accepted record is exactly one CBOR item, so the walk must end
        // at its last byte. `decode` discards that offset, so without this a
        // walk that lost count could return `Ok` early and pass (#673 review).
        if accepted {
            prop_assert_eq!(walk_first_item(&bytes), Ok(bytes.len()));
        }
    }
}

// Argument widths a canonical encoder emits for the values below.
/// Needs a one-byte argument (24..=255).
const ONE_BYTE_ARG_VALUE: u64 = 200;
/// Needs a four-byte argument (65,536..=u32::MAX).
const FOUR_BYTE_ARG_VALUE: u64 = 100_000;
/// Needs an eight-byte argument (above u32::MAX).
const EIGHT_BYTE_ARG_VALUE: u64 = 1_714_060_800_002;
/// A byte-string length needing a four-byte argument.
const FOUR_BYTE_LENGTH: usize = 70_000;
/// A text length needing a two-byte argument.
const TWO_BYTE_LENGTH: usize = 300;
/// Any byte works: the length heads are under test, not the payload.
const FILL: u8 = 0x5a;

/// `login.cbor` uses only one- and eight-byte integer heads and short
/// strings, so the property test above never produces a four-byte head.
/// This record carries every argument width. It must still be accepted, and
/// walked to its last byte, by both pipelines (PR #673 review: a walk that
/// read four-byte arguments as three passed every test in the crate).
#[test]
fn a_record_using_every_argument_width_is_accepted_and_walked_to_its_end() {
    let device_uuid = [0x11; RECORD_UUID_LEN];
    let mut fields = BTreeMap::new();
    fields.insert(
        "blob".to_string(),
        RecordField {
            value: RecordFieldValue::Bytes(vec![FILL; FOUR_BYTE_LENGTH].into()),
            last_mod: ONE_BYTE_ARG_VALUE,
            device_uuid,
            unknown: BTreeMap::new(),
        },
    );
    fields.insert(
        "note".to_string(),
        RecordField {
            value: RecordFieldValue::Text("n".repeat(TWO_BYTE_LENGTH).into()),
            last_mod: FOUR_BYTE_ARG_VALUE,
            device_uuid,
            unknown: BTreeMap::new(),
        },
    );
    let record = Record {
        record_uuid: [0x22; RECORD_UUID_LEN],
        record_type: "login".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: FOUR_BYTE_ARG_VALUE,
        last_mod_ms: EIGHT_BYTE_ARG_VALUE,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    };
    let bytes = encode(&record).expect("encode");
    let bytes = bytes.expose();
    assert_eq!(walk_first_item(bytes), Ok(bytes.len()));
    assert!(legacy_decode(bytes).is_ok());
    assert!(decode(bytes).is_ok());
}

#[test]
fn the_unmutated_seed_is_accepted_by_both() {
    assert!(legacy_decode(LOGIN_RECORD).is_ok());
    assert!(decode(LOGIN_RECORD).is_ok());
}

/// Each measured leniency is rejected by BOTH pipelines, and only the walk
/// names what the bytes actually are. The `legacy` arms pin ciborium's
/// behaviour as measured on 2026-09-15; if a ciborium bump changes one, this
/// test says so before the differential replay does.
#[test]
fn each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk() {
    let undefined_key = [MAP_1, UNDEFINED, UNDEFINED];
    assert!(matches!(
        legacy_decode(&undefined_key),
        Err(RecordError::NonTextKey)
    ));
    assert!(matches!(
        decode(&undefined_key),
        Err(RecordError::CborDecode(_))
    ));

    let bignum = [TAG_BIGNUM_POSITIVE, BYTES_1, ASCII_A];
    assert!(matches!(legacy_decode(&bignum), Err(RecordError::NotAMap)));
    assert!(matches!(decode(&bignum), Err(RecordError::TagRejected)));

    let nested_chunk_key = [
        MAP_1,
        TEXT_INDEFINITE,
        TEXT_INDEFINITE,
        TEXT_1,
        ASCII_A,
        BREAK,
        BREAK,
        UINT_0,
    ];
    assert!(matches!(
        legacy_decode(&nested_chunk_key),
        Err(RecordError::MissingField { .. })
    ));
    assert!(matches!(
        decode(&nested_chunk_key),
        Err(RecordError::CborDecode(_))
    ));

    // The fourth, missed by the first cut (PR #673 review): ciborium reads the
    // two-byte simple form `f8 14` as `false`, though RFC 8949 §3.3 makes that
    // encoding not well-formed.
    let two_byte_simple_key = [MAP_1, SIMPLE_TWO_BYTE, SIMPLE_ARG_FALSE, UINT_0];
    assert!(matches!(
        legacy_decode(&two_byte_simple_key),
        Err(RecordError::NonTextKey)
    ));
    assert!(matches!(
        decode(&two_byte_simple_key),
        Err(RecordError::CborDecode(_))
    ));
}

/// The "never changes acceptance" argument needs ciborium to keep any bignum
/// wider than 64 bits as a `Value::Tag`. If a bump let `Integer` hold one,
/// its re-encode would emit the same tag, a record carrying it in an unknown
/// subtree would pass the legacy pipeline, and the walk would reject it. The
/// property test cannot generate that input, so it is pinned here: ciborium
/// 0.2.2 keeps the tag, so both pipelines reject it as rule 4 (PR #673 review).
#[test]
fn a_bignum_wider_than_64_bits_stays_a_tag_in_ciborium() {
    let mut body = vec![MAP_1, TEXT_1, ASCII_A, TAG_BIGNUM_POSITIVE, BYTES_9];
    body.extend_from_slice(&BIGNUM_WIDER_THAN_U64);
    assert!(matches!(legacy_decode(&body), Err(RecordError::TagRejected)));
    assert!(matches!(decode(&body), Err(RecordError::TagRejected)));
}

/// A UTF-8 sequence split across two chunks of an indefinite-length map KEY
/// is malformed at the byte level (RFC 8949 §3.2.3), not merely non-canonical
/// -- and ciborium agrees, unlike the three leniencies pinned above. Both
/// pipelines report the SAME `CborFault`, and this test asserts it exactly:
/// ciborium itself rejects these bytes as `Syntax` at offset 2 (the first
/// chunk's head), so `legacy_decode`'s `from_secret_reader` call fails before
/// its walk or re-encode ever runs, and `decode`'s byte walk (#641) fails
/// with the same kind at the same offset.
#[test]
fn a_utf8_sequence_split_across_chunks_is_rejected_by_both() {
    let split_utf8_key = [
        MAP_1,
        TEXT_INDEFINITE,
        TEXT_1,
        UTF8_TWO_BYTE_LEAD,
        TEXT_1,
        UTF8_CONTINUATION,
        BREAK,
        UINT_0,
    ];
    let same_fault = CborFault {
        kind: CborErrorKind::Syntax,
        offset: Some(SPLIT_UTF8_CHUNK_AT),
    };
    assert!(matches!(
        legacy_decode(&split_utf8_key),
        Err(RecordError::CborDecode(fault)) if fault == same_fault
    ));
    assert!(matches!(
        decode(&split_utf8_key),
        Err(RecordError::CborDecode(fault)) if fault == same_fault
    ));
}
