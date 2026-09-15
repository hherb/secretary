//! The byte-level walk `record::decode` runs first (#641) changes WHICH error a
//! rejected record reports and never WHETHER a record is accepted.
//!
//! `legacy_decode` is the pre-#641 pipeline, step for step: parse, rule-4 walk
//! over the parsed tree, interpret, re-encode and compare. Why the claim holds:
//! a legacy accept requires the input to be byte-identical to this crate's
//! canonical re-encoding, which never emits a tag, a float, `undefined`, an
//! indefinite item or invalid UTF-8, so no input the walk rejects was ever
//! accepted. The property test checks that argument rather than trusting it.

use proptest::prelude::*;

use crate::cbor::{from_secret_reader, SecretValueTree};
use crate::vault::canonical::reject_floats_and_tags;
use crate::vault::record::{decode, decode_value, encode, Record, RecordError};

/// A canonical record every mutation starts from.
const LOGIN_RECORD: &[u8] = include_bytes!("../../fuzz/seeds/record/login.cbor");
/// Mutations per case: few enough that most inputs stay near a valid record,
/// where acceptance can actually differ.
const MAX_MUTATIONS: usize = 3;
/// More cases than proptest's default 256: each is cheap, and the inputs that
/// could tell the pipelines apart are rare.
const PROPTEST_CASES: u32 = 4096;

// RFC 8949 bytes for the three measured ciborium leniencies.
const MAP_1: u8 = 0xa1;
const UNDEFINED: u8 = 0xf7;
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
        prop_assert_eq!(legacy_decode(&bytes).is_ok(), decode(&bytes).is_ok());
    }
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
}

/// A UTF-8 sequence split across two chunks of an indefinite-length map KEY
/// is malformed at the byte level (RFC 8949 §3.2.3), not merely non-canonical
/// -- and ciborium agrees, unlike the three leniencies pinned above. Both
/// pipelines report `CborDecode`, from the SAME cause: measured pre-#641,
/// ciborium itself rejects these bytes as `Syntax` at offset 2, so
/// `legacy_decode`'s `from_secret_reader` call fails before its walk or
/// re-encode ever runs, and `decode`'s byte walk (#641) fails at the same
/// offset for the same reason.
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
    assert!(matches!(
        legacy_decode(&split_utf8_key),
        Err(RecordError::CborDecode(_))
    ));
    assert!(matches!(
        decode(&split_utf8_key),
        Err(RecordError::CborDecode(_))
    ));
}
