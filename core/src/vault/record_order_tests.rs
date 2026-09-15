//! Rust twins of conformance Section RTS check 5 (#641): two-fault record
//! bodies whose reported error depends on [`decode`]'s phase order.
//!
//! **Parity, not spec.** `docs/vault-format.md` §6.3 fixes no report order
//! (#668), so no committed seed carries two faults. These bodies pin the order
//! `record::decode` shares with `conformance.py`'s `py_decode_record` by design:
//! the byte walk, the top-level map, each entry's key type, repeat and value in
//! wire order, missing required keys, canonical form last. Section RTS pins
//! Python's side; this module pins Rust's, so a reorder on either side reds a
//! test in its own language rather than surfacing only in a local full-corpus
//! replay.
//!
//! **Each test proves its body discriminates.** A two-fault body pins an order
//! only if its faults, each alone, name DIFFERENT errors. Every test therefore
//! asserts both single-fault controls beside the two-fault body. The one
//! exception is the truncated-key row, which Section RTS keeps as a regression
//! pin: ciborium's parse meets the truncation before any key is read, whatever
//! the order.
//!
//! Bodies are built from the committed `login.cbor` seed by value surgery, or
//! from named RFC 8949 bytes; none needs key material of its own.

use ciborium::Value;

use crate::cbor::{CborErrorKind, CborFault};
use crate::vault::record::{decode, RecordError};

/// A canonical record every surgery starts from.
const LOGIN_RECORD: &[u8] = include_bytes!("../../fuzz/seeds/record/login.cbor");

// RFC 8949 initial bytes, named for the shape each plants.
const UINT_0: u8 = 0x00;
const UINT_1: u8 = 0x01;
const TEXT_3: u8 = 0x63;
const ARRAY_1: u8 = 0x81;
const MAP_1: u8 = 0xa1;
const MAP_2: u8 = 0xa2;
const TAG_1: u8 = 0xc1;
const NULL: u8 = 0xf6;
/// Simple value 23: well-formed nowhere in this format.
const UNDEFINED: u8 = 0xf7;
const FLOAT16: u8 = 0xf9;
/// A text payload byte standing after a head that declared three.
const LONE_PAYLOAD_BYTE: u8 = 0xff;
const TRAILING_BYTE: u8 = 0x00;
/// Offsets the walk reports, as positions in the bodies below.
const SECOND_ITEM_AT: usize = 1;
const MAP_1_VALUE_AT: usize = 2;
const MAP_2_SECOND_KEY_AT: usize = 3;

const KEY_RECORD_UUID: &str = "record_uuid";
const KEY_RECORD_TYPE: &str = "record_type";
const KEY_LAST_MOD_MS: &str = "last_mod_ms";
/// An unknown key; an unknown value is vetted by the walk and nothing else.
const UNKNOWN_KEY: &str = "unknown_extension";
const TEXT_WHERE_BYTES_BELONG: &str = "text";

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("encode a test value");
    out
}

fn login_entries() -> Vec<(Value, Value)> {
    match ciborium::de::from_reader(LOGIN_RECORD).expect("login.cbor parses") {
        Value::Map(entries) => entries,
        other => panic!("login.cbor is not a map: {other:?}"),
    }
}

fn is_key(entry: &(Value, Value), key: &str) -> bool {
    matches!(&entry.0, Value::Text(k) if k == key)
}

fn without(entries: Vec<(Value, Value)>, key: &str) -> Vec<(Value, Value)> {
    entries.into_iter().filter(|e| !is_key(e, key)).collect()
}

fn with_value(entries: Vec<(Value, Value)>, key: &str, value: Value) -> Vec<(Value, Value)> {
    entries
        .into_iter()
        .map(|(k, v)| {
            let replace = matches!(&k, Value::Text(t) if t == key);
            (k, if replace { value.clone() } else { v })
        })
        .collect()
}

/// `login.cbor` plus an unknown key whose value is the raw bytes `raw`,
/// spliced over a `null` placeholder in the LAST position.
fn login_with_raw_unknown_value(raw: &[u8]) -> Vec<u8> {
    let mut entries = login_entries();
    entries.push((Value::Text(UNKNOWN_KEY.into()), Value::Null));
    let mut body = encode(&Value::Map(entries));
    assert_eq!(body.pop(), Some(NULL), "the placeholder is the last byte");
    body.extend_from_slice(raw);
    body
}

fn syntax_at(offset: usize) -> CborFault {
    CborFault {
        kind: CborErrorKind::Syntax,
        offset: Some(offset),
    }
}

#[test]
fn a_wrong_type_beside_a_missing_key_reports_the_wrong_type() {
    let wrong = Value::Text(TEXT_WHERE_BYTES_BELONG.into());
    let both = encode(&Value::Map(with_value(
        without(login_entries(), KEY_LAST_MOD_MS),
        KEY_RECORD_UUID,
        wrong.clone(),
    )));
    let type_alone = encode(&Value::Map(with_value(
        login_entries(),
        KEY_RECORD_UUID,
        wrong,
    )));
    let missing_alone = encode(&Value::Map(without(login_entries(), KEY_LAST_MOD_MS)));

    assert!(matches!(
        decode(&type_alone),
        Err(RecordError::WrongType {
            field: KEY_RECORD_UUID,
            ..
        })
    ));
    assert!(matches!(
        decode(&missing_alone),
        Err(RecordError::MissingField {
            field: KEY_LAST_MOD_MS
        })
    ));
    assert!(matches!(
        decode(&both),
        Err(RecordError::WrongType {
            field: KEY_RECORD_UUID,
            ..
        })
    ));
}

#[test]
fn a_repeated_key_whose_second_copy_is_a_float_reports_rule_four() {
    let record_type = encode(&Value::Text(KEY_RECORD_TYPE.into()));
    let t = encode(&Value::Text("t".into()));
    let float16_zero = [FLOAT16, UINT_0, UINT_0];
    let mut both = vec![MAP_2];
    both.extend_from_slice(&record_type);
    both.extend_from_slice(&t);
    both.extend_from_slice(&record_type);
    both.extend_from_slice(&float16_zero);

    let mut repeat_alone = vec![MAP_2];
    for part in [&record_type, &t, &record_type, &t] {
        repeat_alone.extend_from_slice(part);
    }
    let float_alone = login_with_raw_unknown_value(&float16_zero);

    assert!(matches!(
        decode(&repeat_alone),
        Err(RecordError::DuplicateKey {
            field: "<record>",
            index: 1
        })
    ));
    assert!(matches!(
        decode(&float_alone),
        Err(RecordError::FloatRejected { field: "<root>" })
    ));
    assert!(matches!(
        decode(&both),
        Err(RecordError::FloatRejected { field: "<root>" })
    ));
}

/// Section RTS's regression pin, so no single-fault controls: the walk and
/// ciborium's parse alike meet the truncated second key before any key type
/// is read, so no reordering of the later phases moves this report.
#[test]
fn a_truncated_key_behind_a_non_text_key_reports_malformed_cbor() {
    let body = [MAP_2, UINT_1, UINT_0, TEXT_3, LONE_PAYLOAD_BYTE];
    assert!(matches!(
        decode(&body),
        Err(RecordError::CborDecode(CborFault {
            kind: CborErrorKind::Io,
            offset: Some(MAP_2_SECOND_KEY_AT),
        }))
    ));
}

#[test]
fn a_schema_fault_followed_by_trailing_bytes_reports_the_schema_fault() {
    let missing_alone = encode(&Value::Map(without(login_entries(), KEY_LAST_MOD_MS)));
    let mut both = missing_alone.clone();
    both.push(TRAILING_BYTE);
    let mut trailing_alone = LOGIN_RECORD.to_vec();
    trailing_alone.push(TRAILING_BYTE);

    assert!(matches!(
        decode(&trailing_alone),
        Err(RecordError::NonCanonicalEncoding)
    ));
    assert!(matches!(
        decode(&missing_alone),
        Err(RecordError::MissingField {
            field: KEY_LAST_MOD_MS
        })
    ));
    assert!(matches!(
        decode(&both),
        Err(RecordError::MissingField {
            field: KEY_LAST_MOD_MS
        })
    ));
}

#[test]
fn a_non_map_top_level_item_holding_a_malformed_item_reports_malformed_cbor() {
    let both = [ARRAY_1, UNDEFINED];
    let not_a_map_alone = [ARRAY_1, UINT_0];
    let undefined_alone = login_with_raw_unknown_value(&[UNDEFINED]);

    assert!(matches!(
        decode(&not_a_map_alone),
        Err(RecordError::NotAMap)
    ));
    assert!(matches!(
        decode(&undefined_alone),
        Err(RecordError::CborDecode(CborFault {
            kind: CborErrorKind::Syntax,
            ..
        }))
    ));
    assert!(matches!(
        decode(&both),
        Err(RecordError::CborDecode(fault)) if fault == syntax_at(SECOND_ITEM_AT)
    ));
}

#[test]
fn a_non_text_key_whose_value_is_malformed_reports_malformed_cbor() {
    let both = [MAP_1, UINT_1, UNDEFINED];
    let non_text_key_alone = [MAP_1, UINT_1, UINT_0];

    assert!(matches!(
        decode(&non_text_key_alone),
        Err(RecordError::NonTextKey)
    ));
    assert!(matches!(
        decode(&both),
        Err(RecordError::CborDecode(fault)) if fault == syntax_at(MAP_1_VALUE_AT)
    ));
}

#[test]
fn a_tag_wrapping_an_otherwise_valid_record_map_reports_rule_four() {
    let mut both = vec![TAG_1];
    both.extend_from_slice(LOGIN_RECORD);
    let not_a_map_alone = [ARRAY_1, UINT_0];
    let tag_alone = login_with_raw_unknown_value(&[TAG_1, UINT_0]);

    assert!(decode(LOGIN_RECORD).is_ok(), "the wrapped map is valid");
    assert!(matches!(
        decode(&not_a_map_alone),
        Err(RecordError::NotAMap)
    ));
    assert!(matches!(decode(&tag_alone), Err(RecordError::TagRejected)));
    assert!(matches!(decode(&both), Err(RecordError::TagRejected)));
}
