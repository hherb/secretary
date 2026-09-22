//! Rust twins of conformance Section RTS check 5, `contact_card` rows (task
//! 10): two-fault card bodies whose reported error depends on
//! [`ContactCard::from_canonical_cbor`]'s phase order.
//!
//! **Parity, not spec.** crypto-design §6 fixes no report order between
//! these three precedence claims (#618's lesson, restated for the card).
//! These bodies pin the order `from_canonical_cbor` shares with
//! `py_decode_contact_card`: the byte walk, the top-level map, each entry's
//! key type / unknown-key / value check in wire order, the deferred
//! `card_version != 1` comparison, missing required keys, canonical form
//! last. Section RTS's `_card_ordering_cases` pins Python's side; this
//! module pins Rust's, so a reorder on either side reds a test in its own
//! language rather than surfacing only in a local full-corpus replay.
//!
//! **Each test proves its body discriminates.** A two-fault body pins an
//! order only if its faults, each alone, name DIFFERENT errors. Every test
//! therefore asserts both single-fault controls beside the two-fault body.
//!
//! Bodies are built from the committed `with_sigs.cbor` seed by value
//! surgery, or from minimal hand-built maps; none needs key material of its
//! own — [`ContactCard::from_canonical_cbor`] never verifies a signature.

use ciborium::Value;

use crate::identity::card::{CardError, ContactCard};

/// A canonical card every surgery starts from.
const WITH_SIGS: &[u8] = include_bytes!("../../fuzz/seeds/contact_card/with_sigs.cbor");

/// A byte appended past the last committed byte of a canonical body.
const TRAILING_BYTE: u8 = 0x00;

const KEY_CARD_VERSION: &str = "card_version";
const KEY_DISPLAY_NAME: &str = "display_name";
const KEY_CREATED_AT: &str = "created_at";

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("encode a test value");
    out
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn with_sigs_entries() -> Vec<(Value, Value)> {
    match ciborium::de::from_reader(WITH_SIGS).expect("with_sigs.cbor parses") {
        Value::Map(entries) => entries,
        other => panic!("with_sigs.cbor is not a map: {other:?}"),
    }
}

fn is_key(entry: &(Value, Value), key: &str) -> bool {
    matches!(&entry.0, Value::Text(k) if k == key)
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

/// The entry for `key`, immediately followed by a second copy whose value is
/// `second_value` — the only way to plant a repeat, since a `Vec<(Value,
/// Value)>` built from a map has no repeats to begin with.
fn with_key_repeated(
    entries: Vec<(Value, Value)>,
    key: &str,
    second_value: Value,
) -> Vec<(Value, Value)> {
    let at = entries
        .iter()
        .position(|e| is_key(e, key))
        .unwrap_or_else(|| panic!("no entry for key {key}"));
    let mut out = entries;
    let repeat = (out[at].0.clone(), second_value);
    out.insert(at + 1, repeat);
    out
}

fn decode(bytes: &[u8]) -> Result<ContactCard, CardError> {
    ContactCard::from_canonical_cbor(bytes)
}

#[test]
fn a_wrong_type_beside_a_card_version_the_value_check_has_not_run_reports_the_wrong_type() {
    // `card_version` sorts BEFORE `display_name` in canonical key order, so
    // this plants the type fault on a field visited LATER in the entry
    // loop than `card_version`'s own entry — proving the `!= 1` comparison
    // really is deferred to after the WHOLE loop, not merely to after
    // `card_version`'s own entry.
    let wrong_display_name = with_value(
        with_sigs_entries(),
        KEY_DISPLAY_NAME,
        Value::Integer(5.into()),
    );
    let bad_version = with_value(
        with_sigs_entries(),
        KEY_CARD_VERSION,
        Value::Integer(2.into()),
    );
    let both = with_value(
        bad_version.clone(),
        KEY_DISPLAY_NAME,
        Value::Integer(5.into()),
    );

    assert!(matches!(
        decode(&encode(&Value::Map(wrong_display_name))),
        Err(CardError::Malformed(_))
    ));
    assert!(matches!(
        decode(&encode(&Value::Map(bad_version))),
        Err(CardError::InvalidVersion)
    ));
    assert!(matches!(
        decode(&encode(&Value::Map(both))),
        Err(CardError::Malformed(_))
    ));
}

#[test]
fn a_repeated_key_whose_second_copy_is_wrong_typed_reports_the_wrong_type() {
    let both_valid = with_key_repeated(
        with_sigs_entries(),
        KEY_CREATED_AT,
        Value::Integer(0.into()),
    );
    let second_wrong_type = with_key_repeated(with_sigs_entries(), KEY_CREATED_AT, text("bad"));
    let minimal_wrong_type = vec![(text(KEY_CREATED_AT), text("bad"))];

    assert!(matches!(
        decode(&encode(&Value::Map(both_valid))),
        Err(CardError::DuplicateField {
            field: KEY_CREATED_AT
        })
    ));
    assert!(matches!(
        decode(&encode(&Value::Map(minimal_wrong_type))),
        Err(CardError::Malformed(_))
    ));
    assert!(matches!(
        decode(&encode(&Value::Map(second_wrong_type))),
        Err(CardError::Malformed(_))
    ));
}

#[test]
fn a_wrong_typed_field_beside_trailing_bytes_reports_the_wrong_type() {
    let wrong_created_at = with_value(with_sigs_entries(), KEY_CREATED_AT, text("bad"));
    let wrong_alone = encode(&Value::Map(wrong_created_at));
    let mut both = wrong_alone.clone();
    both.push(TRAILING_BYTE);
    let mut trailing_alone = WITH_SIGS.to_vec();
    trailing_alone.push(TRAILING_BYTE);

    assert!(matches!(decode(&wrong_alone), Err(CardError::Malformed(_))));
    assert!(matches!(
        decode(&trailing_alone),
        Err(CardError::NonCanonicalCbor)
    ));
    assert!(matches!(decode(&both), Err(CardError::Malformed(_))));
}
