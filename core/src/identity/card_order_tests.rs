//! Rust twins of conformance Section RTS check 5, `contact_card` rows (task
//! 10): two-fault card bodies whose reported error depends on
//! [`ContactCard::from_canonical_cbor`]'s phase order.
//!
//! **Parity, not spec.** crypto-design §6 fixes no report order between
//! these seven precedence claims (#618's lesson, restated for the card).
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
//! therefore asserts a single-fault control beside the two-fault body.
//!
//! **The last four rows (fix round 1) have only ONE control, not two, and
//! that is structural rather than an oversight.** `undefined`,
//! `depth_257`, `float` and `bignum_narrow` were committed single-fault
//! seeds until this round found each also carries a competing,
//! order-dependent verdict — but the card has **no** forward-compat
//! `unknown` bag, so a simple-value / depth / rule-4 fault can only ever be
//! planted inside a KNOWN field's value, where a per-field type check
//! always also applies. There is therefore no way to build a standalone
//! body that reaches the walk's own verdict (`malformed_cbor` or
//! `rule4_tag_or_float`) with nothing else to compete against it — every
//! one of this file's other single-fault `#[test]`s and every committed
//! `malformed_cbor`/`rule4_tag_or_float` seed already IS that attempt, for
//! every shape where it is possible (`two_byte_simple` and
//! `nested_indefinite_chunk` stay committed precisely because, measured
//! directly, each is malformed at the raw parse layer with no competing
//! reading to order against).
//!
//! `bignum_wide` is NOT in that set, and this doc said it was (#698 review).
//! A bignum tag over a definite 9-byte string is well-formed CBOR: both
//! parsers accept it, `ciborium` keeping a `Value::Tag` and `cbor2` folding
//! it to an `int`. It has two competing readings and they DIFFER by
//! language -- with the walk disabled Rust reaches `take_u64` and says
//! `wrong_type`, Python re-encodes and says `non_canonical_unclassified`.
//! It stays committed as a PARITY-ORDER row of the same class `record`'s
//! three `rule4_tag_or_float__*` seeds already are, accepted under #668,
//! not as a row without a competing reading. The sibling doc in
//! `core/tests/rule_token_seeds_helpers/contact_card.rs` scopes the
//! raw-parse-layer claim to two files and is the one that was right.
//!
//! Each of the four rows below therefore asserts the two-fault body against
//! the walk-first verdict, and ONE control demonstrating the competing
//! verdict alone.
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
const KEY_X25519_PK: &str = "x25519_pk";

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

// ---------------------------------------------------------------------------
// Raw-byte splicing, needed only below: `ciborium::Value` has no constructor
// for RFC 8949's simple value 23 (`undefined`) or for a non-shortest-form
// integer head — its serializer always emits shortest form. Mirrors
// `rule_token_seeds_helpers::contact_card`'s own raw splice helpers.
// ---------------------------------------------------------------------------

type RawEntry = (Vec<u8>, Vec<u8>);

fn raw_entries(bytes: &[u8]) -> Vec<RawEntry> {
    match ciborium::de::from_reader(bytes).expect("a seed map parses") {
        Value::Map(pairs) => pairs.iter().map(|(k, v)| (encode(k), encode(v))).collect(),
        other => panic!("not a map: {other:?}"),
    }
}

fn raw_map(entries: &[RawEntry]) -> Vec<u8> {
    assert!(
        entries.len() < 24,
        "stays under a one-byte map head's 24-entry limit"
    );
    let mut out = vec![0xa0 | u8::try_from(entries.len()).expect("checked above")];
    for (k, v) in entries {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

fn raw_with_value(entries: &[RawEntry], key: &str, value: Vec<u8>) -> Vec<RawEntry> {
    let wanted = encode(&text(key));
    entries
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                if *k == wanted {
                    value.clone()
                } else {
                    v.clone()
                },
            )
        })
        .collect()
}

/// `levels` nested one-element arrays wrapping the integer `0`.
fn nested_array(levels: usize) -> Value {
    let mut v = Value::Integer(0.into());
    for _ in 0..levels {
        v = Value::Array(vec![v]);
    }
    v
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
fn a_wrong_card_version_beside_a_missing_required_key_reports_the_version() {
    // The OTHER branch of the deferral above: a missing key rather than a
    // wrong-typed one. `parse_card_map` requires and compares
    // `card_version` before it reports any missing field, so the version
    // wins; Python defers its own comparison to the same position, ahead of
    // `first_missing_key_in_sorted_order`. Reverse either side and the pair
    // reads `unsupported_version` against `missing_field` — a live
    // divergence on a strictly compared target, and until #698 the order
    // was implemented in both languages and pinned in neither.
    let missing_only: Vec<(Value, Value)> = with_sigs_entries()
        .into_iter()
        .filter(|e| !is_key(e, KEY_X25519_PK))
        .collect();
    let bad_version_only = with_value(
        with_sigs_entries(),
        KEY_CARD_VERSION,
        Value::Integer(2.into()),
    );
    let both: Vec<(Value, Value)> = bad_version_only
        .clone()
        .into_iter()
        .filter(|e| !is_key(e, KEY_X25519_PK))
        .collect();

    // Each control demonstrates its own verdict alone ...
    assert!(matches!(
        decode(&encode(&Value::Map(missing_only))),
        Err(CardError::MissingField { .. })
    ));
    assert!(matches!(
        decode(&encode(&Value::Map(bad_version_only))),
        Err(CardError::InvalidVersion)
    ));
    // ... and the two-fault body reports the version, not the missing key.
    assert!(matches!(
        decode(&encode(&Value::Map(both))),
        Err(CardError::InvalidVersion)
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
    // Fix round 1 (MINOR 5): reuse the same clean, single-fault wrong-type
    // control the next test builds, rather than a one-entry map that ALSO
    // carries nine missing required fields.
    let wrong_type_alone = with_value(with_sigs_entries(), KEY_CREATED_AT, text("bad"));

    assert!(matches!(
        decode(&encode(&Value::Map(both_valid))),
        Err(CardError::DuplicateField {
            field: KEY_CREATED_AT
        })
    ));
    assert!(matches!(
        decode(&encode(&Value::Map(wrong_type_alone))),
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

/// Fix round 1 (IMPORTANT 1): moved off the committed corpus. `undefined`
/// (`0xf7`) is well-formed nowhere in this format, so the walk rejects it —
/// but `ciborium` itself parses it to `Value::Null` (measured), which is
/// exactly what a per-field type check alone would then reject as
/// `wrong_type`. See the module doc for why the walk's OWN verdict has no
/// standalone control here.
#[test]
fn an_undefined_created_at_reports_malformed_cbor() {
    let both = raw_map(&raw_with_value(
        &raw_entries(WITH_SIGS),
        KEY_CREATED_AT,
        vec![0xF7],
    ));
    // `null` (well-formed; one of the walk's three sanctioned simple
    // values) is still not an integer.
    let wrong_type_alone = encode(&Value::Map(with_value(
        with_sigs_entries(),
        KEY_CREATED_AT,
        Value::Null,
    )));

    assert!(matches!(
        decode(&wrong_type_alone),
        Err(CardError::Malformed(_))
    ));
    assert!(matches!(decode(&both), Err(CardError::CborDecode(_))));
}

/// Fix round 1 (IMPORTANT 1): moved off the committed corpus. 256 nested
/// one-element arrays around `0` sit `created_at` at nesting level 257 —
/// one past crypto-design §6.2 rule 6's limit, which the walk rejects. **This
/// row alone does not prove the walk is what rejects it**: `ciborium` 0.2.2
/// has its own built-in recursion limit, numerically 256, so a 257-level
/// body is rejected by `ciborium`'s own parse whether or not the walk runs
/// first (#695) — measured by disabling the walk's call, which does not red
/// this test. An earlier version of this comment claimed the opposite,
/// that `ciborium` "parses arbitrarily deep arrays fine (measured to at
/// least 257 levels)"; that measurement was never taken and is false.
#[test]
fn an_excessively_deep_created_at_reports_malformed_cbor() {
    let both = encode(&Value::Map(with_value(
        with_sigs_entries(),
        KEY_CREATED_AT,
        nested_array(256),
    )));
    // An empty array is well within the depth limit and still not an
    // integer.
    let wrong_type_alone = encode(&Value::Map(with_value(
        with_sigs_entries(),
        KEY_CREATED_AT,
        Value::Array(vec![]),
    )));

    assert!(matches!(
        decode(&wrong_type_alone),
        Err(CardError::Malformed(_))
    ));
    assert!(matches!(decode(&both), Err(CardError::CborDecode(_))));
}

/// Fix round 1 (IMPORTANT 1): moved off the committed corpus. A float
/// anywhere in the body is crypto-design §6.2 rule 4, which the walk
/// rejects before interpretation — but `ciborium` parses a float16 fine
/// (`Value::Float`), which a per-field type check alone would then reject
/// as `wrong_type`.
#[test]
fn a_float_created_at_reports_rule_four() {
    let both = encode(&Value::Map(with_value(
        with_sigs_entries(),
        KEY_CREATED_AT,
        Value::Float(0.0),
    )));
    let wrong_type_alone = encode(&Value::Map(with_value(
        with_sigs_entries(),
        KEY_CREATED_AT,
        Value::Null,
    )));

    assert!(matches!(
        decode(&wrong_type_alone),
        Err(CardError::Malformed(_))
    ));
    assert!(matches!(
        decode(&both),
        Err(CardError::FloatRejected { .. })
    ));
}

/// Fix round 1 (IMPORTANT 1): moved off the committed corpus. A bignum tag
/// over a definite byte string of 1 byte is also rule 4, which the walk
/// rejects — but within that width `ciborium` folds it to a plain integer
/// (measured), which passes every type check and is caught only by the
/// final canonical-form re-encode, the same way a non-shortest-form integer
/// is.
#[test]
fn a_narrow_bignum_created_at_reports_rule_four() {
    let both = encode(&Value::Map(with_value(
        with_sigs_entries(),
        KEY_CREATED_AT,
        Value::Tag(2, Box::new(Value::Bytes(vec![1]))),
    )));
    // Non-shortest form: still parses to the plain integer 5, passing every
    // type check, and caught only by the final re-encode comparison.
    // `ciborium::Value`'s serializer always emits shortest form, so this
    // needs a raw splice rather than a `Value` literal.
    let non_canonical_alone = raw_map(&raw_with_value(
        &raw_entries(WITH_SIGS),
        KEY_CREATED_AT,
        vec![0x18, 0x05],
    ));

    assert!(matches!(
        decode(&non_canonical_alone),
        Err(CardError::NonCanonicalCbor)
    ));
    assert!(matches!(decode(&both), Err(CardError::TagRejected)));
}
