//! Single-fault `contact_card` seeds, planted into
//! `core/fuzz/seeds/contact_card/with_sigs.cbor` (the ten §6 fields:
//! `card_version`, `contact_uuid`, `display_name`, `x25519_pk`,
//! `ml_kem_768_pk`, `ed25519_pk`, `ml_dsa_65_pk`, `created_at`,
//! `self_sig_ed`, `self_sig_pq`).
//!
//! The card has **no** forward-compat `unknown` bag — every key the §6
//! schema does not define is rejected outright — so, unlike `record` and
//! `block_file`, there is nowhere to plant a fault except inside a KNOWN
//! field's value, or by adding/removing/repeating a key. Splice helpers are
//! therefore card-specific rather than reused from
//! `record/surgery.rs`, whose helpers assume `record`'s
//! `fields`/`value` sub-map shape the card does not have.
//!
//! **Ruling (controller, task 10 pre-flight): `created_at_negative` takes
//! `wrong_type`, not `integer_out_of_range`.** `CardError` has no variant
//! `rule_token()` maps to `RuleToken::IntegerOutOfRange` —
//! `card_version`/`created_at` range and type faults alike collapse to
//! `CardError::Malformed(_)`, which `rule_tokens/card.rs`'s exhaustive match
//! sends to `RuleToken::WrongType` — so a row claiming the other token could
//! never be generated; the census in [`cases`] would panic on the very first
//! row. The shape stays a negative `created_at` (`0x20`, CBOR major 1 minor
//! 0 == -1); only its token column moved.

use ciborium::Value;

use super::SeedCase;

/// The replay target this file's rows belong to.
const TARGET: &str = "contact_card";

/// The §6 field a plant is spliced into.
const KEY_CARD_VERSION: &str = "card_version";
const KEY_DISPLAY_NAME: &str = "display_name";
const KEY_X25519_PK: &str = "x25519_pk";
const KEY_CREATED_AT: &str = "created_at";
/// A key the §6 schema does not define, so the card's own unknown-key arm
/// (`CardError::UnknownField`) is what rejects it — the ONE producer of
/// `RuleToken::UnknownField` in this crate (`token.rs`'s own doc).
const FUTURE_KEY: &str = "zz_future";

// RFC 8949 bytes planted below, named for what they mean in context.
const ARRAY_2: u8 = 0x82;
const MAP_1: u8 = 0xa1;
const UINT_ZERO: u8 = 0x00;
const UINT_ONE: u8 = 0x01;
const UINT_TWO: u8 = 0x02;
/// A non-shortest-form encoding of the integer 5: RFC 8949 requires the
/// immediate one-byte form (`0x05`) whenever the value fits it; this spells
/// the same value with a redundant one-byte-following head instead.
const NON_SHORTEST_FIVE: [u8; 2] = [0x18, 0x05];
/// A CBOR negative integer, major type 1 minor 0: the value -1.
const NEGATIVE_ONE: u8 = 0x20;
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
const BYTES_SMALL_BASE: u8 = 0x40;
const FLOAT16: u8 = 0xf9;
const TEXT_INDEFINITE: u8 = 0x7f;
const TEXT_SMALL_BASE: u8 = 0x60;
const ASCII_A: u8 = b'a';
const BREAK: u8 = 0xff;
/// RFC 8949 §3.3 simple value 23: well-formed nowhere in this format.
const UNDEFINED: u8 = 0xf7;
/// A two-byte simple-value head (`0xf8`) naming 21 (`0x15`): the
/// non-shortest, never-well-formed spelling `ciborium` rejects the same way
/// `undefined` above is rejected.
const TWO_BYTE_SIMPLE: [u8; 2] = [0xf8, 0x15];
/// A byte appended past the last committed byte of a canonical body.
const TRAILING_BYTE: u8 = 0x00;

type Entry = (Vec<u8>, Vec<u8>);

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("a seed value encodes");
    out
}

fn text(s: &str) -> Vec<u8> {
    cbor(&Value::Text(s.to_owned()))
}

/// The `(key, value)` byte pairs of the definite map `bytes`.
fn entries(bytes: &[u8]) -> Vec<Entry> {
    let value: Value = ciborium::de::from_reader(bytes).expect("a seed map parses");
    let Value::Map(pairs) = value else {
        panic!("a seed base value is not a map")
    };
    pairs.iter().map(|(k, v)| (cbor(k), cbor(v))).collect()
}

/// A definite one-byte-head map over `entries`. The card holds ten fields, so
/// every shape here — even with one key added or repeated — stays within a
/// one-byte map head's 23-entry limit.
fn map(entries: &[Entry]) -> Vec<u8> {
    let count = u8::try_from(entries.len()).expect("card seed maps stay under 24 entries");
    let mut out = vec![0xa0 | count];
    for (k, v) in entries {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

fn value_of(entries: &[Entry], key: &str) -> Vec<u8> {
    let wanted = text(key);
    entries
        .iter()
        .find(|(k, _)| *k == wanted)
        .unwrap_or_else(|| panic!("seed base has no key {key}"))
        .1
        .clone()
}

fn with_value(entries: &[Entry], key: &str, value: Vec<u8>) -> Vec<Entry> {
    let wanted = text(key);
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

fn without(entries: &[Entry], key: &str) -> Vec<Entry> {
    let wanted = text(key);
    entries
        .iter()
        .filter(|(k, _)| *k != wanted)
        .cloned()
        .collect()
}

/// `entries` with `(key, value)` inserted where RFC 8949's length-first
/// canonical order puts it.
fn inserted(entries: &[Entry], key: Vec<u8>, value: Vec<u8>) -> Vec<Entry> {
    let mut out = entries.to_vec();
    let at = out
        .iter()
        .position(|(k, _)| (k.len(), k.as_slice()) > (key.len(), key.as_slice()))
        .unwrap_or(out.len());
    out.insert(at, (key, value));
    out
}

/// `entries` with the entry for `key` repeated right after itself.
fn repeated_with(entries: &[Entry], key: &str, second_value: Vec<u8>) -> Vec<Entry> {
    let wanted = text(key);
    let at = entries
        .iter()
        .position(|(k, _)| *k == wanted)
        .unwrap_or_else(|| panic!("seed base has no key {key}"));
    let mut out = entries.to_vec();
    out.insert(at + 1, (entries[at].0.clone(), second_value));
    out
}

/// The base with `key`'s value replaced by `bytes`.
fn plant_value(base: &[u8], key: &str, bytes: Vec<u8>) -> Vec<u8> {
    map(&with_value(&entries(base), key, bytes))
}

// ---------------------------------------------------------------------------
// Plants — one function per shape
// ---------------------------------------------------------------------------

fn undefined(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CREATED_AT, vec![UNDEFINED])
}

fn two_byte_simple(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CREATED_AT, TWO_BYTE_SIMPLE.to_vec())
}

fn nested_indefinite_chunk(base: &[u8]) -> Vec<u8> {
    let chunk = vec![
        TEXT_INDEFINITE,
        TEXT_INDEFINITE,
        TEXT_SMALL_BASE | 1,
        ASCII_A,
        BREAK,
        BREAK,
    ];
    plant_value(base, KEY_DISPLAY_NAME, chunk)
}

fn truncated(base: &[u8]) -> Vec<u8> {
    base[..base.len() - 1].to_vec()
}

/// 256 nested one-element arrays around a trailing `0`, so `created_at` sits
/// at nesting level 257 — one past crypto-design §6.2 rule 6's limit.
fn depth_257(base: &[u8]) -> Vec<u8> {
    let mut value = vec![0x81u8; 256];
    value.push(UINT_ZERO);
    plant_value(base, KEY_CREATED_AT, value)
}

/// A bignum tag over a definite byte string of 1 byte: within the width
/// `ciborium` folds to a plain integer, so this is caught by the whole-body
/// rule-4 walk rather than by the re-encode.
fn bignum_narrow(base: &[u8]) -> Vec<u8> {
    let bignum = vec![TAG_BIGNUM_POSITIVE, BYTES_SMALL_BASE | 1, UINT_ONE];
    plant_value(base, KEY_CREATED_AT, bignum)
}

/// A bignum tag over a definite byte string of 9 bytes — past the 8-byte
/// width that folds to `u64`, so `ciborium` keeps it a `Value::Tag`.
fn bignum_wide(base: &[u8]) -> Vec<u8> {
    let mut bignum = vec![TAG_BIGNUM_POSITIVE, BYTES_SMALL_BASE | 9];
    bignum.extend(std::iter::repeat_n(UINT_ONE, 9));
    plant_value(base, KEY_CREATED_AT, bignum)
}

fn float_value(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CREATED_AT, vec![FLOAT16, UINT_ZERO, UINT_ZERO])
}

/// The top-level item is an array, not a map — ignores the base entirely.
fn not_a_map(_base: &[u8]) -> Vec<u8> {
    vec![ARRAY_2, UINT_ZERO, UINT_ZERO]
}

/// A one-entry map keyed by an integer instead of text — ignores the base
/// entirely, since a non-text key is checked before anything about the §6
/// field set.
fn non_text_key(_base: &[u8]) -> Vec<u8> {
    vec![MAP_1, UINT_ONE, UINT_ZERO]
}

fn created_at_text(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CREATED_AT, text("ok"))
}

fn x25519_pk_short(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let value: Value = ciborium::de::from_reader(value_of(&top, KEY_X25519_PK).as_slice())
        .expect("x25519_pk value parses");
    let Value::Bytes(pk) = value else {
        panic!("x25519_pk is not a byte string")
    };
    let short = cbor(&Value::Bytes(pk[..pk.len() - 1].to_vec()));
    map(&with_value(&top, KEY_X25519_PK, short))
}

fn display_name_over_cap(base: &[u8]) -> Vec<u8> {
    // crypto-design §6's cap is 4096 bytes; one byte over it.
    plant_value(base, KEY_DISPLAY_NAME, text(&"a".repeat(4097)))
}

fn card_version_text(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CARD_VERSION, text("ok"))
}

fn created_at_negative(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CREATED_AT, vec![NEGATIVE_ONE])
}

fn no_x25519_pk(base: &[u8]) -> Vec<u8> {
    map(&without(&entries(base), KEY_X25519_PK))
}

fn repeated_created_at(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let same_value = value_of(&top, KEY_CREATED_AT);
    map(&repeated_with(&top, KEY_CREATED_AT, same_value))
}

/// A key outside the §6 schema, well-typed (a CBOR boolean) so nothing about
/// its own bytes could account for the rejection — only its NAME can.
fn extra_key(base: &[u8]) -> Vec<u8> {
    map(&inserted(
        &entries(base),
        text(FUTURE_KEY),
        cbor(&Value::Bool(true)),
    ))
}

fn card_version_two(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CARD_VERSION, vec![UINT_TWO])
}

fn trailing_bytes(base: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    out.push(TRAILING_BYTE);
    out
}

/// `created_at`'s value re-spelled in non-shortest form: still parses to the
/// same integer, so this is caught only by the final re-encode comparison,
/// not by the rule-4 walk or any type check.
fn non_shortest_created_at(base: &[u8]) -> Vec<u8> {
    plant_value(base, KEY_CREATED_AT, NON_SHORTEST_FIVE.to_vec())
}

// ---------------------------------------------------------------------------
// Case table
// ---------------------------------------------------------------------------

pub(super) fn cases() -> Vec<SeedCase> {
    use secretary_core::vault::manifest::RuleToken;

    let case = |token: RuleToken,
                shape: &'static str,
                variant: &'static str,
                plant: fn(&[u8]) -> Vec<u8>| SeedCase {
        target: TARGET,
        token,
        shape,
        variant,
        plant,
    };

    vec![
        case(
            RuleToken::MalformedCbor,
            "undefined",
            "CborDecode",
            undefined,
        ),
        case(
            RuleToken::MalformedCbor,
            "two_byte_simple",
            "CborDecode",
            two_byte_simple,
        ),
        case(
            RuleToken::MalformedCbor,
            "nested_indefinite_chunk",
            "CborDecode",
            nested_indefinite_chunk,
        ),
        case(
            RuleToken::MalformedCbor,
            "truncated",
            "CborDecode",
            truncated,
        ),
        case(
            RuleToken::MalformedCbor,
            "depth_257",
            "CborDecode",
            depth_257,
        ),
        case(
            RuleToken::Rule4TagOrFloat,
            "bignum_narrow",
            "TagRejected",
            bignum_narrow,
        ),
        case(
            RuleToken::Rule4TagOrFloat,
            "bignum_wide",
            "TagRejected",
            bignum_wide,
        ),
        case(
            RuleToken::Rule4TagOrFloat,
            "float",
            "FloatRejected",
            float_value,
        ),
        case(RuleToken::WrongType, "not_a_map", "Malformed", not_a_map),
        case(
            RuleToken::WrongType,
            "non_text_key",
            "Malformed",
            non_text_key,
        ),
        case(
            RuleToken::WrongType,
            "created_at_text",
            "Malformed",
            created_at_text,
        ),
        case(
            RuleToken::WrongType,
            "x25519_pk_short",
            "InvalidFieldLength",
            x25519_pk_short,
        ),
        case(
            RuleToken::WrongType,
            "display_name_over_cap",
            "DisplayNameTooLong",
            display_name_over_cap,
        ),
        case(
            RuleToken::WrongType,
            "card_version_text",
            "Malformed",
            card_version_text,
        ),
        // Ruling (a): `CardError` has no `IntegerOutOfRange` token — every
        // `Malformed(_)` arm, this one included, maps to `WrongType`
        // (`rule_tokens/card.rs`). The shape (a negative `created_at`) is
        // unchanged; only this column moved.
        case(
            RuleToken::WrongType,
            "created_at_negative",
            "Malformed",
            created_at_negative,
        ),
        case(
            RuleToken::MissingField,
            "no_x25519_pk",
            "MissingField",
            no_x25519_pk,
        ),
        case(
            RuleToken::DuplicateMapKey,
            "repeated_created_at",
            "DuplicateField",
            repeated_created_at,
        ),
        case(
            RuleToken::UnknownField,
            "extra_key",
            "UnknownField",
            extra_key,
        ),
        case(
            RuleToken::UnsupportedVersion,
            "card_version_two",
            "InvalidVersion",
            card_version_two,
        ),
        case(
            RuleToken::NonCanonicalUnclassified,
            "trailing_bytes",
            "NonCanonicalCbor",
            trailing_bytes,
        ),
        case(
            RuleToken::NonCanonicalUnclassified,
            "non_shortest_created_at",
            "NonCanonicalCbor",
            non_shortest_created_at,
        ),
    ]
}
