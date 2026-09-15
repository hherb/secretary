//! Single-fault `record` seeds, planted into
//! `core/fuzz/seeds/record/login.cbor` (keys `fields`, `last_mod_ms`,
//! `record_type`, `record_uuid`, `created_at_ms`; fields `username`,
//! `totp_seed`).
//!
//! The base is split into `(key bytes, value bytes)` entries and reassembled,
//! so a planted value can be ANY byte string, canonical or not, while every
//! other entry stays the base's own bytes. Insertions go to the position
//! canonical key order gives them, so no shape plants a key-order fault by
//! accident.

use ciborium::Value;
use secretary_core::vault::manifest::RuleToken;
use secretary_core::vault::record::RECORD_UUID_LEN;

use super::SeedCase;

// RFC 8949 bytes planted below.
const MAP_SMALL_BASE: u8 = 0xa0;
const MAP_ONE_BYTE_COUNT: u8 = 0xb8;
const MAP_INDEFINITE: u8 = 0xbf;
const ARRAY_EMPTY: u8 = 0x80;
const ARRAY_1: u8 = 0x81;
const BYTES_SMALL_BASE: u8 = 0x40;
const TEXT_SMALL_BASE: u8 = 0x60;
const TEXT_INDEFINITE: u8 = 0x7f;
const UINT_ZERO: u8 = 0x00;
const UINT_ONE: u8 = 0x01;
const NINT_ONE: u8 = 0x20;
const TAG_EPOCH: u8 = 0xc1;
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
const FLOAT16: u8 = 0xf9;
/// A CBOR boolean, where an integer or another type belongs.
const TRUE: u8 = 0xf5;
const UNDEFINED: u8 = 0xf7;
const BREAK: u8 = 0xff;
const INVALID_UTF8: u8 = 0xff;
const ASCII_A: u8 = b'a';
/// The largest count a one-byte map head can carry.
const SMALL_COUNT_MAX: usize = 23;
/// A key no v1 record defines, so it lands in the forward-compat bag.
const FUTURE_KEY: &str = "zz_future";
/// The field whose sub-map the nested shapes edit.
const EDITED_FIELD: &str = "username";

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

fn small_count(count: usize) -> u8 {
    assert!(
        count <= SMALL_COUNT_MAX,
        "seed maps stay in the one-byte head form"
    );
    u8::try_from(count).expect("a small count fits a byte")
}

fn entry_bytes(entries: &[Entry]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|(k, v)| k.iter().chain(v).copied())
        .collect()
}

fn map(entries: &[Entry]) -> Vec<u8> {
    let mut out = vec![MAP_SMALL_BASE | small_count(entries.len())];
    out.extend(entry_bytes(entries));
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
fn repeated(entries: &[Entry], key: &str) -> Vec<Entry> {
    let wanted = text(key);
    let at = entries
        .iter()
        .position(|(k, _)| *k == wanted)
        .unwrap_or_else(|| panic!("seed base has no key {key}"));
    let mut out = entries.to_vec();
    out.insert(at + 1, entries[at].clone());
    out
}

/// The base with `EDITED_FIELD`'s sub-map replaced by `edit` of its entries.
fn with_edited_field(base: &[u8], edit: fn(&[Entry]) -> Vec<u8>) -> Vec<u8> {
    let top = entries(base);
    let fields = entries(&value_of(&top, "fields"));
    let field = entries(&value_of(&fields, EDITED_FIELD));
    let fields = with_value(&fields, EDITED_FIELD, edit(&field));
    map(&with_value(&top, "fields", map(&fields)))
}

fn with_future_value(base: &[u8], value: Vec<u8>) -> Vec<u8> {
    map(&inserted(&entries(base), text(FUTURE_KEY), value))
}

fn truncated(base: &[u8]) -> Vec<u8> {
    base[..base.len() - 1].to_vec()
}

fn undefined_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![UNDEFINED])
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
    with_future_value(base, chunk)
}

fn invalid_utf8_text(base: &[u8]) -> Vec<u8> {
    map(&with_value(
        &entries(base),
        "record_type",
        vec![TEXT_SMALL_BASE | 1, INVALID_UTF8],
    ))
}

fn float_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![FLOAT16, UINT_ZERO, UINT_ZERO])
}

fn tag_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![TAG_EPOCH, UINT_ZERO])
}

fn bignum_tag(base: &[u8]) -> Vec<u8> {
    let bignum = vec![TAG_BIGNUM_POSITIVE, BYTES_SMALL_BASE | 1, UINT_ONE];
    map(&with_value(&entries(base), "created_at_ms", bignum))
}

fn top_level_array(base: &[u8]) -> Vec<u8> {
    let mut out = vec![ARRAY_1];
    out.extend_from_slice(base);
    out
}

fn non_text_key(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), vec![UINT_ONE], vec![UINT_ZERO]))
}

fn record_uuid_text(base: &[u8]) -> Vec<u8> {
    let as_text = text(&"u".repeat(RECORD_UUID_LEN));
    map(&with_value(&entries(base), "record_uuid", as_text))
}

/// A 16-byte uuid value one byte short.
fn shortened_uuid(value: &[u8]) -> Vec<u8> {
    let uuid: Value = ciborium::de::from_reader(value).expect("a uuid value parses");
    let Value::Bytes(uuid) = uuid else {
        panic!("seed base uuid is not a byte string")
    };
    cbor(&Value::Bytes(uuid[..RECORD_UUID_LEN - 1].to_vec()))
}

fn record_uuid_short(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let short = shortened_uuid(&value_of(&top, "record_uuid"));
    map(&with_value(&top, "record_uuid", short))
}

fn fields_not_a_map(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "fields", vec![ARRAY_EMPTY]))
}

fn negative_created_at_ms(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "created_at_ms", vec![NINT_ONE]))
}

fn missing_record_uuid(base: &[u8]) -> Vec<u8> {
    map(&without(&entries(base), "record_uuid"))
}

fn missing_field_value(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| map(&without(field, "value")))
}

fn duplicate_record_key(base: &[u8]) -> Vec<u8> {
    map(&repeated(&entries(base), "record_type"))
}

fn duplicate_field_name(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let fields = repeated(&entries(&value_of(&top, "fields")), EDITED_FIELD);
    map(&with_value(&top, "fields", map(&fields)))
}

fn duplicate_field_level_key(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| map(&repeated(field, "last_mod")))
}

fn key_order(base: &[u8]) -> Vec<u8> {
    let mut top = entries(base);
    top.swap(0, 1);
    map(&top)
}

fn indefinite_map(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let mut fields = vec![MAP_INDEFINITE];
    fields.extend(entry_bytes(&entries(&value_of(&top, "fields"))));
    fields.push(BREAK);
    map(&with_value(&top, "fields", fields))
}

fn non_shortest_map_head(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let field_entries = entries(&value_of(&top, "fields"));
    let mut fields = vec![MAP_ONE_BYTE_COUNT, small_count(field_entries.len())];
    fields.extend(entry_bytes(&field_entries));
    map(&with_value(&top, "fields", fields))
}

fn trailing_bytes(base: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    out.push(UINT_ZERO);
    out
}

// The rejection paths the first cut left unseeded (PR #673 review). The
// first two are the bool-as-integer acceptance divergence this slice closed
// in Python: `bool` subclasses `int`, and nothing else in CI would red a
// revert of that fix.

fn created_at_ms_bool(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "created_at_ms", vec![TRUE]))
}

fn field_last_mod_bool(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&with_value(field, "last_mod", vec![TRUE]))
    })
}

fn tags_not_an_array(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tags"), vec![UINT_ZERO]))
}

fn tag_not_text(base: &[u8]) -> Vec<u8> {
    map(&inserted(
        &entries(base),
        text("tags"),
        vec![ARRAY_1, UINT_ONE],
    ))
}

fn tombstone_not_a_bool(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tombstone"), vec![UINT_ONE]))
}

fn negative_tombstoned_at_ms(base: &[u8]) -> Vec<u8> {
    map(&inserted(
        &entries(base),
        text("tombstoned_at_ms"),
        vec![NINT_ONE],
    ))
}

fn field_value_wrong_type(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&with_value(field, "value", vec![UINT_ZERO]))
    })
}

fn negative_field_last_mod(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&with_value(field, "last_mod", vec![NINT_ONE]))
    })
}

fn field_device_uuid_short(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        let short = shortened_uuid(&value_of(field, "device_uuid"));
        map(&with_value(field, "device_uuid", short))
    })
}

fn fields_non_text_key(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let fields = inserted(
        &entries(&value_of(&top, "fields")),
        vec![UINT_ONE],
        vec![UINT_ZERO],
    );
    map(&with_value(&top, "fields", map(&fields)))
}

fn field_non_text_key(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| {
        map(&inserted(field, vec![UINT_ONE], vec![UINT_ZERO]))
    })
}

fn field_not_a_map(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let fields = with_value(
        &entries(&value_of(&top, "fields")),
        EDITED_FIELD,
        vec![UINT_ZERO],
    );
    map(&with_value(&top, "fields", map(&fields)))
}

pub fn cases() -> Vec<SeedCase> {
    let case = |token: RuleToken,
                shape: &'static str,
                variant: &'static str,
                plant: fn(&[u8]) -> Vec<u8>| SeedCase {
        target: "record",
        token,
        shape,
        variant,
        plant,
    };
    use RuleToken::{
        DuplicateMapKey, IntegerOutOfRange, MalformedCbor, MissingField, NonCanonicalUnclassified,
        Rule4TagOrFloat, WrongType,
    };
    vec![
        case(MalformedCbor, "truncated", "CborDecode", truncated),
        case(
            MalformedCbor,
            "undefined_value",
            "CborDecode",
            undefined_value,
        ),
        case(
            MalformedCbor,
            "nested_indefinite_chunk",
            "CborDecode",
            nested_indefinite_chunk,
        ),
        case(
            MalformedCbor,
            "invalid_utf8_text",
            "CborDecode",
            invalid_utf8_text,
        ),
        case(Rule4TagOrFloat, "float_value", "FloatRejected", float_value),
        case(Rule4TagOrFloat, "tag_value", "TagRejected", tag_value),
        case(Rule4TagOrFloat, "bignum_tag", "TagRejected", bignum_tag),
        case(WrongType, "top_level_array", "NotAMap", top_level_array),
        case(WrongType, "non_text_key", "NonTextKey", non_text_key),
        case(WrongType, "record_uuid_text", "WrongType", record_uuid_text),
        case(
            WrongType,
            "record_uuid_short",
            "InvalidUuid",
            record_uuid_short,
        ),
        case(WrongType, "fields_not_a_map", "WrongType", fields_not_a_map),
        case(
            WrongType,
            "created_at_ms_bool",
            "WrongType",
            created_at_ms_bool,
        ),
        case(
            WrongType,
            "field_last_mod_bool",
            "WrongType",
            field_last_mod_bool,
        ),
        case(
            WrongType,
            "tags_not_an_array",
            "WrongType",
            tags_not_an_array,
        ),
        case(WrongType, "tag_not_text", "WrongType", tag_not_text),
        case(
            WrongType,
            "tombstone_not_a_bool",
            "WrongType",
            tombstone_not_a_bool,
        ),
        case(
            WrongType,
            "field_value_uint",
            "WrongType",
            field_value_wrong_type,
        ),
        case(
            WrongType,
            "field_device_uuid_short",
            "InvalidUuid",
            field_device_uuid_short,
        ),
        case(
            WrongType,
            "fields_non_text_key",
            "NonTextKey",
            fields_non_text_key,
        ),
        case(
            WrongType,
            "field_non_text_key",
            "NonTextKey",
            field_non_text_key,
        ),
        case(WrongType, "field_not_a_map", "WrongType", field_not_a_map),
        case(
            IntegerOutOfRange,
            "negative_created_at_ms",
            "IntegerOverflow",
            negative_created_at_ms,
        ),
        case(
            IntegerOutOfRange,
            "negative_tombstoned_at_ms",
            "IntegerOverflow",
            negative_tombstoned_at_ms,
        ),
        case(
            IntegerOutOfRange,
            "negative_field_last_mod",
            "IntegerOverflow",
            negative_field_last_mod,
        ),
        case(
            MissingField,
            "record_uuid",
            "MissingField",
            missing_record_uuid,
        ),
        case(
            MissingField,
            "field_value",
            "MissingField",
            missing_field_value,
        ),
        case(
            DuplicateMapKey,
            "record_level",
            "DuplicateKey",
            duplicate_record_key,
        ),
        case(
            DuplicateMapKey,
            "fields_level",
            "DuplicateKey",
            duplicate_field_name,
        ),
        case(
            DuplicateMapKey,
            "field_level",
            "DuplicateKey",
            duplicate_field_level_key,
        ),
        case(
            NonCanonicalUnclassified,
            "key_order",
            "NonCanonicalEncoding",
            key_order,
        ),
        case(
            NonCanonicalUnclassified,
            "indefinite_map",
            "NonCanonicalEncoding",
            indefinite_map,
        ),
        case(
            NonCanonicalUnclassified,
            "non_shortest_map_head",
            "NonCanonicalEncoding",
            non_shortest_map_head,
        ),
        case(
            NonCanonicalUnclassified,
            "trailing_bytes",
            "NonCanonicalEncoding",
            trailing_bytes,
        ),
    ]
}

#[test]
fn reassembling_the_base_is_byte_identical() {
    let base = super::base("record");
    assert_eq!(
        map(&entries(&base)),
        base,
        "the entry split must round-trip the base"
    );
}
