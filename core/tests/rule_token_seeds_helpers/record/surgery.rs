//! Entry-level surgery on the `record` seed base.
//!
//! The base is split into `(key bytes, value bytes)` entries and reassembled,
//! so a planted value can be ANY byte string, canonical or not, while every
//! other entry stays the base's own bytes. Insertions go to the position
//! canonical key order gives them, so no shape plants a key-order fault by
//! accident.

use ciborium::Value;
use secretary_core::vault::record::RECORD_UUID_LEN;

const MAP_SMALL_BASE: u8 = 0xa0;
/// The largest count a one-byte map head can carry.
const SMALL_COUNT_MAX: usize = 23;
/// A key no v1 record defines, so it lands in the forward-compat bag.
const FUTURE_KEY: &str = "zz_future";
/// The field whose sub-map the nested shapes edit.
pub(super) const EDITED_FIELD: &str = "username";

pub(super) type Entry = (Vec<u8>, Vec<u8>);

pub(super) fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("a seed value encodes");
    out
}

pub(super) fn text(s: &str) -> Vec<u8> {
    cbor(&Value::Text(s.to_owned()))
}

/// The `(key, value)` byte pairs of the definite map `bytes`.
pub(super) fn entries(bytes: &[u8]) -> Vec<Entry> {
    let value: Value = ciborium::de::from_reader(bytes).expect("a seed map parses");
    let Value::Map(pairs) = value else {
        panic!("a seed base value is not a map")
    };
    pairs.iter().map(|(k, v)| (cbor(k), cbor(v))).collect()
}

pub(super) fn small_count(count: usize) -> u8 {
    assert!(
        count <= SMALL_COUNT_MAX,
        "seed maps stay in the one-byte head form"
    );
    u8::try_from(count).expect("a small count fits a byte")
}

pub(super) fn entry_bytes(entries: &[Entry]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|(k, v)| k.iter().chain(v).copied())
        .collect()
}

pub(super) fn map(entries: &[Entry]) -> Vec<u8> {
    let mut out = vec![MAP_SMALL_BASE | small_count(entries.len())];
    out.extend(entry_bytes(entries));
    out
}

pub(super) fn value_of(entries: &[Entry], key: &str) -> Vec<u8> {
    let wanted = text(key);
    entries
        .iter()
        .find(|(k, _)| *k == wanted)
        .unwrap_or_else(|| panic!("seed base has no key {key}"))
        .1
        .clone()
}

pub(super) fn with_value(entries: &[Entry], key: &str, value: Vec<u8>) -> Vec<Entry> {
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

pub(super) fn without(entries: &[Entry], key: &str) -> Vec<Entry> {
    let wanted = text(key);
    entries
        .iter()
        .filter(|(k, _)| *k != wanted)
        .cloned()
        .collect()
}

/// `entries` with `(key, value)` inserted where RFC 8949's length-first
/// canonical order puts it.
pub(super) fn inserted(entries: &[Entry], key: Vec<u8>, value: Vec<u8>) -> Vec<Entry> {
    let mut out = entries.to_vec();
    let at = out
        .iter()
        .position(|(k, _)| (k.len(), k.as_slice()) > (key.len(), key.as_slice()))
        .unwrap_or(out.len());
    out.insert(at, (key, value));
    out
}

/// `entries` with the entry for `key` repeated right after itself.
pub(super) fn repeated(entries: &[Entry], key: &str) -> Vec<Entry> {
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
pub(super) fn with_edited_field(base: &[u8], edit: fn(&[Entry]) -> Vec<u8>) -> Vec<u8> {
    let top = entries(base);
    let fields = entries(&value_of(&top, "fields"));
    let field = entries(&value_of(&fields, EDITED_FIELD));
    let fields = with_value(&fields, EDITED_FIELD, edit(&field));
    map(&with_value(&top, "fields", map(&fields)))
}

pub(super) fn with_future_value(base: &[u8], value: Vec<u8>) -> Vec<u8> {
    map(&inserted(&entries(base), text(FUTURE_KEY), value))
}

/// A 16-byte uuid value one byte short.
pub(super) fn shortened_uuid(value: &[u8]) -> Vec<u8> {
    let uuid: Value = ciborium::de::from_reader(value).expect("a uuid value parses");
    let Value::Bytes(uuid) = uuid else {
        panic!("seed base uuid is not a byte string")
    };
    cbor(&Value::Bytes(uuid[..RECORD_UUID_LEN - 1].to_vec()))
}
