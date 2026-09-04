//! Post-hoc `ciborium` surgery on an already-encoded manifest body.
//!
//! **Why this exists (#600).** `encode_manifest` now rejects a manifest
//! whose §4.2-constrained arrays hold a repeated value, which is the
//! whole point of #600 — but three decoder tests needed exactly such a
//! body to prove the READER rejects it too, and built it by handing the
//! duplicate straight to the encoder. That route is closed, deliberately:
//! a test fixture that can only be produced by a non-conformant writer is
//! a fixture the writer must keep being able to produce.
//!
//! So the body is built the way a hostile or buggy PEER would have to
//! build it — encode a conformant manifest, then edit the bytes. That is
//! also a truer fixture than the old one: the input `decode_manifest`
//! must defend against comes off a disk or a network, not out of this
//! crate's own encoder.
//!
//! The sibling pattern is
//! `core/tests/manifest_canonicality_kat.rs`'s `reverse_array`, which
//! reverses one array for the same reason (the encoder sorts, so it
//! cannot emit an out-of-order body either). **That helper and this one
//! are deliberately not shared**: it lives in an integration test, which
//! sees only `secretary_core`'s public API and cannot reach a
//! `#[cfg(test)]` module. `core/tests/manifest_uniqueness_kat.rs` carries
//! its own copy for the same reason. Promoting either into the public API
//! to spare one duplication would put test-only manifest surgery on the
//! shipped surface, which is a worse trade.

use ciborium::Value;

/// Where an array lives inside an encoded manifest body.
///
/// Two levels is all §4.2 has, so this is an enum of the two rather than
/// a general path walk.
pub(in crate::vault::manifest) enum BodyArray<'a> {
    /// A top-level array key — `vector_clock`, `blocks` or `trash`.
    Top(&'a str),
    /// An array inside one `blocks` entry — `recipients` or
    /// `vector_clock_summary`. The `usize` indexes `blocks` **as
    /// encoded**, i.e. after the §4.2 ascending-`block_uuid` sort.
    InBlock(usize, &'a str),
}

/// Copy one map field from element `from` to element `to` of an array
/// inside an encoded manifest body, and re-encode.
///
/// Used to plant a repeated value — the caller picks a field §4.2
/// constrains (`block_uuid`, `device_uuid`) and two elements that
/// currently differ in it.
///
/// **Re-encoding a parsed `Value` is byte-preserving for a canonical
/// input**, which is what makes the output differ from the input in
/// exactly the planted field and nothing else: `ciborium`'s reader
/// normalises indefinite lengths and non-shortest heads on parse, and
/// `Value::Map` keeps its entries as an ordered `Vec`, so a body that was
/// already canonical round-trips unchanged. The property is not assumed —
/// `parse_and_reencode_is_byte_preserving_for_a_canonical_body` asserts
/// it directly, and `manifest_uniqueness_kat_replays` asserts it again
/// end-to-end against a frozen fixture.
///
/// Panics rather than returning a `Result`: every caller is a test
/// naming a key it just encoded, so a miss is a broken test, not a
/// condition to handle.
pub(in crate::vault::manifest) fn copy_entry_field(
    body: &[u8],
    array: BodyArray<'_>,
    from: usize,
    to: usize,
    field: &str,
) -> Vec<u8> {
    let mut v: Value = ciborium::de::from_reader(body).expect("parse manifest body");

    let items = match array {
        BodyArray::Top(key) => array_mut(&mut v, key),
        BodyArray::InBlock(index, key) => {
            let block = array_mut(&mut v, "blocks")
                .get_mut(index)
                .unwrap_or_else(|| panic!("blocks[{index}] does not exist"));
            array_mut(block, key)
        }
    };
    assert!(
        from != to,
        "copying a field onto itself plants nothing -- the case would be vacuous"
    );

    let source = field_of(&items[from], field).clone();
    assert_ne!(
        &source,
        field_of(&items[to], field),
        "elements {from} and {to} already share {field:?} -- the case would be vacuous"
    );
    *field_mut(&mut items[to], field) = source;

    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).expect("re-encode");
    out
}

/// The array stored under `key` in a CBOR map.
fn array_mut<'a>(v: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    let entries = match v {
        Value::Map(m) => m,
        other => panic!("expected a map, got {other:?}"),
    };
    let slot = entries
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, val)| val)
        .unwrap_or_else(|| panic!("key {key:?} not found"));
    match slot {
        Value::Array(a) => a,
        other => panic!("key {key:?} is not an array: {other:?}"),
    }
}

fn field_of<'a>(entry: &'a Value, field: &str) -> &'a Value {
    match entry {
        Value::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_text() == Some(field))
            .map(|(_, val)| val)
            .unwrap_or_else(|| panic!("entry has no field {field:?}")),
        other => panic!("array element is not a map: {other:?}"),
    }
}

fn field_mut<'a>(entry: &'a mut Value, field: &str) -> &'a mut Value {
    match entry {
        Value::Map(m) => m
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(field))
            .map(|(_, val)| val)
            .unwrap_or_else(|| panic!("entry has no field {field:?}")),
        other => panic!("array element is not a map: {other:?}"),
    }
}

#[cfg(test)]
mod tests;
