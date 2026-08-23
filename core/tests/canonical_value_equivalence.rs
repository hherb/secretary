//! The load-bearing byte-identity claim of #547: a hand-written `Serialize`
//! over borrowed data emits CBOR byte-identical to the equivalent owned
//! `ciborium::Value` tree, across every CBOR head-length boundary.
//!
//! If this ever fails, the on-disk format has moved and the vault is
//! unreadable by every client written before the change. It is therefore an
//! integration test, run on every CI run, and not a design-time attestation.

use ciborium::Value;
use secretary_core::vault::canonical_test_api::{CanonicalMap, CanonicalValue};

fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::ser::into_writer(v, &mut b).expect("encode");
    b
}

/// Every CBOR head-length boundary: the argument is inline (<24), then 1, 2,
/// 4 and 8 additional bytes (RFC 8949 §3).
const LEN_BOUNDARIES: &[usize] = &[0, 1, 23, 24, 255, 256, 65535, 65536];

#[test]
fn uint_is_byte_identical_across_every_head_boundary() {
    for u in [
        0u64,
        1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        4294967295,
        4294967296,
        u64::MAX,
    ] {
        assert_eq!(
            enc(&Value::Integer(u.into())),
            enc(&CanonicalValue::Uint(u)),
            "uint {u}"
        );
    }
}

#[test]
fn text_is_byte_identical_across_every_head_boundary() {
    for &n in LEN_BOUNDARIES {
        let s = "a".repeat(n);
        assert_eq!(
            enc(&Value::Text(s.clone())),
            enc(&CanonicalValue::Text(&s)),
            "text len {n}"
        );
    }
}

#[test]
fn bytes_are_byte_identical_across_every_head_boundary() {
    for &n in LEN_BOUNDARIES {
        let b = vec![0xABu8; n];
        assert_eq!(
            enc(&Value::Bytes(b.clone())),
            enc(&CanonicalValue::Bytes(&b)),
            "bytes len {n}"
        );
    }
}

#[test]
fn bool_is_byte_identical() {
    for b in [true, false] {
        assert_eq!(
            enc(&Value::Bool(b)),
            enc(&CanonicalValue::Bool(b)),
            "bool {b}"
        );
    }
}

#[test]
fn array_is_byte_identical_across_every_head_boundary() {
    for &n in &[0usize, 1, 23, 24, 300] {
        let owned = Value::Array((0..n).map(|i| Value::Integer((i as u64).into())).collect());
        let borrowed =
            CanonicalValue::Array((0..n).map(|i| CanonicalValue::Uint(i as u64)).collect());
        assert_eq!(enc(&owned), enc(&borrowed), "array len {n}");
    }
}

/// The map arm additionally proves the SORT: keys are pushed in an order that
/// is not canonical, and the emitted bytes must match a `Value::Map` whose
/// entries were pre-sorted by encoded key bytes (length-then-bytewise, RFC
/// 8949 §4.2.1 — which differs from `String` ordering whenever key lengths
/// differ).
#[test]
fn map_is_byte_identical_and_sorts_its_own_keys() {
    // "z" (1 byte) sorts BEFORE "ab" (2 bytes) in canonical CBOR, and AFTER
    // it in plain string order. Pushing in string order proves the encoder
    // re-sorts rather than emitting insertion order.
    let keys = ["ab", "z", "aaa", "b"];
    let mut borrowed = CanonicalMap::with_capacity(keys.len());
    for (i, k) in keys.iter().enumerate() {
        borrowed.push(k, CanonicalValue::Uint(i as u64));
    }

    let mut owned_entries: Vec<(Value, Value)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (Value::Text((*k).into()), Value::Integer((i as u64).into())))
        .collect();
    owned_entries.sort_by_key(|(k, _)| {
        let mut b = Vec::new();
        ciborium::ser::into_writer(k, &mut b).expect("encode key");
        b
    });

    assert_eq!(enc(&Value::Map(owned_entries)), enc(&borrowed));
}

#[test]
fn map_is_byte_identical_across_every_head_boundary() {
    for &n in &[0usize, 1, 23, 24, 300] {
        let names: Vec<String> = (0..n).map(|i| format!("k{i:05}")).collect();
        let mut borrowed = CanonicalMap::with_capacity(n);
        for (i, name) in names.iter().enumerate() {
            borrowed.push(name, CanonicalValue::Uint(i as u64));
        }
        let owned = Value::Map(
            names
                .iter()
                .enumerate()
                .map(|(i, k)| (Value::Text(k.clone()), Value::Integer((i as u64).into())))
                .collect(),
        );
        assert_eq!(enc(&owned), enc(&borrowed), "map len {n}");
    }
}

/// The exact shape the record path emits: an outer map holding an array of
/// per-record maps, each holding a per-field map with a text secret, an
/// integer clock and a byte uuid.
#[test]
fn nested_record_in_block_shape_is_byte_identical() {
    let secret = "hunter2";
    let device_uuid = [7u8; 16];

    // `ciborium::Value::Map`'s `Serialize` emits entries in Vec order — it
    // does NOT sort them (`size.rs`'s module doc and `CanonicalMap`'s own
    // doc both say so). So this "equivalent owned tree" must already be
    // listed in canonical order (length-then-bytewise: "value" (5) <
    // "last_mod" (8) < "device_uuid" (11)) for the comparison below to be
    // meaningful — `CanonicalMap` sorts at serialise time regardless of
    // push order, so it would reach the same bytes from any push order.
    let owned_field = Value::Map(vec![
        (Value::Text("value".into()), Value::Text(secret.into())),
        (
            Value::Text("last_mod".into()),
            Value::Integer(1_234_567_890u64.into()),
        ),
        (
            Value::Text("device_uuid".into()),
            Value::Bytes(device_uuid.to_vec()),
        ),
    ]);
    let owned = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(24u64.into())),
        (
            Value::Text("records".into()),
            Value::Array(vec![owned_field]),
        ),
    ]);

    let mut field = CanonicalMap::with_capacity(3);
    field.push("value", CanonicalValue::Text(secret));
    field.push("last_mod", CanonicalValue::Uint(1_234_567_890));
    field.push("device_uuid", CanonicalValue::Bytes(&device_uuid));
    let mut outer = CanonicalMap::with_capacity(2);
    outer.push(
        "records",
        CanonicalValue::Array(vec![CanonicalValue::Map(field)]),
    );
    outer.push("n", CanonicalValue::Uint(24));

    assert_eq!(enc(&owned), enc(&outer));
}

/// Forward-compat unknown values pass through verbatim as a borrow.
#[test]
fn borrowed_unknown_passes_through_verbatim() {
    let unk = Value::Array(vec![Value::Text("x".into()), Value::Bytes(vec![1, 2, 3])]);
    assert_eq!(enc(&unk), enc(&CanonicalValue::Borrowed(&unk)));
}
