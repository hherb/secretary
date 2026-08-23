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
/// is not canonical, and the emitted bytes must match the literal CBOR
/// encoding of the canonically-sorted map.
///
/// The oracle here is a hardcoded expected byte vector, not a second
/// invocation of "encode each key then sort the encodings" — that
/// would-be oracle used to be exactly the algorithm this test is supposed
/// to be checking `CanonicalMap` *against*, so it proved only that two
/// implementations of the same idea agree with each other, not that either
/// agrees with real CBOR. That distinction became load-bearing once
/// `CanonicalMap`'s own comparator stopped encoding keys at all (review
/// round 1 of #547 Task 2) and switched to comparing `(byte length, bytes)`
/// directly — a hand-derived byte vector is independent of both.
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

    // Canonical order (length-then-bytewise) is "b" < "z" < "ab" < "aaa",
    // carrying values 3, 1, 0, 2 respectively (the index each key was
    // pushed at above). Derived by hand from RFC 8949 §4.2.1, not computed
    // by any sort call:
    //   0xA4                   -- map(4)
    //   0x61 'b'   0x03        -- "b": 3
    //   0x61 'z'   0x01        -- "z": 1
    //   0x62 'a''b' 0x00       -- "ab": 0
    //   0x63 'a''a''a' 0x02    -- "aaa": 2
    let expected: Vec<u8> = vec![
        0xA4, 0x61, b'b', 3, 0x61, b'z', 1, 0x62, b'a', b'b', 0, 0x63, b'a', b'a', b'a', 2,
    ];

    assert_eq!(enc(&borrowed), expected);
}

/// The sort comparator's own head-length-class boundary, distinct from
/// [`map_is_byte_identical_across_every_head_boundary`]'s MAP-length
/// boundary below: that test's keys are all the same fixed width
/// (`k00000`..`k00299`), so it never exercises a KEY crossing a CBOR
/// text-head length class, and the four-key sort test above uses keys of
/// 1-3 bytes, all within the single-byte-head class (0-23). This test
/// pushes a 23-byte key (single-byte head `0x77`) and a 24-byte key
/// (two-byte head `0x78 0x18`) — RFC 8949's exact head-length transition —
/// plus a pair chosen so that sorting by CHAR count instead of BYTE length
/// would put them in the wrong order: "ab" is 2 bytes/2 chars, "日" is 3
/// bytes/1 char, so a char-count comparator would rank "日" before "ab"
/// while the correct byte-length comparator ranks "ab" first. All four are
/// pushed in scrambled order.
#[test]
fn map_key_sort_crosses_head_length_boundary_and_uses_byte_not_char_length() {
    let short = "ab";
    let multibyte = "\u{65e5}"; // "日": 1 char, 3 bytes (U+65E5)
    let boundary_23 = "c".repeat(23);
    let boundary_24 = "d".repeat(24);
    assert_eq!(boundary_23.len(), 23);
    assert_eq!(boundary_24.len(), 24);
    assert_eq!(multibyte.chars().count(), 1);
    assert_eq!(multibyte.len(), 3);

    let mut borrowed = CanonicalMap::with_capacity(4);
    borrowed.push(&boundary_24, CanonicalValue::Uint(3));
    borrowed.push(short, CanonicalValue::Uint(0));
    borrowed.push(&boundary_23, CanonicalValue::Uint(2));
    borrowed.push(multibyte, CanonicalValue::Uint(1));

    // Canonical order is ascending BYTE length: short(2) < multibyte(3) <
    // boundary_23(23) < boundary_24(24). Listed here already in that
    // order — this is a hand-asserted expectation, not a sort call, so it
    // does not restate the algorithm under test.
    let owned = Value::Map(vec![
        (Value::Text(short.into()), Value::Integer(0u64.into())),
        (Value::Text(multibyte.into()), Value::Integer(1u64.into())),
        (
            Value::Text(boundary_23.clone()),
            Value::Integer(2u64.into()),
        ),
        (
            Value::Text(boundary_24.clone()),
            Value::Integer(3u64.into()),
        ),
    ]);

    assert_eq!(enc(&owned), enc(&borrowed));
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

    // Pushed OUT of canonical order (8-byte key before the 5-byte key) so
    // the nested `Map` arm's own sort is load-bearing for this test: with
    // the earlier in-order push, this test would pass even if `Serialize`
    // for a nested `CanonicalMap` silently emitted push order instead of
    // sorting — "nested maps sort themselves" is the type's headline claim
    // and this is what actually pins it.
    let mut field = CanonicalMap::with_capacity(3);
    field.push("last_mod", CanonicalValue::Uint(1_234_567_890));
    field.push("value", CanonicalValue::Text(secret));
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
