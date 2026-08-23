// Entry-sort, map-encode and float/tag-rejection helpers. See the module
// docs at `super` (`canonical/mod.rs`) for the shared contract these three
// functions implement, and `size.rs` for the pre-reservation helper
// `encode_canonical_map` depends on.

use ciborium::Value;

use super::CanonicalError;
use crate::cbor::classify_ser;

/// Sort `(key, value)` entries by the canonical CBOR encoding of their
/// keys (RFC 8949 §4.2.1: length-then-bytewise).
///
/// Each key is materialised to its CBOR encoding, the entries are sorted
/// bytewise on those encodings, and the original `(key, value)` pairs
/// are returned in the new order. Robust against any future key shape
/// (text, byte, integer) without per-type code paths.
///
/// The `ciborium::ser::into_writer` call inside is structurally
/// infallible against a `Vec<u8>` writer, but propagating the typed error
/// keeps this function defensible against a future ciborium signature
/// change without a panic-or-empty-key footgun.
pub fn canonical_sort_entries(
    entries: &[(Value, Value)],
) -> Result<Vec<(Value, Value)>, CanonicalError> {
    let mut materialised: Vec<(Vec<u8>, (Value, Value))> = entries
        .iter()
        .map(|pair| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(&pair.0, &mut key_bytes)
                .map_err(|e| CanonicalError::CborEncode(classify_ser(&e)))?;
            Ok((key_bytes, pair.clone()))
        })
        .collect::<Result<_, CanonicalError>>()?;
    materialised.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(materialised.into_iter().map(|(_, pair)| pair).collect())
}

/// Serialize a pre-sorted, BORROWED entry list as a definite-length CBOR map.
///
/// Exists so the encoder never has to build a `ciborium::Value::Map`, which
/// owns its pairs and therefore costs a deep clone of every byte string it
/// holds. `serialize_map` with an explicit length emits the same major-type-5
/// definite-length header `Value::Map` does, so the bytes are unchanged — a
/// property the golden vault pins hard: `vault::record::decode` re-encodes
/// its parsed representation and requires a byte-identical match against the
/// input (`record.rs`'s strict canonical-input check), so any drift here
/// would fail that comparison on the very next round trip. (Not
/// `identity::card::from_canonical_cbor` — its own doc states it tolerates
/// non-§6 key order on input and does not re-encode-and-compare.)
pub(crate) struct BorrowedCanonicalMap<'a>(&'a [(&'a Value, &'a Value)]);

impl serde::Serialize for BorrowedCanonicalMap<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// Encode an entry list as a top-level canonical-CBOR map.
///
/// Sorts on the CBOR-encoded key bytes (because `ciborium` emits a
/// `Value::Map`'s `Vec<(Value, Value)>` in iteration order, NOT in CBOR
/// canonical order), then serialises as a single definite-length map.
pub fn encode_canonical_map(entries: &[(Value, Value)]) -> Result<Vec<u8>, CanonicalError> {
    // Only the KEYS are materialised, to sort on. The values ride along as
    // BORROWS: the `pair.clone()` this replaced was a full deep clone of every
    // value, and on the record path those values are decrypted user plaintext
    // (#547). Same fix #546 made in `unlock::bundle::encode_map`; this is the
    // shared helper it did not reach.
    let mut sorted: Vec<(Vec<u8>, (&Value, &Value))> = entries
        .iter()
        .map(|(key, value)| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(key, &mut key_bytes)
                .map_err(|e| CanonicalError::CborEncode(classify_ser(&e)))?;
            Ok((key_bytes, (key, value)))
        })
        .collect::<Result<_, CanonicalError>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let borrowed: Vec<(&Value, &Value)> = sorted.into_iter().map(|(_, pair)| pair).collect();

    // Pre-reserve so `into_writer` cannot grow (and thus realloc-and-free) a
    // buffer that may hold plaintext. See `size::cbor_size_bound`. The outer
    // `+ super::HEAD_MAX` accounts for the enclosing map's own CBOR head;
    // it is the same constant `cbor_size_bound` uses internally for every
    // value's head, re-exported so this call site cannot silently drift
    // from that one by hardcoding a duplicate literal.
    let capacity_bound = entries
        .iter()
        .map(|(k, v)| super::cbor_size_bound(k) + super::cbor_size_bound(v))
        .sum::<usize>()
        + super::HEAD_MAX;
    let mut buf = Vec::with_capacity(capacity_bound);

    ciborium::ser::into_writer(&BorrowedCanonicalMap(&borrowed), &mut buf)
        .map_err(|e| CanonicalError::CborEncode(classify_ser(&e)))?;

    // Real runtime check, not `debug_assert!`: this crate's only
    // `debug-assertions = true` is `core/fuzz/Cargo.toml`, which is
    // `exclude`d from the workspace (see root `Cargo.toml`), so a
    // `debug_assert!` here would be a no-op in `cargo test --release`, in
    // `cargo build --release`, and in every shipped artifact. This check
    // DETECTS an under-reserve after the fact — by the time it runs,
    // `into_writer` has already grown the buffer if it needed to, and the
    // old (possibly plaintext-bearing) allocation is already freed unwiped.
    // It is a tripwire for a future `ciborium::Value` variant `size.rs`
    // cannot name, not a preventive guarantee.
    if buf.len() > capacity_bound {
        return Err(CanonicalError::CapacityBoundExceeded {
            actual: buf.len(),
            bound: capacity_bound,
        });
    }
    Ok(buf)
}

/// Walk a `Value` tree and reject floats and tags (`docs/crypto-design.md`
/// §6.2 #4). `field_hint` is propagated unchanged into the emitted error
/// so the caller sees which entry-point caught the violation.
///
/// Recurses without an explicit depth bound. Termination relies on
/// `ciborium`'s default `from_reader` recursion limit (256), which has
/// already capped the input tree depth before we walk it. If a future
/// contributor switches the parser to
/// `from_reader_with_recursion_limit(.., usize::MAX)` or similar, add an
/// explicit `depth` parameter here to prevent stack overflow on
/// adversarial input.
pub fn reject_floats_and_tags(v: &Value, field_hint: &'static str) -> Result<(), CanonicalError> {
    match v {
        Value::Float(_) => Err(CanonicalError::FloatRejected { field: field_hint }),
        Value::Tag(_, _) => Err(CanonicalError::TagRejected { field: field_hint }),
        Value::Array(items) => {
            for item in items {
                reject_floats_and_tags(item, field_hint)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            for (k, val) in entries {
                reject_floats_and_tags(k, field_hint)?;
                reject_floats_and_tags(val, field_hint)?;
            }
            Ok(())
        }
        // Integer / Bytes / Text / Bool / Null are all permitted in v1.
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_canonical_map_round_trips_small_map() {
        // Two entries inserted out of canonical order (length-then-lex).
        // Canonical order here puts `"a"` before `"bb"` because `"a"`'s
        // encoded key is shorter.
        let entries = vec![
            (Value::Text("bb".into()), Value::Integer(2u64.into())),
            (Value::Text("a".into()), Value::Integer(1u64.into())),
        ];
        let bytes = encode_canonical_map(&entries).expect("encode");
        // Re-parse and verify the keys come back in canonical order.
        let parsed: Value = ciborium::de::from_reader(bytes.as_slice()).expect("decode");
        match parsed {
            Value::Map(m) => {
                let keys: Vec<&str> = m
                    .iter()
                    .map(|(k, _)| match k {
                        Value::Text(s) => s.as_str(),
                        _ => panic!("non-text key"),
                    })
                    .collect();
                assert_eq!(keys, vec!["a", "bb"], "canonical order is length-then-lex");
            }
            _ => panic!("expected a map"),
        }
    }

    #[test]
    fn canonical_sort_orders_by_length_then_lex() {
        // Three text keys whose canonical CBOR encodings differ in length.
        // `"z"` (1 char) sorts before `"ab"` (2 chars) because its CBOR
        // encoding `0x61 0x7a` is shorter than `"ab"`'s `0x62 0x61 0x62`.
        let entries = vec![
            (Value::Text("ab".into()), Value::Null),
            (Value::Text("z".into()), Value::Null),
            (Value::Text("aa".into()), Value::Null),
        ];
        let sorted = canonical_sort_entries(&entries).expect("sort");
        let keys: Vec<&str> = sorted
            .iter()
            .map(|(k, _)| match k {
                Value::Text(s) => s.as_str(),
                _ => panic!("non-text key"),
            })
            .collect();
        assert_eq!(
            keys,
            vec!["z", "aa", "ab"],
            "length-then-lex orders \"z\" first then \"aa\" then \"ab\""
        );
    }

    #[test]
    fn reject_floats_with_field_hint_preserved() {
        // A float at the top level: walker emits FloatRejected with the
        // exact field hint we passed in.
        let v = Value::Float(1.5);
        let err = reject_floats_and_tags(&v, "<root>").expect_err("float must be rejected");
        assert!(
            matches!(err, CanonicalError::FloatRejected { field: "<root>" }),
            "expected FloatRejected {{ field: \"<root>\" }}, got {err:?}"
        );

        // A float nested inside an array inside a map: hint is propagated
        // unchanged (the walker does not thread per-key hints).
        let nested = Value::Map(vec![(
            Value::Text("k".into()),
            Value::Array(vec![Value::Float(2.5)]),
        )]);
        let err = reject_floats_and_tags(&nested, "<unknown>")
            .expect_err("nested float must be rejected");
        assert!(
            matches!(err, CanonicalError::FloatRejected { field: "<unknown>" }),
            "expected FloatRejected {{ field: \"<unknown>\" }}, got {err:?}"
        );
    }

    #[test]
    fn reject_tags_with_field_hint_preserved() {
        // Tag 0 (RFC 3339 datetime) at the top level — irrelevant to the
        // walker, which rejects ALL tags regardless of tag number.
        let v = Value::Tag(0, Box::new(Value::Text("2024-04-25T00:00:00Z".into())));
        let err = reject_floats_and_tags(&v, "<root>").expect_err("tag must be rejected");
        assert!(
            matches!(err, CanonicalError::TagRejected { field: "<root>" }),
            "expected TagRejected {{ field: \"<root>\" }}, got {err:?}"
        );
    }

    /// `encode_canonical_map` must not grow its output buffer. A realloc
    /// copies to a new block and frees the old one unwiped — the hazard
    /// `SecretBytes::concat` (#524) exists to prevent. `capacity()` is the
    /// only observable proxy, and it IS observable: the #546 review found the
    /// claim that it was not to be wrong.
    #[test]
    fn encode_canonical_map_does_not_realloc() {
        let mut entries: Vec<(Value, Value)> = (0..40)
            .map(|i| {
                (
                    Value::Text(format!("k{i:03}")),
                    Value::Bytes(vec![0xCD; 100 + i]),
                )
            })
            .collect();
        // One nested entry (a Map-of-Bytes value) so this test actually
        // drives the recursive Map arm of `cbor_size_bound` through
        // `encode_canonical_map` itself — every other entry here is flat,
        // which the bundle's original flat-only bound would also have
        // covered, and flat entries alone wouldn't exercise the reason the
        // bound was made recursive (#547).
        entries.push((
            Value::Text("nested".into()),
            Value::Map(vec![(
                Value::Text("inner".into()),
                Value::Bytes(vec![0xEF; 64]),
            )]),
        ));

        let out = encode_canonical_map(&entries).expect("encode");
        // A Vec that never grew has exactly the capacity it was created with.
        // Any growth would have gone through the doubling path and produced a
        // capacity that is not the reserved bound.
        assert!(
            out.capacity() >= out.len(),
            "sanity: capacity {} < len {}",
            out.capacity(),
            out.len()
        );
        // NOTE on what this does and does not prove: this recomputes the
        // SAME `Σ(bound(k)+bound(v)) + HEAD_MAX` formula
        // `encode_canonical_map` uses internally, so a copy-paste edit that
        // changed both sites identically (e.g. the same off-by-one applied
        // to `HEAD_MAX` here and there) would stay green. It is not a
        // from-first-principles check. That job belongs to
        // `size_bound_is_not_under_reserved_for_a_nested_tree` in
        // `size.rs`, which compares the bound against `ciborium`'s ACTUAL
        // encoded length independently. This test's narrower job is proving
        // `encode_canonical_map` really uses `with_capacity` (not `new`)
        // with EXACTLY the bound it computes — see the #547 mutation check
        // recorded in the task report.
        let bound: usize = entries
            .iter()
            .map(|(k, v)| {
                crate::vault::canonical::cbor_size_bound(k)
                    + crate::vault::canonical::cbor_size_bound(v)
            })
            .sum::<usize>()
            + crate::vault::canonical::HEAD_MAX;
        assert_eq!(
            out.capacity(),
            bound,
            "capacity changed from the reserved bound — into_writer grew the \
             buffer, freeing an unwiped block"
        );
    }
}
