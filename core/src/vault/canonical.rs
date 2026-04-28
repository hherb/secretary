//! Shared canonical-CBOR helpers for the vault format
//! (`docs/vault-format.md` §6.2 / §6.3 + RFC 8949 §4.2.1).
//!
//! [`block`](super::block) and [`record`](super::record) (and, in a
//! subsequent build-sequence step, the manifest layer) all need three
//! micro-operations on a `(key, value)` entry list:
//!
//! 1. [`canonical_sort_entries`] — re-order entries by the canonical CBOR
//!    encoding of their keys (length-then-bytewise per RFC 8949 §4.2.1).
//! 2. [`encode_canonical_map`] — sort, then serialise as a single
//!    definite-length CBOR map.
//! 3. [`reject_floats_and_tags`] — walk a `Value` tree and reject the two
//!    forbidden node types (§6.2 #4) so callers don't have to re-check on
//!    the per-field decode path.
//!
//! Before this module existed, each of `block.rs` and `record.rs` carried
//! a private copy of all three helpers. The duplication was defensible
//! when there were two callers; PR-B's manifest layer would have made it
//! a third copy. Pulling them here keeps the canonical-encoding
//! discipline centralised and makes any future tightening (e.g.
//! threading a depth bound into the walker) a one-place change.
//!
//! The errors that arise from these helpers are typed as
//! [`CanonicalError`]. Callers convert them to their layer-local error
//! enum (`BlockError`, `RecordError`) via the per-layer
//! `From<CanonicalError>` impls; those impls map each canonical-layer
//! variant to the pre-existing layer-local variant of the same shape so
//! the public error surface (and existing pattern-match call sites) is
//! preserved bit-for-bit.

#![forbid(unsafe_code)]

use ciborium::Value;

/// Errors emitted by the three canonical-CBOR helpers in this module.
///
/// The variant set is the union of what the existing `block.rs` and
/// `record.rs` private copies actually produced — no speculative
/// variants. Specifically:
///
/// - [`Self::CborEncode`] — emitted by [`canonical_sort_entries`] (per-key
///   `ciborium::ser::into_writer` failure) and [`encode_canonical_map`]
///   (top-level `ciborium::ser::into_writer` failure). Same string-payload
///   shape as `RecordError::CborEncode` and `BlockError::CborEncode` for
///   the same generic-source justification (`ciborium::ser::Error<E>` is
///   generic over the writer's I/O error and so cannot be uniformly
///   captured as a `#[from]` source).
///
/// - [`Self::FloatRejected`] / [`Self::TagRejected`] — emitted by
///   [`reject_floats_and_tags`] when it walks into a `Value::Float(_)` or
///   `Value::Tag(_, _)` node. `field` carries the entry-point hint the
///   caller passed so the user sees which subtree contained the
///   disallowed item (`"<root>"` for the top-level walk, `"<unknown>"`
///   for an unknown-value walk, etc.). The original record/block
///   `TagRejected` variants did not carry the hint; this one does, which
///   is a strict information improvement — the per-layer `From` impls
///   discard the hint when mapping to the legacy variant if needed.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    /// `ciborium::ser::into_writer` returned an I/O or serialisation error.
    /// Carries the formatted error message — see variant doc for why
    /// `#[from]` doesn't work for `ciborium::ser::Error<E>`.
    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    /// A CBOR float was found in a position the canonical CBOR profile
    /// (`docs/crypto-design.md` §6.2 #4) forbids. `field` is the
    /// entry-point hint passed by the caller.
    #[error("float values are not permitted in canonical CBOR (in field {field})")]
    FloatRejected {
        /// Entry-point hint identifying which subtree contained the float.
        /// Coarse-grained: usually `"<root>"` for the top-level walk and
        /// `"<unknown>"` for unknown-value walks. The walker does not
        /// thread per-key hints into nested subtrees.
        field: &'static str,
    },

    /// A CBOR tag was found in a position the canonical CBOR profile
    /// forbids. `field` is the entry-point hint passed by the caller.
    #[error("CBOR tags are not permitted in canonical CBOR (in field {field})")]
    TagRejected {
        /// Entry-point hint identifying which subtree contained the tag.
        /// See [`Self::FloatRejected::field`] for the granularity contract.
        field: &'static str,
    },
}

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
                .map_err(|e| CanonicalError::CborEncode(e.to_string()))?;
            Ok((key_bytes, pair.clone()))
        })
        .collect::<Result<_, CanonicalError>>()?;
    materialised.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(materialised.into_iter().map(|(_, pair)| pair).collect())
}

/// Encode an entry list as a top-level canonical-CBOR map.
///
/// Sorts via [`canonical_sort_entries`] (because `ciborium` emits a
/// `Value::Map`'s `Vec<(Value, Value)>` in iteration order, NOT in CBOR
/// canonical order), then serialises as a single definite-length map.
pub fn encode_canonical_map(
    entries: &[(Value, Value)],
) -> Result<Vec<u8>, CanonicalError> {
    let sorted = canonical_sort_entries(entries)?;
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(sorted), &mut buf)
        .map_err(|e| CanonicalError::CborEncode(e.to_string()))?;
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
pub fn reject_floats_and_tags(
    v: &Value,
    field_hint: &'static str,
) -> Result<(), CanonicalError> {
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
        let err = reject_floats_and_tags(&v, "<root>")
            .expect_err("float must be rejected");
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
        let err = reject_floats_and_tags(&v, "<root>")
            .expect_err("tag must be rejected");
        assert!(
            matches!(err, CanonicalError::TagRejected { field: "<root>" }),
            "expected TagRejected {{ field: \"<root>\" }}, got {err:?}"
        );
    }
}
