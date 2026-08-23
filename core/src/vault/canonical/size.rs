//! Upper bound on a `ciborium::Value`'s CBOR encoding length.
//!
//! Used only to pre-reserve an output buffer so `ciborium::ser::into_writer`
//! never grows it. A realloc copies the buffer to a new block and frees the
//! old one **unwiped**, which for a plaintext-bearing encode is exactly the
//! hazard [`crate::crypto::secret::SecretBytes::concat`] (#524) exists to
//! prevent.
//!
//! Never an exact size. Being over is harmless (the only cost is slack);
//! being under reopens the hazard, so every arm rounds up.
//!
//! Moved here from `unlock::bundle` (#547) and **made recursive**. The
//! bundle's version returned `HEAD_MAX` for the container arms, which was
//! sound only because that module's entry lists are flat — a fact its
//! `ZeroizingEntries::new` `debug_assert` pinned. The record path nests a
//! per-field map inside an outer map inside an array, so a flat bound would
//! under-reserve.

use ciborium::Value;

/// Largest CBOR head: initial byte plus an 8-byte argument (RFC 8949 §3).
const HEAD_MAX: usize = 9;

/// Upper bound on the CBOR encoding length of `value`, including its head.
///
/// Recurses without an explicit depth bound, for the same reason
/// [`super::reject_floats_and_tags`] does: `ciborium`'s default `from_reader`
/// recursion limit (256) has already capped the depth of any parsed tree, and
/// trees we construct ourselves are shallow by shape. If a future contributor
/// raises that parser limit, add a `depth` parameter here too.
pub(crate) fn cbor_size_bound(value: &Value) -> usize {
    HEAD_MAX
        + match value {
            Value::Bytes(b) => b.len(),
            Value::Text(t) => t.len(),
            Value::Array(items) => items.iter().map(cbor_size_bound).sum(),
            Value::Map(entries) => entries
                .iter()
                .map(|(k, v)| cbor_size_bound(k) + cbor_size_bound(v))
                .sum(),
            Value::Tag(_, inner) => cbor_size_bound(inner),
            // Integer / Float / Bool / Null, and anything `#[non_exhaustive]`
            // adds later, are bounded by HEAD_MAX alone: every one of them is
            // a single CBOR head with no payload beyond its argument. A novel
            // variant that carried a payload would under-reserve here, which
            // is why the callers `debug_assert!` their actual length against
            // the bound rather than trusting it.
            _ => 0,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle's original `cbor_size_bound` returned `HEAD_MAX` for every
    /// container arm, which UNDER-reserves on a nested tree. Under-reserving
    /// is the whole hazard: `into_writer` then grows the buffer, and a realloc
    /// frees the old block — holding plaintext — unwiped.
    #[test]
    fn size_bound_is_not_under_reserved_for_a_nested_tree() {
        let inner = Value::Map(vec![
            (Value::Text("value".into()), Value::Text("x".repeat(300))),
            (Value::Text("bytes".into()), Value::Bytes(vec![0xAB; 400])),
        ]);
        let tree = Value::Array(vec![inner.clone(), inner]);

        let mut actual = Vec::new();
        ciborium::ser::into_writer(&tree, &mut actual).expect("encode");

        assert!(
            cbor_size_bound(&tree) >= actual.len(),
            "bound {} under-reserved for actual {} bytes",
            cbor_size_bound(&tree),
            actual.len()
        );
    }

    #[test]
    fn size_bound_covers_every_scalar_arm() {
        for v in [
            Value::Integer(u64::MAX.into()),
            Value::Bool(true),
            Value::Null,
            Value::Text(String::new()),
            Value::Bytes(Vec::new()),
        ] {
            let mut actual = Vec::new();
            ciborium::ser::into_writer(&v, &mut actual).expect("encode");
            assert!(
                cbor_size_bound(&v) >= actual.len(),
                "under-reserved for {v:?}"
            );
        }
    }
}
