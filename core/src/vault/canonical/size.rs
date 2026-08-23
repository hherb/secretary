//! Upper bound on a `ciborium::Value`'s CBOR encoding length.
//!
//! Used only to pre-reserve an output buffer so `ciborium::ser::into_writer`
//! never grows it. A realloc copies the buffer to a new block and frees the
//! old one **unwiped**, which for a plaintext-bearing encode is exactly the
//! hazard [`crate::crypto::secret::SecretBytes::concat`] (#524) exists to
//! prevent. [`super::legacy::encode_canonical_map`] backs this bound with a
//! real runtime check (not a `debug_assert!`, which compiles out of every
//! release build — see [`super::CanonicalError::CapacityBoundExceeded`]) that
//! DETECTS a wrong bound after the fact; it cannot prevent the realloc it
//! catches, since by the time it runs the encode has already happened.
//!
//! Never an exact size. Being over is harmless (the only cost is slack);
//! being under reopens the hazard, so every arm rounds up.
//!
//! Copied here from `unlock::bundle` (#547) — the original still lives at
//! `bundle.rs`'s own `cbor_size_bound` until Task 7 deletes it — and **made
//! recursive**. The bundle's version returns `HEAD_MAX` for a container
//! *arm* (i.e. `HEAD_MAX + HEAD_MAX` = 18 for the function as a whole, since
//! the outer `HEAD_MAX +` in that version is unconditional), which is sound
//! only because that module's entry lists are flat — a fact its
//! `ZeroizingEntries::new` `debug_assert` pins. The record path nests a
//! per-field map inside an outer map inside an array, so a flat bound would
//! under-reserve.

use ciborium::Value;

/// Largest CBOR head: initial byte plus an 8-byte argument (RFC 8949 §3).
pub(crate) const HEAD_MAX: usize = 9;

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
            // Integer / Float / Bool / Null are single CBOR heads with no
            // payload beyond their argument, so HEAD_MAX alone (the
            // unconditional `HEAD_MAX +` above) already covers them and this
            // arm need add nothing more.
            //
            // `ciborium::Value` is `#[non_exhaustive]`: a future variant
            // this match cannot name also falls here. We cannot know whether
            // such a variant would carry a payload, so — matching the bundle
            // original this is modelled on — the wildcard rounds up
            // defensively by another HEAD_MAX rather than assuming zero.
            // `encode_canonical_map`'s runtime check is the backstop if even
            // that turns out to be wrong.
            _ => HEAD_MAX,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle's original `cbor_size_bound` returns `HEAD_MAX` for a
    /// container *arm* (18 total for the function, per the module doc),
    /// which UNDER-reserves on a nested tree. Under-reserving is the whole
    /// hazard: `into_writer` then grows the buffer, and a realloc frees the
    /// old block — holding plaintext — unwiped.
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
            Value::Float(1.5),
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

    /// The `Tag` arm recurses into its inner value rather than falling into
    /// the scalar wildcard. A large inner payload proves the recursion
    /// actually ran: if `Tag` fell into the wildcard instead, the bound
    /// would be `HEAD_MAX` (9) plus the wildcard's own `HEAD_MAX` (9) — 18
    /// total, far short of the inner text's ~300-byte encoding.
    #[test]
    fn size_bound_recurses_into_tag_arm() {
        let tagged = Value::Tag(0, Box::new(Value::Text("x".repeat(300))));

        let mut actual = Vec::new();
        ciborium::ser::into_writer(&tagged, &mut actual).expect("encode");

        assert!(
            cbor_size_bound(&tagged) >= actual.len(),
            "bound {} under-reserved for actual {} bytes",
            cbor_size_bound(&tagged),
            actual.len()
        );
    }
}
