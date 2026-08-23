//! A borrowing mirror of the CBOR subset `docs/vault-format.md` uses.
//!
//! `ciborium::Value` owns its payloads. That ownership is precisely the defect
//! #547 records: encoding a record meant copying every decrypted field out of
//! its [`SecretString`](crate::crypto::secret::SecretString) wrapper into a
//! `Value::Text`, and then deep-cloning that copy three more times on the way
//! to the wire. A borrowing type serialises straight out of the wrapper, so
//! the copy never exists.
//!
//! [`CanonicalMap`] sorts its own keys at SERIALISE time, per RFC 8949
//! §4.2.1. That is what lets nested maps stay borrowed: the previous design
//! had to sort each level eagerly and materialise a `Value::Map` to hand
//! upward, because `ciborium` emits a `Value::Map`'s entries in iteration
//! order with no recursive sort.
//!
//! **Only KEYS are ever materialised**, to sort on. A key is a field name
//! from the vault schema or a forward-compat unknown key — never a value —
//! so the sort buffer is not secret-bearing.
//!
//! No production consumer yet (#547 Task 2): [`CanonicalMap`],
//! [`CanonicalValue`] and [`to_canonical_vec`] are declared `pub` so the
//! `#[doc(hidden)]` `canonical_test_api` module `vault::mod` adds can
//! re-export them, which is what lets
//! `core/tests/canonical_value_equivalence.rs` pin the byte-identity
//! property (`--cfg test` is not propagated to dependent crates, so a
//! `#[cfg(test)]` item would be invisible to that integration test).
//! Reachability through that `pub` path is also what keeps all three out of
//! `dead_code` in the meantime — see the rationale at the `pub use` in
//! `canonical/mod.rs`. Tasks 4 and 5 migrate the record and block encode
//! paths onto this type.

use ciborium::Value;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Serialize, Serializer};

use super::CanonicalError;
use crate::cbor::classify_ser;

/// One value in a canonical map or array. Every arm either borrows or is a
/// scalar; no arm owns a byte string.
pub enum CanonicalValue<'a> {
    /// Borrowed UTF-8 text — typically `SecretString::expose()`.
    Text(&'a str),
    /// Borrowed bytes — typically `SecretBytes::expose()` or a uuid array.
    Bytes(&'a [u8]),
    /// An unsigned integer (clocks, versions, timestamps).
    Uint(u64),
    /// A boolean (`tombstone`).
    Bool(bool),
    /// A nested map, which sorts its own keys when serialised.
    Map(CanonicalMap<'a>),
    /// A homogeneous sequence (`tags`, `records`).
    Array(Vec<CanonicalValue<'a>>),
    /// A forward-compat unknown value, emitted verbatim.
    ///
    /// This version cannot know a future version's shape, so the subtree is
    /// passed through as a borrow rather than mirrored. It costs no copy.
    Borrowed(&'a Value),
}

/// A CBOR map whose keys are sorted at serialise time.
///
/// Construct with [`Self::with_capacity`] and [`Self::push`]; the push order
/// is irrelevant, because [`Serialize`] imposes the canonical order.
pub struct CanonicalMap<'a>(Vec<(&'a str, CanonicalValue<'a>)>);

impl<'a> CanonicalMap<'a> {
    /// An empty map with room for `n` entries.
    pub fn with_capacity(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }

    /// Append an entry. Order is not significant — [`Serialize`] sorts.
    pub fn push(&mut self, key: &'a str, value: CanonicalValue<'a>) {
        self.0.push((key, value));
    }

    /// Upper bound on this map's CBOR encoding length, for pre-reserving.
    /// Same contract as [`super::cbor_size_bound`]: over is harmless, under
    /// reopens the realloc hazard.
    fn size_bound(&self) -> usize {
        super::HEAD_MAX
            + self
                .0
                .iter()
                .map(|(k, v)| super::HEAD_MAX + k.len() + v.size_bound())
                .sum::<usize>()
    }
}

impl CanonicalValue<'_> {
    /// Upper bound on this value's CBOR encoding length. See
    /// [`CanonicalMap::size_bound`] for the contract.
    fn size_bound(&self) -> usize {
        match self {
            Self::Text(t) => super::HEAD_MAX + t.len(),
            Self::Bytes(b) => super::HEAD_MAX + b.len(),
            Self::Uint(_) | Self::Bool(_) => super::HEAD_MAX,
            Self::Map(m) => m.size_bound(),
            Self::Array(items) => {
                super::HEAD_MAX + items.iter().map(Self::size_bound).sum::<usize>()
            }
            Self::Borrowed(v) => super::cbor_size_bound(v),
        }
    }
}

impl Serialize for CanonicalMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // RFC 8949 §4.2.1: sort by the deterministic CBOR encoding of each
        // key, length-then-bytewise. Materialising the KEY is safe — a key is
        // a schema field name or an unknown key, never a value.
        //
        // Sorting a `Vec<(Vec<u8>, usize)>` of (encoded key, index) keeps the
        // values themselves untouched and unmoved.
        let mut order: Vec<(Vec<u8>, usize)> = Vec::with_capacity(self.0.len());
        for (i, (key, _)) in self.0.iter().enumerate() {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(key, &mut key_bytes).map_err(serde::ser::Error::custom)?;
            order.push((key_bytes, i));
        }
        order.sort_by(|a, b| a.0.cmp(&b.0));

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (_, i) in &order {
            let (key, value) = &self.0[*i];
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl Serialize for CanonicalValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(t) => serializer.serialize_str(t),
            Self::Bytes(b) => serializer.serialize_bytes(b),
            Self::Uint(u) => serializer.serialize_u64(*u),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Map(m) => m.serialize(serializer),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Borrowed(v) => v.serialize(serializer),
        }
    }
}

/// Serialise a [`CanonicalMap`] to canonical CBOR bytes.
///
/// The output buffer is pre-reserved against the map's (private) size-bound
/// estimate so `into_writer` cannot grow it: a realloc copies to a new block
/// and frees the old one **unwiped**, and on the record path that buffer
/// holds decrypted plaintext.
pub fn to_canonical_vec(map: &CanonicalMap<'_>) -> Result<Vec<u8>, CanonicalError> {
    let bound = map.size_bound();
    let mut buf = Vec::with_capacity(bound);
    ciborium::ser::into_writer(map, &mut buf)
        .map_err(|e| CanonicalError::CborEncode(classify_ser(&e)))?;

    // Real runtime check, not `debug_assert!`: this crate's only
    // `debug-assertions = true` is `core/fuzz/Cargo.toml`, which is
    // `exclude`d from the workspace, so a `debug_assert!` here would be a
    // no-op in `cargo test --release`, in `cargo build --release`, and in
    // every shipped artifact. Mirrors `legacy::encode_canonical_map`'s check
    // exactly. This DETECTS an under-reserve after the fact — by the time it
    // runs, `into_writer` has already grown the buffer if it needed to, and
    // the old (possibly plaintext-bearing) allocation is already freed
    // unwiped. It is a tripwire for a future `ciborium::Value` variant
    // `size.rs` cannot name, not a preventive guarantee.
    if buf.len() > bound {
        return Err(CanonicalError::CapacityBoundExceeded {
            actual: buf.len(),
            bound,
        });
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `to_canonical_vec` must not grow its output buffer. A realloc copies
    /// to a new block and frees the old one unwiped — the hazard this
    /// function's pre-reservation exists to prevent (see
    /// `legacy::encode_canonical_map_does_not_realloc`, which pins the same
    /// property for the `Value`-based encoder this type mirrors).
    #[test]
    fn to_canonical_vec_does_not_realloc() {
        let names: Vec<String> = (0..40).map(|i| format!("k{i:03}")).collect();
        let values: Vec<Vec<u8>> = (0..40).map(|i| vec![0xCDu8; 100 + i]).collect();

        let mut map = CanonicalMap::with_capacity(names.len());
        for (name, bytes) in names.iter().zip(values.iter()) {
            map.push(name, CanonicalValue::Bytes(bytes));
        }

        let out = to_canonical_vec(&map).expect("encode");
        let bound = map.size_bound();
        assert_eq!(
            out.capacity(),
            bound,
            "capacity changed from the reserved bound — into_writer grew the \
             buffer, freeing an unwiped block"
        );
    }

    /// `to_canonical_vec`'s output matches directly serialising the same
    /// `CanonicalMap` — i.e. the pre-reservation wrapper changes nothing
    /// about the emitted bytes, only how the buffer is allocated.
    #[test]
    fn to_canonical_vec_matches_direct_serialize() {
        let mut map = CanonicalMap::with_capacity(2);
        map.push("b", CanonicalValue::Uint(2));
        map.push("a", CanonicalValue::Uint(1));

        let via_helper = to_canonical_vec(&map).expect("encode via helper");

        let mut direct = Vec::new();
        ciborium::ser::into_writer(&map, &mut direct).expect("encode directly");

        assert_eq!(via_helper, direct);
    }
}
