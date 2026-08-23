//! A borrowing mirror of the CBOR subset `docs/vault-format.md` uses.
//!
//! `ciborium::Value` owns its payloads. That ownership is precisely the defect
//! #547 records: encoding a record meant copying every decrypted field out of
//! its [`SecretString`](crate::crypto::secret::SecretString) wrapper into a
//! `Value::Text`, and then deep-cloning that copy two more times on the way
//! to the wire (`record.rs`'s two `canonical_sort_entries` calls, inner then
//! outer — `encode_canonical_map`'s own clone was already removed in Task 1,
//! so this is two, not three, as of `main`). A borrowing type serialises
//! straight out of the wrapper, so the copy never exists.
//!
//! [`CanonicalMap`] sorts its own keys at SERIALISE time, per RFC 8949
//! §4.2.1. That is what lets nested maps stay borrowed: the previous design
//! had to sort each level eagerly and materialise a `Value::Map` to hand
//! upward, because `ciborium` emits a `Value::Map`'s entries in iteration
//! order with no recursive sort.
//!
//! **No key buffer is ever materialised.** `CanonicalMap`'s keys are always
//! `&'a str`, and for a CBOR text key the canonical order (RFC 8949 §4.2.1:
//! sort by the deterministic encoding of the key) reduces exactly to
//! ordering on `(byte length, bytes)` — a text head's length prefix is a
//! monotonic function of the string's byte length, so that comparison and
//! "compare the two keys' full CBOR encodings" always agree. The sort
//! therefore reads straight through the borrowed `&str`s and never encodes
//! one into a temporary buffer. This matters because a key here is not
//! always safe to copy: `record.fields` is keyed by user-authored field
//! names living inside an encrypted record — decrypted plaintext, the same
//! class of data `RecordError::DuplicateKey` used to leak by formatting one
//! (#474) — and `record.unknown` / `field.unknown` keys come straight off
//! the wire. The earlier draft of this module claimed the (then-existing)
//! sort buffer "was not secret-bearing"; that claim was false. The fix is
//! not to wipe the buffer — it is to have none.
//!
//! No production consumer yet (#547 Task 2): [`CanonicalMap`] and
//! [`CanonicalValue`] are declared `pub` so the `#[doc(hidden)]`
//! `canonical_test_api` module `vault::mod` adds can re-export them, which
//! is what lets `core/tests/canonical_value_equivalence.rs` pin the
//! byte-identity property (`--cfg test` is not propagated to dependent
//! crates, so a `#[cfg(test)]` item would be invisible to that integration
//! test). Reachability through that `pub` path is also what keeps both out
//! of `dead_code` in the meantime — see the rationale at the `pub use` in
//! `canonical/mod.rs`. Tasks 4 and 5 migrate the record and block encode
//! paths onto this type, reintroducing an `encode_canonical_map` counterpart
//! (`to_canonical_vec`, deleted from this file in review round 1 — see
//! `task-2-report.md` — for having a `Result<_, CanonicalError>` return type
//! that was unnameable through `canonical_test_api`, which did not
//! re-export `CanonicalError`) alongside its first real caller.
//!
//! Neither [`CanonicalValue`] nor [`CanonicalMap`] derives `Debug`. That is
//! deliberate, not an oversight — a type that borrows secret-bearing text
//! and bytes should not gain a formatter that prints them; do not add one.
//!
//! [`CanonicalValue::Borrowed`] holds a `&'a ciborium::Value`, and both it
//! and [`Value`] itself are reachable through the `pub`
//! `canonical_test_api::CanonicalValue` path (see above) — this is the
//! first place `ciborium::Value` enters `secretary-core`'s public API
//! surface, `#[doc(hidden)]` or not. A future `ciborium` major-version bump
//! is therefore a semver-relevant, potentially breaking change for this
//! crate, not merely an internal dependency bump.

use ciborium::Value;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Serialize, Serializer};

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
    /// See the module doc for the public-API-surface consequence of this
    /// arm holding a `&'a ciborium::Value`.
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
}

impl Serialize for CanonicalMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // RFC 8949 §4.2.1 canonical key order, specialised to TEXT keys
        // (the only key type this type supports): ordering on
        // `(byte length, bytes)` is exactly equivalent to ordering on each
        // key's full CBOR encoding, because a CBOR text head's length
        // prefix is a monotonic function of the string's byte length. So
        // this comparator never encodes a key — it reads straight through
        // the borrowed `&str`s in `self.0` and materialises nothing. There
        // is no key buffer here to worry about being secret-bearing (see
        // the module doc): nothing is copied out of the key to begin with.
        //
        // `.len()` on `&str` is BYTE length, not char count — load-bearing:
        // a multi-byte UTF-8 key (e.g. 3-byte "日") must sort by its 3 CBOR
        // payload bytes, not by its 1 char, or the order would diverge from
        // the real CBOR head. `core/tests/canonical_value_equivalence.rs`
        // pins this with a key pair that would sort the other way under a
        // char-count comparator.
        let mut order: Vec<usize> = (0..self.0.len()).collect();
        order.sort_by(|&a, &b| {
            let (ka, kb) = (self.0[a].0, self.0[b].0);
            ka.len()
                .cmp(&kb.len())
                .then_with(|| ka.as_bytes().cmp(kb.as_bytes()))
        });

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for i in order {
            let (key, value) = &self.0[i];
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
