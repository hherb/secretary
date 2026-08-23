//! A borrowing mirror of the CBOR subset `docs/vault-format.md` uses.
//!
//! `ciborium::Value` owns its payloads. That ownership is precisely the defect
//! #547 records: encoding a record meant copying every decrypted field out of
//! its [`SecretString`](crate::crypto::secret::SecretString) wrapper into a
//! `Value::Text`, and then deep-cloning that copy two more times on the way
//! to the wire (`record.rs`'s two `canonical_sort_entries` calls, inner then
//! outer — `encode_canonical_map`'s own clone was already removed in Task 1).
//! A borrowing type serialises straight out of the wrapper, so the copy
//! never exists — as of Task 4, `record::record_to_canonical` /
//! `record::encode` do exactly that, and no call from production `record.rs`
//! into `canonical_sort_entries` survives.
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
//! [`CanonicalMap`] and [`CanonicalValue`] have a real production consumer
//! as of Task 4 (#547): `record::record_to_canonical` builds one directly
//! out of a `Record`'s fields, and `record::encode` serialises it via
//! [`to_canonical_vec`] — this file's `encode_canonical_map` counterpart,
//! declared `pub(crate)` (not `pub`) because `record.rs` is an in-crate
//! caller and needs nothing more. An earlier version, also named
//! `to_canonical_vec`, was deleted from this file in review round 1 of
//! Task 2 — see `task-2-report.md` — for returning a `Result<_,
//! CanonicalError>` that was unnameable through `canonical_test_api`, which
//! did not re-export `CanonicalError`. `block.rs`'s own plaintext encode is
//! unmigrated as of this step — a later build-sequence step's concern, not
//! this one's.
//!
//! [`CanonicalMap`] / [`CanonicalValue`] themselves stay `pub`, not
//! `pub(crate)`: the `#[doc(hidden)]` `canonical_test_api` module
//! `vault::mod` adds re-exports them so
//! `core/tests/canonical_value_equivalence.rs` can construct them directly
//! (`--cfg test` is not propagated to dependent crates, so a `#[cfg(test)]`
//! item would be invisible to that integration test). Before Task 4, that
//! `pub` path was ALSO what kept both types out of `dead_code`, for want of
//! any in-crate caller — see the rationale at the `pub use` in
//! `canonical/mod.rs` — but ordinary crate-internal usage does that now;
//! the test-reachability need is what keeps the visibility `pub`.
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

    /// Upper bound on this map's CBOR encoding length, for pre-reserving.
    /// Same contract as [`super::cbor_size_bound`]: over is harmless, under
    /// reopens the realloc hazard.
    ///
    /// Module-private (not `pub(crate)`): every caller — this impl's own
    /// recursive `CanonicalValue::size_bound` arm and [`to_canonical_vec`]
    /// — lives in this same file, so there is no cross-module need. An
    /// earlier round of this task over-widened both `size_bound` fns to
    /// `pub(crate)` without checking for one — unlike [`to_canonical_vec`]
    /// itself (a real `record.rs` caller) or [`CanonicalMap`] /
    /// [`CanonicalValue`] (`pub`, needed for `canonical_test_api`'s
    /// cross-crate integration-test reach), neither `size_bound` has ever
    /// had a caller outside this file. Narrowed back per review.
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
    /// [`CanonicalMap::size_bound`] for the contract and for why this is
    /// module-private, not `pub(crate)`.
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

/// Serialise a [`CanonicalMap`] to canonical CBOR bytes.
///
/// `pub(crate)`: this is reintroduced alongside its first real production
/// caller (`record::record_to_canonical`'s `encode`, #547 Task 4), so
/// nothing needs the `pub` + `canonical_test_api` re-export workaround an
/// earlier build-sequence step used to keep `CanonicalMap`/`CanonicalValue`
/// out of `dead_code` before either had a production consumer.
///
/// The output buffer is pre-reserved against the map's size-bound estimate
/// so `into_writer` cannot grow it: a realloc copies to a new block and
/// frees the old one **unwiped**, and on the record path that buffer holds
/// decrypted plaintext.
pub(crate) fn to_canonical_vec(map: &CanonicalMap<'_>) -> Result<Vec<u8>, CanonicalError> {
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
