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
//! Task 2, for returning a `Result<_, CanonicalError>` that was unnameable
//! through `canonical_test_api`, which did not re-export `CanonicalError`.
//! (That sentence cited `task-2-report.md` until the #560 review; the
//! per-task SDD reports live under a gitignored `.superpowers/` and are not
//! in the repo, so the pointer could not be followed — the conclusion is
//! inlined here instead.) `block.rs`'s own plaintext encode was
//! unmigrated as of Task 4 — that changed in Task 5, which moved
//! `block::encode_plaintext` onto `record::record_to_canonical` too (see
//! `canonical/mod.rs`'s module doc for the detail); production `block.rs`
//! calls neither `record::encode` nor `legacy::encode_canonical_map` any
//! more.
//!
//! A THIRD consumer joined later, on a separate slice: the
//! cbor-residue-closeout follow-up (#569) migrated
//! `unlock::bundle::IdentityBundle::to_canonical_cbor` onto `CanonicalMap`
//! directly (not through `record_to_canonical` — the bundle's fields don't
//! share a `Record`'s shape), eliminating four long-term secret-key copies
//! per encode. Which files call this module is deliberately not tracked as
//! a running list past this point, for the reason `canonical/mod.rs`'s own
//! module doc gives for not enumerating them at all: read the callers
//! directly (`grep -rn "CanonicalMap::with_capacity" core/src`) rather than
//! trusting a count that has already needed correcting twice.
//!
//! [`CanonicalMap`] / [`CanonicalValue`] are `pub(crate)`, matching the
//! `canonical` module they live in — and as of the #560 review that is
//! true of the DECLARATIONS, not merely of the effective visibility. Both
//! types (and `CanonicalMap`'s `with_capacity` / `push`) were declared
//! bare `pub` while this paragraph and three others already claimed
//! `pub(crate)`; the crate boundary came entirely from `mod value;` being
//! private and `vault/mod.rs`'s `pub(crate) mod canonical;`. That is open
//! issue #559, and the risk it names is real: changing one keyword in
//! ANOTHER file would have published both types — and, through
//! [`CanonicalValue::Borrowed`], the `#[non_exhaustive]` `ciborium::Value`
//! — with no local signal, because the items themselves said `pub`. The
//! declarations now carry the restriction they are documented as having.
//! An earlier version of this branch made
//! them `pub` instead, re-exported through a `#[doc(hidden)]`
//! `vault::canonical_test_api` module, so that `core/tests/
//! canonical_value_equivalence.rs` could construct them directly from an
//! integration test (`--cfg test` is not propagated to dependent crates, so
//! a `#[cfg(test)]` item is invisible there). The final whole-branch review
//! of #547 found that reasoning wrong on two counts: it put a third-party
//! `#[non_exhaustive]` enum (`ciborium::Value`, via
//! [`CanonicalValue::Borrowed`]) into this crate's public API surface for a
//! type whose stated purpose is decades-long readability — the exact
//! pattern `cbor::secret_tree`'s module doc records rejecting, for the same
//! reason, for `SecretValueTree`/`SecretEntries` — and the premise that the
//! byte-identity proof *needed* to be an integration test was itself false:
//! a `#[cfg(test)] mod tests` in this file runs on every CI run just as an
//! integration test does. That proof now lives in this file's own test
//! module below; `canonical_test_api` and the integration test file are
//! gone.
//!
//! Neither [`CanonicalValue`] nor [`CanonicalMap`] derives `Debug`. That is
//! deliberate, not an oversight — a type that borrows secret-bearing text
//! and bytes should not gain a formatter that prints them; do not add one.
//!
//! [`CanonicalValue::Borrowed`] holds a `&'a ciborium::Value`, so
//! `ciborium::Value` reaches this file's public-to-the-crate surface, but
//! not the crate's *external* one: both [`CanonicalValue`] and [`Value`]
//! are `pub(crate)` / re-exported at `pub(crate)`, so a future `ciborium`
//! major-version bump stays an ordinary internal dependency bump, not a
//! semver-relevant one for `secretary-core` itself.

use ciborium::Value;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Serialize, Serializer};

use super::CanonicalError;
use crate::cbor::classify_ser;

/// One value in a canonical map or array. Every arm either borrows or is a
/// scalar; no arm owns a byte string.
pub(crate) enum CanonicalValue<'a> {
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
pub(crate) struct CanonicalMap<'a>(Vec<(&'a str, CanonicalValue<'a>)>);

impl<'a> CanonicalMap<'a> {
    /// An empty map with room for `n` entries.
    pub(crate) fn with_capacity(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }

    /// Append an entry. Order is not significant — [`Serialize`] sorts.
    pub(crate) fn push(&mut self, key: &'a str, value: CanonicalValue<'a>) {
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
    /// itself (a real `record.rs` caller), neither `size_bound` has ever
    /// had a caller outside this file. Narrowed back per review. (`CanonicalMap`
    /// / `CanonicalValue` themselves were `pub`, for `canonical_test_api`'s
    /// cross-crate integration-test reach, at the time this comment was
    /// first written; both are `pub(crate)` now — see the module doc.)
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
        // The general equivalence claim in the paragraph above — ordering
        // on `(byte length, bytes)` matches ordering on the full CBOR
        // encoding, for any pair of strings — is pinned by the proptest
        // `len_then_bytes_matches_full_cbor_encoding_order`, in this
        // file's own test module below (#567).
        //
        // `.len()` on `&str` is BYTE length, not char count — load-bearing:
        // a multi-byte UTF-8 key (e.g. 3-byte "日") must sort by its 3 CBOR
        // payload bytes, not by its 1 char, or the order would diverge from
        // the real CBOR head. `map_key_sort_crosses_head_length_boundary_and_uses_byte_not_char_length`,
        // in this file's own test module below, pins this with a key pair
        // that would sort the other way under a char-count comparator.
        // (That citation read `core/tests/canonical_value_equivalence.rs`
        // until the #560 review — a file this branch DELETED when the
        // proof moved in here; the test survived the move, only its home
        // changed.)
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

    // -----------------------------------------------------------------
    // Byte-identity equivalence: CanonicalValue/CanonicalMap vs. ciborium::Value
    // -----------------------------------------------------------------
    //
    // The load-bearing byte-identity claim of #547: a hand-written
    // `Serialize` over borrowed data emits CBOR byte-identical to the
    // equivalent owned `ciborium::Value` tree, across every CBOR
    // head-length boundary.
    //
    // If this ever fails, the on-disk format has moved and the vault is
    // unreadable by every client written before the change. It used to live
    // in `core/tests/canonical_value_equivalence.rs` as an integration
    // test, on the belief that a `#[cfg(test)]` unit test would be invisible
    // to that kind of check; that belief was wrong (see this file's module
    // doc). Moved here so `CanonicalMap`/`CanonicalValue` can go back to
    // `pub(crate)` — every test below runs on every `cargo test`, exactly
    // as it did as an integration test.

    fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::ser::into_writer(v, &mut b).expect("encode");
        b
    }

    /// Every CBOR head-length boundary: the argument is inline (<24), then
    /// 1, 2, 4 and 8 additional bytes (RFC 8949 §3).
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
        // Uses the shared `LEN_BOUNDARIES` (#560 review). This test and its
        // map twin below previously stopped at 300, i.e. inside the 2-byte
        // head class — so the `0x99` -> `0x9A` transition at 65536, where a
        // CBOR container head grows from a 2-byte to a 4-byte argument, was
        // the one head-length boundary the byte-identity proof never
        // crossed for a CONTAINER. The scalar arms (uint / text / bytes)
        // already swept the full list. Divergence is unlikely, since both
        // sides route through the same ciborium head writer — but "unlikely"
        // is not the bar for a format frozen for decades.
        for &n in LEN_BOUNDARIES {
            let owned = Value::Array((0..n).map(|i| Value::Integer((i as u64).into())).collect());
            let borrowed =
                CanonicalValue::Array((0..n).map(|i| CanonicalValue::Uint(i as u64)).collect());
            assert_eq!(enc(&owned), enc(&borrowed), "array len {n}");
        }
    }

    /// The map arm additionally proves the SORT: keys are pushed in an order
    /// that is not canonical, and the emitted bytes must match the literal
    /// CBOR encoding of the canonically-sorted map.
    ///
    /// The oracle here is a hardcoded expected byte vector, not a second
    /// invocation of "encode each key then sort the encodings" — that
    /// would-be oracle used to be exactly the algorithm this test is
    /// supposed to be checking `CanonicalMap` *against*, so it proved only
    /// that two implementations of the same idea agree with each other, not
    /// that either agrees with real CBOR. That distinction became
    /// load-bearing once `CanonicalMap`'s own comparator stopped encoding
    /// keys at all (review round 1 of #547 Task 2) and switched to
    /// comparing `(byte length, bytes)` directly — a hand-derived byte
    /// vector is independent of both.
    #[test]
    fn map_is_byte_identical_and_sorts_its_own_keys() {
        // "z" (1 byte) sorts BEFORE "ab" (2 bytes) in canonical CBOR, and
        // AFTER it in plain string order. Pushing in string order proves
        // the encoder re-sorts rather than emitting insertion order.
        let keys = ["ab", "z", "aaa", "b"];
        let mut borrowed = CanonicalMap::with_capacity(keys.len());
        for (i, k) in keys.iter().enumerate() {
            borrowed.push(k, CanonicalValue::Uint(i as u64));
        }

        // Canonical order (length-then-bytewise) is "b" < "z" < "ab" <
        // "aaa", carrying values 3, 1, 0, 2 respectively (the index each
        // key was pushed at above). Derived by hand from RFC 8949 §4.2.1,
        // not computed by any sort call:
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
    /// text-head length class, and the four-key sort test above uses keys
    /// of 1-3 bytes, all within the single-byte-head class (0-23). This
    /// test pushes a 23-byte key (single-byte head `0x77`) and a 24-byte
    /// key (two-byte head `0x78 0x18`) — RFC 8949's exact head-length
    /// transition — plus a pair chosen so that sorting by CHAR count
    /// instead of BYTE length would put them in the wrong order: "ab" is 2
    /// bytes/2 chars, "日" is 3 bytes/1 char, so a char-count comparator
    /// would rank "日" before "ab" while the correct byte-length comparator
    /// ranks "ab" first. All four are pushed in scrambled order.
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

        // Canonical order is ascending BYTE length: short(2) < multibyte(3)
        // < boundary_23(23) < boundary_24(24). Listed here already in that
        // order — this is a hand-asserted expectation, not a sort call, so
        // it does not restate the algorithm under test.
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
        // Full `LEN_BOUNDARIES` sweep (#560 review) — see the array twin
        // above for why stopping at 300 left the 65536 container-head
        // transition unproven. The `{i:05}` width keeps every key 6 bytes
        // even at n = 65536 (max index 65535, 5 digits), so the sort stays
        // a pure bytewise comparison at every n and this test keeps
        // measuring the HEAD, not the comparator — which
        // `map_key_sort_crosses_head_length_boundary_and_uses_byte_not_char_length`
        // covers separately.
        for &n in LEN_BOUNDARIES {
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

    /// The exact shape the record path emits: an outer map holding an array
    /// of per-record maps, each holding a per-field map with a text secret,
    /// an integer clock and a byte uuid.
    #[test]
    fn nested_record_in_block_shape_is_byte_identical() {
        let secret = "hunter2";
        let device_uuid = [7u8; 16];

        // `ciborium::Value::Map`'s `Serialize` emits entries in Vec order —
        // it does NOT sort them (`size.rs`'s module doc and `CanonicalMap`'s
        // own doc both say so). So this "equivalent owned tree" must
        // already be listed in canonical order (length-then-bytewise:
        // "value" (5) < "last_mod" (8) < "device_uuid" (11)) for the
        // comparison below to be meaningful — `CanonicalMap` sorts at
        // serialise time regardless of push order, so it would reach the
        // same bytes from any push order.
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

        // Pushed OUT of canonical order (8-byte key before the 5-byte key)
        // so the nested `Map` arm's own sort is load-bearing for this
        // test: with the earlier in-order push, this test would pass even
        // if `Serialize` for a nested `CanonicalMap` silently emitted push
        // order instead of sorting — "nested maps sort themselves" is the
        // type's headline claim and this is what actually pins it.
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

    /// `enc_text` is written locally on purpose. Reusing the production
    /// encoder would make the test circular.
    fn enc_text(s: &str) -> Vec<u8> {
        let n = s.len();
        let mut out = Vec::with_capacity(n + 9);
        // RFC 8949 §3: major type 3 (text string) is 0b011_xxxxx.
        const MAJOR_TEXT: u8 = 0x60;
        match n {
            0..=23 => out.push(MAJOR_TEXT | n as u8),
            24..=0xFF => {
                out.push(MAJOR_TEXT | 24);
                out.push(n as u8);
            }
            0x100..=0xFFFF => {
                out.push(MAJOR_TEXT | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            0x1_0000..=0xFFFF_FFFF => {
                out.push(MAJOR_TEXT | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            _ => {
                out.push(MAJOR_TEXT | 27);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(s.as_bytes());
        out
    }

    proptest::proptest! {
        /// The `(byte length, bytes)` comparator `CanonicalMap::serialize`
        /// uses must be *exactly* RFC 8949 §4.2.1 order — i.e. identical to
        /// ordering on each key's full CBOR encoding.
        ///
        /// This is the property that lets the sort read straight through
        /// the borrowed `&str`s and materialise no key buffer, which is
        /// the whole security point: record field names are decrypted
        /// plaintext. If it ever breaks, the on-disk format moves
        /// silently.
        ///
        /// It has been checked twice by exhaustive sweep (184,041 pairwise
        /// comparisons; 400,000 in an independent reproduction) and
        /// neither sweep was committed — both lived in prose (#567). This
        /// makes it permanent. `golden_vault_001` cannot cover it: every
        /// key there is ASCII, so a byte-length -> char-count regression
        /// yields byte-identical output for that vault (#562).
        ///
        /// **It drives `CanonicalMap::serialize`, and the first version of
        /// it did not** (#575 review). That version compared
        /// `(a.len(), a.as_bytes()).cmp(..)` — an expression written in
        /// this test — against `enc_text`, so it proved a mathematical
        /// fact about RFC 8949 and touched no production code: mutating
        /// the real comparator to `chars().count()` left it GREEN. The
        /// second half below closes that by pushing both keys into a real
        /// `CanonicalMap` and asserting the SERIALIZED key order, which is
        /// the only thing that makes this a pin rather than a proof.
        /// Verified by mutation in both directions.
        ///
        /// Counterexamples from this test ARE committed — the one exception to
        /// the project's "do not commit proptest regressions" policy, carved out
        /// in `.gitignore` (#577). The reason is the paragraph above: this is a
        /// format-freezing property whose only other anchors are ASCII-only
        /// fixtures (#562), so a CI failure here must yield a replayable seed
        /// rather than a message.
        ///
        /// **The carve-out is keyed on the MODULE FILE, not on this test.**
        /// `proptest` names its regression file after the module path, so the
        /// negation re-includes `core/proptest-regressions/vault/canonical/
        /// value.txt` — every proptest in THIS file, not just this one. There
        /// is exactly one today. A second proptest added here would have its
        /// counterexamples become committable with no signal, so either keep
        /// this file to one proptest or widen `.gitignore` deliberately.
        #[test]
        fn len_then_bytes_matches_full_cbor_encoding_order(a: String, b: String) {
            let by_parts = (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()));
            let by_encoding = enc_text(&a).cmp(&enc_text(&b));
            proptest::prop_assert_eq!(
                by_parts,
                by_encoding,
                "comparator diverged from RFC 8949 4.2.1 for {:?} vs {:?}",
                a,
                b
            );

            // ...and the PRODUCTION comparator must agree with that same
            // ordering. Two distinct keys only: `CanonicalMap` does not
            // deduplicate, and a duplicate key would make "which came
            // first" meaningless rather than wrong.
            if a != b {
                let mut m = CanonicalMap::with_capacity(2);
                // Pushed in the order the comparator must REVERSE whenever
                // `b` sorts first, so a comparator that ignored its input
                // entirely (e.g. a stable no-op sort) would fail half the
                // generated cases rather than passing by luck.
                m.push(&a, CanonicalValue::Uint(0));
                m.push(&b, CanonicalValue::Uint(1));

                let expected_first = if by_encoding == std::cmp::Ordering::Less { &a } else { &b };
                let owned_first = Value::Text(expected_first.clone());

                let parsed: Value = ciborium::de::from_reader(enc(&m).as_slice())
                    .expect("CanonicalMap must serialize to parseable CBOR");
                let Value::Map(entries) = parsed else {
                    return Err(proptest::test_runner::TestCaseError::fail(
                        "CanonicalMap must serialize to a CBOR map",
                    ));
                };
                proptest::prop_assert_eq!(
                    &entries[0].0,
                    &owned_first,
                    "CanonicalMap::serialize emitted the wrong key first for {:?} vs {:?}",
                    a,
                    b
                );
            }
        }
    }

    /// `proptest`'s default `String` strategy is heavily ASCII-weighted,
    /// so the property above would rarely exercise the multi-byte case
    /// that a char-count regression breaks. Pin it explicitly.
    #[test]
    fn byte_length_not_char_count_decides_order() {
        // "日" is 1 char but 3 UTF-8 bytes; "ab" is 2 chars and 2 bytes.
        // Under (byte length, bytes) "ab" sorts first. Under a char count
        // it would not — that is the regression this pins.
        assert_eq!(
            ("ab".len(), "ab".as_bytes()).cmp(&("日".len(), "日".as_bytes())),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            enc_text("ab").cmp(&enc_text("日")),
            std::cmp::Ordering::Less
        );
        assert!("ab".chars().count() > "日".chars().count());

        // Direct production-path check: push both keys into a real
        // CanonicalMap (pushed out of canonical order) and confirm
        // `CanonicalMap::serialize`'s own comparator — not just `enc_text`
        // above, which is test-local — places "ab" before "日". Without
        // this, a regression in the production comparator alone (leaving
        // `enc_text` untouched) would not fail this test, only the
        // pre-existing `map_key_sort_crosses_head_length_boundary_and_uses_byte_not_char_length`
        // above; mutation-checked (#567 task brief step 3) against a
        // `chars().count()` regression in `CanonicalMap::serialize` to
        // confirm this assertion, not that sibling test, is what catches
        // it.
        let mut m = CanonicalMap::with_capacity(2);
        m.push("日", CanonicalValue::Uint(1));
        m.push("ab", CanonicalValue::Uint(0));
        let owned = Value::Map(vec![
            (Value::Text("ab".into()), Value::Integer(0u64.into())),
            (Value::Text("日".into()), Value::Integer(1u64.into())),
        ]);
        assert_eq!(enc(&owned), enc(&m));
    }
}
