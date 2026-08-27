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
//!
//! Split into a directory module (#547): [`legacy`] holds the three
//! functions above. Of those, [`encode_canonical_map`] is clone-free on the
//! value side (only keys are materialised, to sort on) and
//! [`reject_floats_and_tags`] clones nothing (it only ever reads through
//! `&Value`) — [`canonical_sort_entries`] is the one holdout: it still
//! `pair.clone()`s every entry, unchanged from before the split.
//!
//! **What that clone still costs, corrected (#569 path 2).** This
//! paragraph used to end by naming the manifest encoder as the live
//! plaintext-bearing caller: `manifest.rs` called
//! [`canonical_sort_entries`] once per manifest sub-structure, and one of
//! those callers — `block_entry_to_value`'s `block_name` field, genuinely
//! user-visible plaintext within the encrypted manifest — was cloned once
//! into the owned entry list and again by this function's own
//! `pair.clone()`, two clones of every block name per manifest save. It
//! was recorded as "deliberately left unmigrated by this slice's own scope
//! decision". **That is now false, and the history is kept rather than
//! deleted so the claim can be checked against the code**: #569 path 2
//! migrated the manifest encode path onto the borrowing
//! [`CanonicalMap`] (`manifest::encode::manifest_to_canonical`), so
//! neither clone is made at all: **no PRODUCTION `manifest.rs` call into
//! [`canonical_sort_entries`] or [`encode_canonical_map`] survives.**
//!
//! Scope that sentence to production and to the encoder, because the
//! manifest module still reaches both from `#[cfg(test)]` code and an
//! earlier draft of this paragraph said "in production or in test code",
//! which the very commit that wrote it falsified. The surviving
//! manifest-module test callers, enumerated so the claim is checkable:
//! `manifest::test_support::dummy_kdf_params_value` is pinned against
//! [`canonical_sort_entries`] by
//! `dummy_kdf_params_value_is_in_canonical_key_order` — that fixture
//! replaced the deleted `encode::kdf_params_to_value`, whose sorted
//! output six decode-negative tests depended on, and the pin is what
//! keeps their input bytes unchanged; and six hand-built decode
//! negatives call [`encode_canonical_map`]
//! (`test_support.rs`'s `build_manifest_map_with_overrides`,
//! `decode::tests::rejects_float_in_unknown_value`, and four in
//! `decode::extract::tests`). Those are ORACLES and FIXTURES, not the
//! encode path.
//!
//! [`canonical_sort_entries`] is **not** thereby dead, and saying so
//! would be the overclaim this paragraph just corrected. One production
//! caller remains: `sync::state::SyncState::to_canonical_cbor`
//! (`core/src/sync/state.rs`), which sorts a two-key
//! `(device_uuid, counter)` vector-clock entry map on the way to
//! OS-keystore persistence. That is sync metadata, not decrypted vault
//! content — a different exposure class from `block_name`, and one this
//! slice did not assess. [`encode_canonical_map`] likewise keeps two
//! production callers, `sync::state` and `identity::card`. Both functions
//! also remain in use from `record.rs`'s and `block.rs`'s `#[cfg(test)]`
//! byte-identity oracles, which deliberately keep the pre-migration owned
//! path alive to prove the borrowing one emits identical bytes.
//!
//! [`size`]
//! holds [`cbor_size_bound`], the pre-reservation helper
//! `encode_canonical_map` uses so its output buffer is sized to avoid
//! reallocating; a real runtime check (not a `debug_assert!`, which compiles
//! out of every release build) then DETECTS the rare case where that bound
//! turned out to be wrong — see [`CanonicalError::CapacityBoundExceeded`].
//! Detecting is not preventing: by the time that check runs, the encode
//! (and any realloc it triggered) has already happened.
//!
//! [`value`] holds the second half of #547's fix: [`CanonicalValue`] /
//! [`CanonicalMap`], a borrowing mirror of the same CBOR subset that
//! serialises straight out of a `SecretString`/`SecretBytes` wrapper instead
//! of copying into an owned `Value` tree first. As of Task 4 of #547, it has
//! a real production consumer: `record::record_to_canonical` builds one out
//! of a `Record`'s fields, and `record::encode` serialises it via
//! [`value::to_canonical_vec`] — the `encode_canonical_map` counterpart over
//! a [`CanonicalMap`] this doc used to say a later step would introduce
//! alongside its first real caller (an earlier version, also named
//! `to_canonical_vec`, was deleted in review round 1 of Task 2 for
//! returning `Result<_, CanonicalError>` while `CanonicalError` itself was
//! not test-API-reachable, making its error type unnameable by the one
//! caller that could have used it — that reasoning was cited to
//! `task-2-report.md` until the #560 review, which found the per-task SDD
//! reports live under a gitignored `.superpowers/` and are not in the repo,
//! so the conclusion is inlined rather than pointed at). It is declared
//! `pub(crate)`, not `pub` — as, since that same review, are
//! [`CanonicalMap`] / [`CanonicalValue`] themselves: `canonical_test_api`
//! and the cross-crate visibility floor it needed are both gone, so
//! nothing in this module declares more visibility than it uses (#559).
//! `block.rs`'s own plaintext encode was unmigrated as of Task 4 — it still
//! called `super::record::encode` once per record and re-parsed the
//! resulting bytes into the `Value` tree it handed to
//! [`legacy::encode_canonical_map`], rather than nesting a borrowed
//! `CanonicalMap`. **That is no longer true**: Task 5 migrated
//! `block::encode_plaintext` onto `record::record_to_canonical` the same
//! way `record::encode` itself uses it (see that function's doc comment),
//! so production `block.rs` calls neither `record::encode` nor
//! `encode_canonical_map` any more. Both survive only in `block.rs`'s
//! `#[cfg(test)]` equivalence oracle, which deliberately keeps the old
//! round-trip path alive to prove the new one produces identical bytes.

#![forbid(unsafe_code)]

use crate::cbor::CborFault;

mod legacy;
mod size;
mod value;

pub use legacy::{canonical_sort_entries, encode_canonical_map, reject_floats_and_tags};
pub(crate) use size::{cbor_size_bound, HEAD_MAX};
pub(crate) use value::to_canonical_vec;
// `CanonicalMap`/`CanonicalValue` were re-exported `pub` (not `pub(crate)`)
// through the end of the final whole-branch review of #547: `vault::
// canonical_test_api` needed a `pub`-visibility chain all the way down to
// reach them from `core/tests/canonical_value_equivalence.rs` (E0365 —
// re-exporting an item as more public than its own established visibility
// is rejected, and a `pub(crate)` hop here would have set that ceiling).
// That review found the tradeoff wrong: it put a third-party
// `#[non_exhaustive]` enum (`ciborium::Value`, via `CanonicalValue::
// Borrowed`) into this crate's public API surface, so a `ciborium` 0.3
// bump would have become a semver-breaking change for `secretary-core` —
// exactly the outcome `cbor::secret_tree` rejected for the same shape of
// type (see that module's doc comment). The belief that the byte-identity
// proof had to be an integration test was itself wrong: a `#[cfg(test)]
// mod tests` inside the crate runs on every CI run just as an integration
// test does, and (as of this fix) is where that proof now lives — in
// `value.rs`, beside the types it is about, NOT in this file, which has no
// `mod tests` at all. Both types are
// therefore back to `pub(crate)`, and `canonical_test_api` no longer
// exists.
//
// (Which in-crate files call them beyond `record.rs` is deliberately not
// enumerated here — that list has been written wrong twice; read the
// callers directly instead of trusting a cached grep result nothing
// validates.)
pub(crate) use value::{CanonicalMap, CanonicalValue};

/// Errors emitted by the three canonical-CBOR helpers in this module.
///
/// [`Self::CborEncode`], [`Self::FloatRejected`] and [`Self::TagRejected`]
/// are the union of what the pre-split `block.rs` and `record.rs` private
/// copies actually produced — no speculative variants there.
/// [`Self::CapacityBoundExceeded`] is new: it did not exist before this
/// module did, because the value-cloning `encode_canonical_map` used to do
/// never needed a pre-reserved buffer to defend. Specifically:
///
/// - [`Self::CborEncode`] — emitted by [`canonical_sort_entries`] (per-key
///   `ciborium::ser::into_writer` failure) and [`encode_canonical_map`]
///   (top-level `ciborium::ser::into_writer` failure). Carries a
///   classified [`CborFault`] rather than the upstream message: `ciborium`'s
///   `Display` is its `Debug` form, so stringifying it copies
///   `ser::Error::Value(String)` verbatim — a `serde` custom message that
///   can embed the offending value (#474). [`crate::cbor::classify_ser`]
///   projects the generic `ciborium::ser::Error<E>` (generic over the
///   writer's I/O error, so `#[from]` does not apply) to a non-generic,
///   data-free type instead.
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
///
/// - [`Self::CapacityBoundExceeded`] — emitted by [`encode_canonical_map`]
///   when its pre-reserved output buffer needed more bytes than
///   [`cbor_size_bound`] computed for it. `cbor_size_bound` is a bound over
///   today's known `ciborium::Value` variant set; `Value` is
///   `#[non_exhaustive]`, so this variant exists as a tripwire for a future
///   variant that bound cannot name (or a serializer change), not as a
///   routine error path — on today's variant set the bound is provably
///   sufficient (see `size.rs`'s tests). It fires only AFTER
///   `ciborium::ser::into_writer` has already returned: if the buffer really
///   did grow past its reservation, the old (possibly plaintext-bearing)
///   allocation is already freed unwiped by the time this check runs. It
///   DETECTS the hazard; it cannot PREVENT it.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    /// `ciborium::ser::into_writer` returned an I/O or serialisation error.
    /// Carries a classified [`CborFault`] rather than the upstream message —
    /// see the variant doc above for why, and why `#[from]` doesn't work
    /// for `ciborium::ser::Error<E>`.
    #[error("CBOR encode error: {0}")]
    CborEncode(CborFault),

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

    /// `encode_canonical_map`'s output exceeded its pre-reserved capacity.
    /// See the variant doc above — this is a post-hoc tripwire, not a
    /// preventive guarantee: the realloc it reports has already happened by
    /// the time it fires.
    #[error("canonical CBOR encode exceeded its reserved size bound ({actual} > {bound})")]
    CapacityBoundExceeded {
        /// Actual encoded length in bytes.
        actual: usize,
        /// The `cbor_size_bound`-derived capacity that was reserved.
        bound: usize,
    },
}
