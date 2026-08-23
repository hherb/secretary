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
//! `pair.clone()`s every entry, unchanged from before the split, because it
//! is a later build-sequence step (Task 4) that removes its last
//! plaintext-bearing caller, not this one. [`size`]
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
//! `to_canonical_vec`, was deleted in review round 1 of Task 2 — see
//! `task-2-report.md` — for returning `Result<_, CanonicalError>` while
//! `CanonicalError` itself was not test-API-reachable, making its error
//! type unnameable by the one caller that could have used it). It is
//! declared `pub(crate)`, not `pub`: unlike [`CanonicalMap`] /
//! [`CanonicalValue`] themselves, no integration test needs to reach it, so
//! there is no `canonical_test_api` cross-crate visibility floor to satisfy.
//! `block.rs`'s own plaintext encode is unmigrated as of this step — it
//! still calls [`super::record::encode`] once per record and re-parses the
//! resulting bytes into the `Value` tree it hands to
//! [`legacy::encode_canonical_map`], rather than nesting a borrowed
//! `CanonicalMap` — a later build-sequence step's concern, not this one's.

#![forbid(unsafe_code)]

use crate::cbor::CborFault;

mod legacy;
mod size;
mod value;

pub use legacy::{canonical_sort_entries, encode_canonical_map, reject_floats_and_tags};
pub(crate) use size::{cbor_size_bound, HEAD_MAX};
pub(crate) use value::to_canonical_vec;
// `CanonicalMap`/`CanonicalValue` are re-exported `pub` (not `pub(crate)`),
// even though this `canonical` module itself is `pub(crate)` (see
// `vault/mod.rs`): `vault::canonical_test_api` needs a `pub`-visibility
// chain all the way down to reach them from `core/tests/*.rs` (E0365 —
// re-exporting an item as more public than its own established visibility
// is rejected, and a `pub(crate)` hop here would set that ceiling).
//
// As of Task 4 (#547), both have a genuine in-crate production caller —
// `record::record_to_canonical` — so, unlike at the point this comment was
// first written (Task 2), their `pub` path is no longer what keeps them out
// of `dead_code`; ordinary crate-internal usage does that now, the same as
// for the three `legacy` functions re-exported just above. The `pub`
// visibility stays for the ORIGINAL reason stated two paragraphs up:
// `canonical_test_api` needs it so
// `core/tests/canonical_value_equivalence.rs` can construct these types
// directly, and dropping to `pub(crate)` would still fail at E0365 even
// though `dead_code` would no longer object.
//
// (Which in-crate files call them beyond `record.rs` is deliberately not
// enumerated here — that list has been written wrong twice; read the
// callers directly instead of trusting a cached grep result nothing
// validates.)
pub use value::{CanonicalMap, CanonicalValue};

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
