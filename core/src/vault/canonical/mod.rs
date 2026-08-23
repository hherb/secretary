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
//! functions above, now clone-free on the value side (only keys are
//! materialised to sort); [`size`] holds [`cbor_size_bound`], the
//! pre-reservation helper that keeps `encode_canonical_map`'s output
//! buffer from ever reallocating.

#![forbid(unsafe_code)]

use crate::cbor::CborFault;

mod legacy;
mod size;

pub use legacy::{canonical_sort_entries, encode_canonical_map, reject_floats_and_tags};
pub(crate) use size::cbor_size_bound;

/// Errors emitted by the three canonical-CBOR helpers in this module.
///
/// The variant set is the union of what the existing `block.rs` and
/// `record.rs` private copies actually produced — no speculative
/// variants. Specifically:
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
}
