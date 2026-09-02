//! Which canonical-form rule the §4.3 step-4 re-encode comparison caught,
//! and how its byte locator renders (#590).
//!
//! Split out of [`super::error`] rather than added to it: that file is the
//! manifest layer's error enum, and this is a classification vocabulary the
//! decode path computes. Keeping them apart also keeps `error.rs` from
//! growing a second public type whose doc is longer than most of its
//! variants.

use std::fmt;

/// Which canonical-form rule most likely explains a manifest body failing
/// the §4.3 step-4 re-encode comparison.
///
/// **Advisory, not the verdict.** [`decode_manifest`] still rejects on the
/// byte comparison alone; this type only says *which rule* most likely
/// explains that rejection, so a misclassification changes a diagnostic
/// and never an acceptance decision. That is what makes the positional
/// classification in `manifest::decode::classify` sound to use on the path
/// every vault open takes, and it is why [`Self::Unclassified`] is a real
/// outcome rather than a bug to eliminate.
///
/// **Fieldless by construction (#474):** every variant is a compile-time
/// constant, so no decrypted manifest content — a `block_name`, an unknown
/// key — can ride along into an error payload. The `thiserror` derive is
/// load-bearing rather than cosmetic: `scripts/check-error-payload-hygiene.py`
/// credits an enum carrying `#[error(...)]` in its body as data-free by
/// recursion (tier 2 of `is_data_free`), so this type needs neither a
/// `DATA_FREE_TYPES` registration — which is what `CborFault`, a plain
/// struct, required — nor an allowlist row.
///
/// [`decode_manifest`]: super::decode_manifest
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NonCanonicalCause {
    /// One of the five arrays `docs/vault-format.md` §4.2 fixes an order
    /// for did not arrive in it: `vector_clock`, `blocks`, `trash`, a
    /// block's `recipients`, or a block's `vector_clock_summary`.
    ///
    /// Decisive in both directions, unlike the byte-head causes below,
    /// because it is read off the *parsed* [`Manifest`] rather than off a
    /// divergence position: `encode_manifest` sorts all five on output, so
    /// an unsorted input always diverges, and an input in which all five
    /// are sorted can never diverge *because of* array order.
    ///
    /// This is the cause a clean-room implementer is most likely to hit —
    /// the sort disciplines were enforced by the encoder from the first
    /// manifest commit and stated nowhere in `docs/` until #572's review.
    ///
    /// [`Manifest`]: super::Manifest
    #[error("an array was not in its vault-format §4.2 sort order")]
    ArraySortOrder,

    /// An indefinite-length item (RFC 8949 major types 2-5 with additional
    /// information 31, or the `0xFF` break code).
    ///
    /// `ciborium`'s `Value` reader collapses these on parse, so the input
    /// bytes are the only place the evidence survives — which is why this
    /// is classified from the input rather than from the parsed value.
    #[error("an indefinite-length item")]
    IndefiniteLength,

    /// A non-shortest-form integer or length prefix: an argument encoded
    /// in more bytes than RFC 8949 §4.2.1 permits for its value.
    #[error("a non-shortest-form integer or length prefix")]
    NonShortestForm,

    /// The divergence is real but not attributable to any cause above.
    ///
    /// Reached when the first differing byte is an ordinary head — most
    /// often map keys among the *known* key set arriving out of canonical
    /// order, which re-encodes to the canonical order and diverges without
    /// leaving a distinguishing byte at the divergence point. Reported
    /// honestly rather than guessed: naming a cause that cannot be proven
    /// from the bytes would make the diagnostic worse than silence.
    #[error("cause not determined")]
    Unclassified,
}

/// Renders a `NonCanonicalEncoding` byte locator as a message suffix.
///
/// A private [`fmt::Display`] adapter rather than a `format!` inside the
/// `#[error]` attribute: it allocates nothing, and it keeps the "no
/// offset was available" case from rendering as a bare `Some(41)` /
/// `None` debug form. Mirrors the shape [`crate::cbor::CborFault`]'s own
/// `Display` uses for the same datum.
pub(super) struct OffsetSuffix(pub(super) Option<usize>);

impl fmt::Display for OffsetSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(at) => write!(f, " (first divergence at byte offset {at})"),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests;
