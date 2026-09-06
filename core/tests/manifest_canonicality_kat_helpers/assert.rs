//! Asserting a corpus row's rejection against the cause the fixture
//! declares, and the vocabulary both languages share for it.
//!
//! Extracted from `manifest_canonicality_kat.rs` (#612).

use secretary_core::vault::manifest::{ManifestError, NonCanonicalCause};

/// Which of the decoder's two independent canonicality mechanisms rejected
/// a row.
///
/// They are not interchangeable, and `decode/mod.rs` carries a standing
/// warning against conflating them: a normalising parse PRESERVES a float
/// and re-encodes it identically, so the §4.3 step-4 comparison
/// structurally cannot see one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// The step-4 re-encode comparison, which #590 gave a cause and a
    /// byte locator.
    ReEncode,
    /// `reject_floats_and_tags`, the whole-body walk that runs first.
    FloatWalk,
}

/// The fixture's spelling of a [`NonCanonicalCause`].
///
/// This is the cross-language vocabulary #604 exists to establish: before
/// it, the label-suffix -> cause mapping lived in this file's
/// `assert_rejection_mechanism` and nowhere else, so `conformance.py` had
/// nothing to agree with. The names are now recorded per row in
/// `manifest_canonicality_kat.json` and read back by both languages.
///
/// **Exhaustive on purpose.** A fifth `NonCanonicalCause` variant fails to
/// COMPILE here rather than silently acquiring no fixture spelling.
///
/// That is a DIFFERENT axis from the `other => panic!` arm this function
/// replaced, which was fail-closed on an unrecognised SHAPES entry. That
/// axis is still covered, just elsewhere: `Shape::verdict` is a required
/// field, and the replay asserts both `rows.len() == 21` and
/// `labels == Level::ALL x SHAPES`. Nothing about this match protects it.
pub fn cause_name(cause: NonCanonicalCause) -> &'static str {
    match cause {
        NonCanonicalCause::ArraySortOrder => "ArraySortOrder",
        NonCanonicalCause::IndefiniteLength => "IndefiniteLength",
        NonCanonicalCause::NonShortestForm => "NonShortestForm",
        NonCanonicalCause::Unclassified => "Unclassified",
    }
}

/// Assert that `err` is the rejection the corpus row DECLARES, and say
/// which mechanism produced it.
///
/// `expect_cause` is the row's `expect_cause` column: `Some(name)` for a
/// row the §4.3 step-4 re-encode comparison catches, `None` for one
/// rejected before that comparison ever runs. **The fixture is the source
/// of truth** — this function no longer matches on the label suffix, so
/// the Rust test is a consumer of the cross-language contract rather than
/// its sole author (#604).
///
/// Fail-closed in both arms. A cause spelling no `NonCanonicalCause`
/// produces can never match, so a typo'd or invented fixture value panics
/// naming both sides. And `None` asserts a NEGATIVE — that the row did not
/// reach the re-encode at all — which is the assertion that would catch a
/// future change routing floats through the comparison: such a row would
/// still be "rejected", and only this would notice.
pub fn assert_rejection_mechanism(
    label: &str,
    expect_cause: Option<&str>,
    err: &ManifestError,
) -> Mechanism {
    match expect_cause {
        // Rule 2 and rule 3 are encoding-level departures the parse
        // normalises away, so the re-encode is the only signal — and #590's
        // classifier walks the whole input, which is the one place the
        // evidence survives.
        Some(want) => {
            let got = match err {
                ManifestError::NonCanonicalEncoding { cause, .. } => cause_name(*cause),
                other => panic!(
                    "row {label:?}: corpus declares cause {want:?}, so this row must be \
                     rejected by the §4.3 step-4 re-encode comparison -- got {other}"
                ),
            };
            assert_eq!(
                got, want,
                "row {label:?}: corpus declares cause {want:?}, decoder produced {got:?}"
            );
            Mechanism::ReEncode
        }
        // A null cause means "rejected BEFORE the re-encode produced a
        // NonCanonicalEncoding". `reject_floats_and_tags`
        // (`decode/mod.rs`) is the only mechanism that reaches this
        // arm for any body this corpus builds.
        //
        // LIMIT, stated because the obvious wider claim is false and an
        // earlier version of this comment made it: this asserts the error
        // VARIANT FAMILY, not the mechanism. `ManifestError::Canonical`
        // is `#[from] CanonicalError`, so it also spans `DuplicateKey`,
        // `CapacityBoundExceeded` and `CborEncode` -- which
        // `encode_manifest` can raise AT the step-4 re-encode, i.e. the
        // opposite mechanism, and which would be miscounted as FloatWalk
        // here. The tight form
        // `Canonical(CanonicalError::FloatRejected { .. })` is what
        // `manifest/decode/tests.rs`'s `rejects_float_in_unknown_value`
        // asserts; it
        // is unavailable HERE because `vault::canonical` is
        // `pub(crate)` (`core/src/vault/mod.rs:24`) and this is an
        // integration test, i.e. a separate crate. The mechanism is
        // therefore pinned in-crate and the family pinned here; do not
        // read this arm as doing both.
        None => {
            assert!(
                matches!(err, ManifestError::Canonical(_)),
                "row {label:?}: corpus declares no cause, so this row must be caught \
                 before the re-encode produces a NonCanonicalEncoding -- for this \
                 corpus that means reject_floats_and_tags, got {err}"
            );
            Mechanism::FloatWalk
        }
    }
}
