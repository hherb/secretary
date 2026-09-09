//! Comparing a decoder verdict against a row's declared [`Expect`].
//!
//! ONE implementation, called by the generator and by the replay, so the
//! two cannot drift onto two readings of the same column (#604's ruling
//! for the canonicality corpus, adopted here from the start).

use secretary_core::vault::manifest::ManifestError;

use super::cases::Expect;

/// A short rendering of what the decoder actually returned, for panic
/// messages. Deliberately not `Debug` on the whole error: the point of a
/// failure message here is which RULE fired, not the payload.
fn seen(err: &ManifestError) -> String {
    match err {
        ManifestError::DuplicateKey { field, index } => {
            format!("DuplicateKey {{ field: {field:?}, index: {index} }}")
        }
        ManifestError::Canonical(inner) => format!("Canonical({inner})"),
        other => format!("{other:?}"),
    }
}

/// Assert that `outcome` is exactly what §4.2's precedence paragraph
/// requires for a row.
///
/// Fail-closed in every arm: an unexpected rejection is a failure, and so
/// is an unexpected acceptance. `dup_index` is the ordinal the surgery
/// planted at (`None` for rows that plant nothing), and it is checked
/// only where the row expects a duplicate -- there is no other row shape
/// for which the decoder reports one.
pub fn assert_precedence(
    label: &str,
    expect: Expect,
    field: Option<&str>,
    dup_index: Option<usize>,
    outcome: &Result<secretary_core::vault::manifest::Manifest, ManifestError>,
) {
    match (expect, outcome) {
        (Expect::Accept, Ok(_)) => {}
        (Expect::Accept, Err(e)) => panic!(
            "row {label}: the table says this body is valid, but the decoder rejected it \
             with {}",
            seen(e)
        ),

        (Expect::DuplicateKey, Err(ManifestError::DuplicateKey { field: got, index })) => {
            let field = field.expect(
                "a row expecting a duplicate must name the repeated key in its \
                 `field` column",
            );
            assert_eq!(
                *got, field,
                "row {label}: the rejection must name the REPEATED key"
            );
            let want = dup_index.expect(
                "a row expecting a duplicate must have planted one, so the surgery \
                 must have reported the ordinal it inserted at",
            );
            assert_eq!(
                *index, want,
                "row {label}: the rejection must report the ordinal of the SECOND \
                 occurrence, which is where the surgery inserted it"
            );
        }

        // The variant FAMILY, not the tight `CanonicalError::FloatRejected`
        // / `TagRejected` spellings -- those name a `pub(crate)` type this
        // integration test cannot reach, the same limit
        // `manifest_canonicality_kat_helpers::assert` documents for its
        // `FloatWalk` arm.
        //
        // It still discriminates the property under test, which is what
        // matters here: `ManifestError::Canonical` is the ONLY family
        // `reject_floats_and_tags` produces, and deleting that pre-pass
        // sends these rows to `parse_manifest_map`, which reports
        // `ManifestError::DuplicateKey` -- a different variant, so the
        // mutation reds. What it does NOT do is separate a rule-4
        // rejection from a `CanonicalError` raised at the step-4
        // re-encode; no row in this corpus reaches that far, because
        // every one of them is rejected earlier.
        //
        // **Consequence worth stating, because it is not obvious from
        // here:** this arm cannot tell a FLOAT row from a TAG row, so for
        // those rows `every_row_body_matches_the_case_its_label_names` is
        // the SOLE discriminator on the Rust side -- measured, by making
        // all the rule-4 bodies identical, which left this replay green
        // and red only the rebuild. Weakening that test takes the
        // float/tag distinction with it. Section MPR is unaffected: its
        // `NonCanonicalItem` detail names which of the two fired.
        (Expect::Rule4, Err(ManifestError::Canonical(_))) => {}

        (want, Ok(_)) => panic!(
            "row {label}: §4.2 requires this body to be rejected as {}, but the decoder \
             ACCEPTED it",
            want.name()
        ),
        (want, Err(e)) => panic!(
            "row {label}: §4.2 requires {}, but the decoder reported {}. Both reject, so \
             nothing is unsafe -- but a reader that names a different rule from the one \
             the spec fixes is not interoperable, which is the whole subject of this \
             corpus.",
            want.name(),
            seen(e)
        ),
    }
}
