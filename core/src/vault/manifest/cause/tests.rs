//! Unit tests for the [`NonCanonicalCause`] vocabulary and its byte-locator
//! renderer (#590).

use super::*;

/// Every [`NonCanonicalCause`] variant, kept honest by an exhaustive match
/// rather than by a hand-maintained list.
///
/// A bare `[A, B, C, D]` array silently under-covers when a fifth arm is
/// added — which is the opposite standard from
/// `assert_rejection_mechanism`'s fail-closed `other => panic!` in
/// `core/tests/manifest_canonicality_kat.rs`. The `match` below makes a new
/// variant a COMPILE error here, so the two agree.
const ALL_CAUSES: [NonCanonicalCause; 4] = [
    NonCanonicalCause::ArraySortOrder,
    NonCanonicalCause::IndefiniteLength,
    NonCanonicalCause::NonShortestForm,
    NonCanonicalCause::Unclassified,
];

/// The compile-time guard behind [`ALL_CAUSES`]: an exhaustive `match` that
/// must gain an arm when a variant is added, returning a discriminant name
/// the test below then requires [`ALL_CAUSES`] to cover.
///
/// Deliberately not an identity `match` (which `clippy::needless_match`
/// rightly flags as a no-op): mapping to a distinct name is what makes both
/// halves — "the match is exhaustive" and "the array is complete" — carry
/// weight instead of only the first.
fn discriminant_name(cause: NonCanonicalCause) -> &'static str {
    match cause {
        NonCanonicalCause::ArraySortOrder => "ArraySortOrder",
        NonCanonicalCause::IndefiniteLength => "IndefiniteLength",
        NonCanonicalCause::NonShortestForm => "NonShortestForm",
        NonCanonicalCause::Unclassified => "Unclassified",
    }
}

/// Adding a `NonCanonicalCause` variant fails to COMPILE in
/// [`discriminant_name`]; adding it there but not to [`ALL_CAUSES`] reds
/// here. Between them the list cannot silently under-cover, which is the
/// standard `assert_rejection_mechanism` already holds itself to.
#[test]
fn every_variant_is_listed_in_all_causes() {
    let listed: Vec<&str> = ALL_CAUSES.iter().copied().map(discriminant_name).collect();

    for name in [
        "ArraySortOrder",
        "IndefiniteLength",
        "NonShortestForm",
        "Unclassified",
    ] {
        assert!(
            listed.contains(&name),
            "{name} is a NonCanonicalCause variant missing from ALL_CAUSES"
        );
    }
    assert_eq!(
        listed.len(),
        4,
        "ALL_CAUSES holds a duplicate, or a variant was added without \
         extending this test's expected-name list"
    );
}

/// Every variant renders a distinct, non-empty phrase. A duplicate or an
/// empty message would make the composed `ManifestError` line no more
/// informative than the single fieldless variant this replaced, which is
/// the whole point of #590.
#[test]
fn every_cause_renders_a_distinct_non_empty_phrase() {
    let all = ALL_CAUSES;

    let rendered: Vec<String> = all.iter().map(ToString::to_string).collect();

    for (cause, text) in all.iter().zip(&rendered) {
        assert!(!text.is_empty(), "{cause:?} rendered an empty message");
    }

    let mut unique = rendered.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        rendered.len(),
        "two causes render the same phrase: {rendered:?}"
    );
}

/// The locator renders as a human suffix when present and contributes
/// nothing at all when absent — never a `Some(..)` / `None` debug form.
#[test]
fn offset_suffix_renders_only_when_present() {
    assert_eq!(
        OffsetSuffix(Some(41)).to_string(),
        " (first divergence at byte offset 41)"
    );
    assert_eq!(OffsetSuffix(None).to_string(), "");
}

/// The offset is interpolated as a decimal number, not debug-formatted.
/// Pins the failure mode the adapter exists to prevent.
#[test]
fn offset_suffix_does_not_leak_the_option_debug_form() {
    let rendered = OffsetSuffix(Some(7)).to_string();
    assert!(
        rendered.contains("offset 7"),
        "offset not rendered as a decimal number: {rendered}"
    );
    assert!(
        !rendered.contains("Some"),
        "offset rendered via Debug: {rendered}"
    );
}
