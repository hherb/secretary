//! Unit tests for the [`NonCanonicalCause`] vocabulary and its byte-locator
//! renderer (#590).

use super::*;

/// Every variant renders a distinct, non-empty phrase. A duplicate or an
/// empty message would make the composed `ManifestError` line no more
/// informative than the single fieldless variant this replaced, which is
/// the whole point of #590.
#[test]
fn every_cause_renders_a_distinct_non_empty_phrase() {
    let all = [
        NonCanonicalCause::ArraySortOrder,
        NonCanonicalCause::IndefiniteLength,
        NonCanonicalCause::NonShortestForm,
        NonCanonicalCause::Unclassified,
    ];

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
