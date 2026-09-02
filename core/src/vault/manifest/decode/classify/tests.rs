//! Unit tests for the §4.3 step-4 divergence classifier (#590).
//!
//! Everything under test is a pure function, so these drive the head
//! classifier and the array-order predicate directly rather than through a
//! whole manifest decode. The end-to-end pins — that each rejecting row of
//! the canonicality corpus names its own cause — live in
//! `core/tests/manifest_noncanonical_cause.rs`, where the real bodies are.

use super::*;
use crate::vault::manifest::test_support::populated_manifest;
use crate::vault::manifest::{TrashEntry, UUID_LEN};
use std::collections::BTreeMap;

/// A manifest whose five §4.2 arrays are all in their normative order, with
/// at least two entries in each.
///
/// Built by sorting [`populated_manifest`] rather than by hand, because
/// that fixture is deliberately UNSORTED — it exists to prove
/// `encode_manifest` sorts on output — so it cannot serve as the
/// all-sorted control. Its `trash` also carries a single entry, which a
/// `reverse()`-based violation test cannot express, so a second one is
/// appended here. `the_fixture_has_at_least_two_entries_in_every_checked_array`
/// pins both properties so a future change to the shared fixture cannot
/// make these tests vacuous.
fn sorted_manifest() -> Manifest {
    let mut m = populated_manifest();

    m.trash.push(TrashEntry {
        block_uuid: [0x11; UUID_LEN],
        tombstoned_at_ms: 1_714_060_900_001,
        tombstoned_by: [0x55; UUID_LEN],
        fingerprint: None,
        purged_at_ms: None,
        unknown: BTreeMap::new(),
    });

    m.vector_clock.sort_by_key(|entry| entry.device_uuid);
    m.blocks.sort_by_key(|entry| entry.block_uuid);
    m.trash.sort_by_key(|entry| entry.block_uuid);
    for block in &mut m.blocks {
        block.recipients.sort_unstable();
        block
            .vector_clock_summary
            .sort_by_key(|entry| entry.device_uuid);
    }

    m
}

// ---------------------------------------------------------------------------
// first_divergence
// ---------------------------------------------------------------------------

#[test]
fn first_divergence_reports_the_first_differing_index() {
    assert_eq!(first_divergence(&[1, 2, 3], &[1, 9, 3]), Some(1));
    assert_eq!(first_divergence(&[9, 2, 3], &[1, 2, 3]), Some(0));
}

#[test]
fn first_divergence_is_none_when_one_buffer_is_a_prefix_of_the_other() {
    // `zip` stops at the shorter buffer, so a pure length difference has no
    // differing PAIR. Documented as `None` rather than silently reported as
    // the truncation point, which would be a different claim.
    assert_eq!(first_divergence(&[1, 2], &[1, 2, 3]), None);
    assert_eq!(first_divergence(&[1, 2, 3], &[1, 2]), None);
    assert_eq!(first_divergence(&[], &[1]), None);
}

#[test]
fn first_divergence_is_none_for_identical_buffers() {
    assert_eq!(first_divergence(&[1, 2, 3], &[1, 2, 3]), None);
}

// ---------------------------------------------------------------------------
// classify_head — indefinite lengths
// ---------------------------------------------------------------------------

/// Major types 2-5 with additional information 31, plus the break code.
/// These are exactly the heads `ciborium`'s reader collapses on parse, so
/// the input bytes are the only surviving evidence.
#[test]
fn indefinite_heads_of_every_admitting_major_type_are_classified() {
    for head in [
        0x5F, // indefinite byte string
        0x7F, // indefinite text string
        0x9F, // indefinite array
        0xBF, // indefinite map
        0xFF, // break
    ] {
        assert_eq!(
            classify_head(&[head]),
            Some(NonCanonicalCause::IndefiniteLength),
            "head {head:#04X} was not classified as indefinite-length"
        );
    }
}

/// Additional information 31 under major types 0 and 1 is not a
/// well-formed indefinite item, so it is not claimed as one.
#[test]
fn additional_info_31_under_a_non_admitting_major_type_is_not_indefinite() {
    for head in [0x1F, 0x3F] {
        assert_eq!(
            classify_head(&[head]),
            None,
            "head {head:#04X} was wrongly classified as indefinite-length"
        );
    }
}

// ---------------------------------------------------------------------------
// classify_head — shortest form
// ---------------------------------------------------------------------------

/// One case per argument width, each carrying a value that fits the width
/// below it. `0x18 0x05` is the shape the `*__rule3_non_shortest_int`
/// corpus rows use.
#[test]
fn non_shortest_arguments_are_classified_at_every_width() {
    let cases: [(&[u8], &str); 4] = [
        (&[0x18, 0x05], "1-byte argument holding a value below 24"),
        (
            &[0x19, 0x00, 0x05],
            "2-byte argument holding a 1-byte value",
        ),
        (
            &[0x1A, 0x00, 0x00, 0x01, 0x00],
            "4-byte argument holding a 2-byte value",
        ),
        (
            &[0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
            "8-byte argument holding a 4-byte value",
        ),
    ];

    for (bytes, what) in cases {
        assert_eq!(
            classify_head(bytes),
            Some(NonCanonicalCause::NonShortestForm),
            "{what} was not classified as non-shortest-form"
        );
    }
}

/// The boundary in both directions at every width. A comparator that used
/// `>=` instead of `>` would misreport each of these as non-shortest.
#[test]
fn smallest_value_needing_each_width_is_shortest_form() {
    let cases: [(&[u8], &str); 4] = [
        (&[0x18, 0x18], "24 — the smallest value needing a byte"),
        (&[0x19, 0x01, 0x00], "256 — the smallest needing two"),
        (
            &[0x1A, 0x00, 0x01, 0x00, 0x00],
            "65_536 — the smallest needing four",
        ),
        (
            &[0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            "2^32 — the smallest needing eight",
        ),
    ];

    for (bytes, what) in cases {
        assert_eq!(classify_head(bytes), None, "{what} was wrongly rejected");
    }
}

/// A value representable inline needs no argument byte at all, so a head
/// carrying it directly is canonical.
#[test]
fn inline_arguments_are_never_non_shortest() {
    for additional in 0..=AI_MAX_INLINE {
        assert_eq!(
            classify_head(&[additional]),
            None,
            "inline additional information {additional} was wrongly classified"
        );
    }
}

/// Major type 7 is excluded on purpose: its arguments are simple values and
/// floats with their own rules, and a float never reaches this code because
/// `reject_floats_and_tags` runs first.
#[test]
fn major_type_seven_is_not_classified_as_non_shortest() {
    // 0xF9 is a half-precision float head; 0xF8 0x05 a 1-byte simple value
    // whose argument would look "non-shortest" under the integer rule.
    assert_eq!(classify_head(&[0xF9, 0x00, 0x00]), None);
    assert_eq!(classify_head(&[0xF8, 0x05]), None);
}

/// Reserved additional-information values are not a shortest-form question.
#[test]
fn reserved_additional_information_is_unclassified() {
    for additional in 28..=30u8 {
        assert_eq!(classify_head(&[additional]), None);
    }
}

/// A head promising an argument the buffer does not contain must not panic
/// or guess. Fuzz inputs reach this code path.
#[test]
fn truncated_arguments_are_unclassified_rather_than_a_panic() {
    assert_eq!(classify_head(&[0x18]), None);
    assert_eq!(classify_head(&[0x19, 0x00]), None);
    assert_eq!(classify_head(&[0x1B, 0x00, 0x00]), None);
    assert_eq!(classify_head(&[]), None);
}

// ---------------------------------------------------------------------------
// read_argument
// ---------------------------------------------------------------------------

/// Fail-safe on a value that is not an argument width: report "shortest",
/// so an unexpected head goes to `Unclassified` rather than being announced
/// as a non-shortest-form violation it is not.
#[test]
fn a_value_that_is_not_an_argument_width_is_treated_as_shortest() {
    for additional in [0u8, AI_MAX_INLINE, 28, AI_INDEFINITE] {
        assert!(
            is_shortest_form(0, additional),
            "additional information {additional} is not an argument width and \
             must not be reported as a violation"
        );
    }
}

#[test]
fn read_argument_is_big_endian_at_every_width() {
    assert_eq!(read_argument(&[0x2A], AI_ARG_ONE_BYTE), Some(42));
    assert_eq!(read_argument(&[0x01, 0x00], AI_ARG_TWO_BYTE), Some(256));
    assert_eq!(
        read_argument(&[0x00, 0x01, 0x00, 0x00], AI_ARG_FOUR_BYTE),
        Some(65_536)
    );
    assert_eq!(
        read_argument(&[0, 0, 0, 1, 0, 0, 0, 0], AI_ARG_EIGHT_BYTE),
        Some(1 << 32)
    );
}

#[test]
fn read_argument_reads_only_its_own_width() {
    // Trailing bytes belong to the payload, not the argument.
    assert_eq!(
        read_argument(&[0x2A, 0xFF, 0xFF], AI_ARG_ONE_BYTE),
        Some(42)
    );
}

// ---------------------------------------------------------------------------
// arrays_are_sorted
// ---------------------------------------------------------------------------

#[test]
fn a_canonically_built_manifest_has_all_five_arrays_sorted() {
    assert!(arrays_are_sorted(&sorted_manifest()));
}

/// One case per array §4.2 fixes an order for. Each swaps that array out of
/// order and asserts the predicate notices — so a future edit that drops a
/// term from the conjunction reds exactly one of these, naming it.
#[test]
fn each_of_the_five_arrays_is_checked() {
    let mut m = sorted_manifest();
    m.vector_clock.reverse();
    assert!(!arrays_are_sorted(&m), "vector_clock order is not checked");

    let mut m = sorted_manifest();
    m.blocks.reverse();
    assert!(!arrays_are_sorted(&m), "blocks order is not checked");

    let mut m = sorted_manifest();
    m.trash.reverse();
    assert!(!arrays_are_sorted(&m), "trash order is not checked");

    let mut m = sorted_manifest();
    m.blocks[0].recipients.reverse();
    assert!(!arrays_are_sorted(&m), "recipients order is not checked");

    let mut m = sorted_manifest();
    m.blocks[0].vector_clock_summary.reverse();
    assert!(
        !arrays_are_sorted(&m),
        "vector_clock_summary order is not checked"
    );
}

/// The fixture must actually be able to express each violation. A
/// single-element array reverses to itself, so a `reverse()`-based test
/// over one would pass vacuously whatever the predicate did.
#[test]
fn the_fixture_has_at_least_two_entries_in_every_checked_array() {
    let m = sorted_manifest();
    assert!(
        m.vector_clock.len() >= 2,
        "vector_clock is too short to reorder"
    );
    assert!(m.blocks.len() >= 2, "blocks is too short to reorder");
    assert!(m.trash.len() >= 2, "trash is too short to reorder");
    assert!(
        m.blocks[0].recipients.len() >= 2,
        "recipients is too short to reorder"
    );
    assert!(
        m.blocks[0].vector_clock_summary.len() >= 2,
        "vector_clock_summary is too short to reorder"
    );
}

// ---------------------------------------------------------------------------
// classify_non_canonical — the composition
// ---------------------------------------------------------------------------

/// The array check outranks the byte head, and does so even when the byte
/// at the divergence would classify as something else. Without the
/// ordering, an unsorted array whose divergence happens to land on an
/// indefinite head would be reported as the wrong cause.
#[test]
fn array_order_outranks_a_byte_head_that_would_classify_otherwise() {
    let mut m = sorted_manifest();
    m.blocks.reverse();

    let (cause, at) = classify_non_canonical(&m, &[0x00, 0xBF], &[0x00, 0x00]);

    assert_eq!(cause, NonCanonicalCause::ArraySortOrder);
    assert_eq!(at, Some(1), "the locator is reported whatever the cause");
}

/// With every array sorted, the byte head decides.
#[test]
fn a_sorted_manifest_falls_through_to_the_byte_head() {
    let m = sorted_manifest();

    let (cause, at) = classify_non_canonical(&m, &[0x00, 0xBF], &[0x00, 0xA1]);
    assert_eq!(cause, NonCanonicalCause::IndefiniteLength);
    assert_eq!(at, Some(1));

    let (cause, at) = classify_non_canonical(&m, &[0x18, 0x05], &[0x05]);
    assert_eq!(cause, NonCanonicalCause::NonShortestForm);
    assert_eq!(at, Some(0));
}

/// An ordinary head at the divergence is reported honestly rather than
/// guessed at. This is the arm known-key map disorder lands on.
#[test]
fn an_ordinary_head_at_the_divergence_is_unclassified() {
    let m = sorted_manifest();

    let (cause, at) = classify_non_canonical(&m, &[0x61, 0x62], &[0x61, 0x61]);

    assert_eq!(cause, NonCanonicalCause::Unclassified);
    assert_eq!(at, Some(1));
}

/// No divergence pair and sorted arrays leaves nothing to classify — and
/// must not index past either buffer.
#[test]
fn a_prefix_relationship_is_unclassified_with_no_offset() {
    let m = sorted_manifest();

    let (cause, at) = classify_non_canonical(&m, &[0x01, 0x02], &[0x01, 0x02, 0x03]);

    assert_eq!(cause, NonCanonicalCause::Unclassified);
    assert_eq!(at, None);
}
