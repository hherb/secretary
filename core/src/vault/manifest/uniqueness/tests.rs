//! Unit tests for §4.2's repeated-value rules (#600).
//!
//! Two layers, and both are needed. [`has_repeat`] is tested directly
//! because it is the single expression of the rule that both directions
//! call, so its edge cases (empty, single, non-adjacent input) belong
//! with it rather than being re-discovered per call site.
//! [`check_no_repeated_array_values`] is tested over a whole
//! [`Manifest`] because the interesting property is not the scan but
//! WHICH arrays it is applied to — four of five, with `recipients` the
//! documented exception.

use super::*;
use crate::vault::manifest::test_support::populated_manifest;

// ---- has_repeat ------------------------------------------------------

#[test]
fn has_repeat_is_false_for_distinct_values() {
    assert!(!has_repeat(vec![3u8, 1, 2]));
}

#[test]
fn has_repeat_is_false_for_empty_and_single_element_inputs() {
    // `windows(2)` yields nothing below length 2, so both are `false` —
    // asserted rather than assumed, because a rewrite reaching for
    // `ids[0] == ids[1]` panics on exactly these two inputs and every
    // real manifest array can legitimately be empty (`minimal_manifest`
    // has three).
    assert!(!has_repeat(Vec::<u8>::new()));
    assert!(!has_repeat(vec![7u8]));
}

#[test]
fn has_repeat_finds_a_repeat_on_the_first_adjacent_pair() {
    assert!(has_repeat(vec![1u8, 1, 2]));
}

#[test]
fn has_repeat_finds_a_repeat_on_the_last_adjacent_pair() {
    // Distinct from the case above, and both are needed: with a
    // two-element input a full adjacent scan and an `ids[0] == ids[1]`
    // check are the same function, so neither alone separates them.
    assert!(has_repeat(vec![1u8, 2, 2]));
}

#[test]
fn has_repeat_finds_a_repeat_the_input_order_separates() {
    // THE SORT IS LOAD-BEARING, and this is the only test that says so.
    // `[1, 2, 1]` has no equal ADJACENT pair as given; the repeat is
    // visible only after sorting. Deleting the `sort_unstable` line
    // leaves every other test in this file green.
    assert!(has_repeat(vec![1u8, 2, 1]));
}

#[test]
fn has_repeat_works_on_the_uuid_arrays_it_is_actually_called_with() {
    // The production instantiation is `[u8; 16]`, not `u8`: `Ord` on a
    // fixed-size array is lexicographic over the elements, which is the
    // 16-byte bytewise compare §4.2 names. Exercised so the generic is
    // pinned at the type the four call sites use.
    assert!(has_repeat(vec![[0x01u8; 16], [0x02; 16], [0x01; 16]]));
    assert!(!has_repeat(vec![[0x01u8; 16], [0x02; 16], [0x03; 16]]));
}

// ---- check_no_repeated_array_values ----------------------------------

#[test]
fn a_distinct_manifest_passes() {
    // The control. Without it every rejection test below would be
    // satisfied by a check that rejected every manifest.
    assert!(check_no_repeated_array_values(&populated_manifest()).is_ok());
}

#[test]
fn a_repeated_block_uuid_is_rejected() {
    let mut m = populated_manifest();
    m.blocks[1].block_uuid = m.blocks[0].block_uuid;
    assert!(matches!(
        check_no_repeated_array_values(&m),
        Err(ManifestError::EncodeDuplicateBlockUuid)
    ));
}

#[test]
fn a_repeated_trash_block_uuid_is_rejected() {
    let mut m = populated_manifest();
    let dup = m.trash[0].clone();
    m.trash.push(dup);
    assert!(matches!(
        check_no_repeated_array_values(&m),
        Err(ManifestError::EncodeDuplicateTrashUuid)
    ));
}

#[test]
fn a_repeated_vector_clock_device_uuid_is_rejected() {
    let mut m = populated_manifest();
    m.vector_clock[1].device_uuid = m.vector_clock[0].device_uuid;
    assert!(matches!(
        check_no_repeated_array_values(&m),
        Err(ManifestError::EncodeVectorClockDuplicateDevice)
    ));
}

#[test]
fn a_repeated_device_uuid_in_a_non_first_block_summary_is_rejected() {
    // Planted in `blocks[1]`, not `blocks[0]`, and that index is the
    // point of the test: §4.2 constrains "**each** block's" summary, so
    // a walk that checks only the first block is a divergence no
    // `blocks[0]` fixture can detect.
    let mut m = populated_manifest();
    let first = m.blocks[1].vector_clock_summary[0].device_uuid;
    m.blocks[1].vector_clock_summary[1].device_uuid = first;
    assert!(matches!(
        check_no_repeated_array_values(&m),
        Err(ManifestError::EncodeVectorClockDuplicateDevice)
    ));
}

#[test]
fn a_repeated_recipient_contact_uuid_is_accepted() {
    // §4.2's ONE exception, and the reason this check enumerates four
    // arrays rather than walking all five: a repeated `contact_uuid`
    // denotes no additional grant. A "consistency" edit that folds
    // `recipients` in would narrow a v1-frozen decoder — the read side
    // accepts these bodies and must keep doing so — and reds here first.
    let mut m = populated_manifest();
    m.blocks[1].recipients[1] = m.blocks[1].recipients[0];
    assert!(
        check_no_repeated_array_values(&m).is_ok(),
        "a repeated contact_uuid is §4.2's documented exception"
    );
}
