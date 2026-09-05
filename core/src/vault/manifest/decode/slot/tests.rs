//! Unit tests for the manifest decoder's single-assignment slots.

use std::cell::Cell;

use super::*;

/// A §4.2 key name standing in for any `KEY_*` constant. The slot types
/// are generic over the field name, so which constant a caller passes is
/// not a property under test here — that it is reported verbatim is.
const FIELD: &str = "counter";

/// A second name, so a test can prove the reported field is the one the
/// caller passed rather than a constant baked into the slot.
const OTHER_FIELD: &str = "device_uuid";

/// An arbitrary map ordinal. Deliberately not `0` or `1`: an off-by-one
/// or a hardcoded index would still pass against those.
const INDEX: usize = 7;

/// A minimal valid `UnknownValue` for the bag tests: canonical CBOR for
/// the unsigned integer 1. Its content is irrelevant — `UnknownBag` keys
/// on the map key, never on the value.
fn unknown_value() -> UnknownValue {
    UnknownValue::from_canonical_cbor(&[0x01]).expect("0x01 is a canonical CBOR integer")
}

// ---------------------------------------------------------------------------
// Once::set
// ---------------------------------------------------------------------------

#[test]
fn set_fills_a_vacant_slot() {
    let mut slot: Once<u64> = Once::default();
    slot.set(FIELD, INDEX, || Ok(42))
        .expect("vacant slot accepts");
    assert_eq!(slot.require(FIELD).expect("filled slot"), 42);
}

#[test]
fn set_rejects_a_repeat_naming_the_field_and_index() {
    let mut slot: Once<u64> = Once::default();
    slot.set(FIELD, 0, || Ok(1)).expect("first set");
    match slot.set(FIELD, INDEX, || Ok(2)) {
        Err(ManifestError::DuplicateKey { field, index }) => {
            assert_eq!(field, FIELD, "must name the key the caller passed");
            assert_eq!(index, INDEX, "must report the ordinal of the REPEAT");
        }
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

#[test]
fn set_reports_the_field_the_caller_passed_not_the_one_that_filled_it() {
    // Guards against a slot that remembers its own name: the two calls
    // pass different names, and it is the SECOND that must be reported.
    let mut slot: Once<u64> = Once::default();
    slot.set(OTHER_FIELD, 0, || Ok(1)).expect("first set");
    match slot.set(FIELD, INDEX, || Ok(2)) {
        Err(ManifestError::DuplicateKey { field, .. }) => assert_eq!(field, FIELD),
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

/// The whole reason [`Once::set`] takes a closure rather than a value.
///
/// The hand-copied guards this type replaces checked `slot.is_some()`
/// *before* parsing the second copy of a repeated key, so a duplicate whose
/// second copy is malformed reported `DuplicateKey`, not `WrongType`. An
/// eager `set(field, index, take_u64(v, KEY)?)` reverses that silently.
#[test]
fn set_does_not_evaluate_the_value_on_a_repeat() {
    let mut slot: Once<u64> = Once::default();
    slot.set(FIELD, 0, || Ok(1)).expect("first set");

    let evaluated = Cell::new(false);
    let result = slot.set(FIELD, INDEX, || {
        evaluated.set(true);
        Ok(2)
    });

    assert!(result.is_err(), "the repeat must be rejected");
    assert!(
        !evaluated.get(),
        "the value must NOT be parsed once the slot is known to be occupied"
    );
}

#[test]
fn set_evaluates_the_value_exactly_once_when_vacant() {
    let calls = Cell::new(0u32);
    let mut slot: Once<u64> = Once::default();
    slot.set(FIELD, INDEX, || {
        calls.set(calls.get() + 1);
        Ok(9)
    })
    .expect("vacant slot accepts");
    assert_eq!(calls.get(), 1, "the fill must run once, not zero or twice");
}

#[test]
fn set_propagates_a_fill_error_and_leaves_the_slot_vacant() {
    let mut slot: Once<u64> = Once::default();
    let result = slot.set(FIELD, INDEX, || {
        Err(ManifestError::WrongType {
            field: FIELD,
            expected: "unsigned integer",
        })
    });
    assert!(
        matches!(result, Err(ManifestError::WrongType { .. })),
        "the fill's own error must reach the caller unchanged"
    );
    // Matches the idiom this replaces: `slot = Some(take_u64(..)?)` never
    // assigned when `take_u64` failed, so a later well-typed copy of the
    // same key would have filled it. Preserving that keeps a failed fill
    // from being indistinguishable from a successful one.
    assert!(
        matches!(slot.require(FIELD), Err(ManifestError::MissingField { .. })),
        "a failed fill must leave the slot vacant"
    );
}

// ---------------------------------------------------------------------------
// Once::require / into_option
// ---------------------------------------------------------------------------

#[test]
fn require_reports_the_missing_field() {
    let slot: Once<u64> = Once::default();
    match slot.require(FIELD) {
        Err(ManifestError::MissingField { field }) => assert_eq!(field, FIELD),
        other => panic!("expected MissingField, got {other:?}"),
    }
}

#[test]
fn into_option_is_none_when_vacant() {
    let slot: Once<u64> = Once::default();
    assert!(slot.into_option().is_none());
}

#[test]
fn into_option_yields_the_value_when_filled() {
    let mut slot: Once<u64> = Once::default();
    slot.set(FIELD, INDEX, || Ok(5))
        .expect("vacant slot accepts");
    assert_eq!(slot.into_option(), Some(5));
}

// ---------------------------------------------------------------------------
// UnknownBag
// ---------------------------------------------------------------------------

#[test]
fn unknown_bag_accumulates_distinct_keys() {
    let mut bag = UnknownBag::default();
    bag.insert("a".to_string(), unknown_value(), 0)
        .expect("first key");
    bag.insert("b".to_string(), unknown_value(), 1)
        .expect("distinct key");
    let map = bag.into_map();
    assert_eq!(map.len(), 2);
    assert!(map.contains_key("a") && map.contains_key("b"));
}

/// The bag reports the constant `"<unknown>"`, never the repeated key —
/// that text is attacker-influenced content from inside the encrypted
/// manifest and is exactly the class `RecordError::DuplicateKey` once
/// leaked (#474).
#[test]
fn unknown_bag_rejects_a_repeat_without_naming_the_key() {
    let secret_looking_key = "a-key-a-peer-chose".to_string();
    let mut bag = UnknownBag::default();
    bag.insert(secret_looking_key.clone(), unknown_value(), 0)
        .expect("first key");
    match bag.insert(secret_looking_key.clone(), unknown_value(), INDEX) {
        Err(ManifestError::DuplicateKey { field, index }) => {
            assert_eq!(field, UNKNOWN_FIELD, "must report the constant");
            assert_ne!(
                field, secret_looking_key,
                "must NOT report the repeated key itself"
            );
            assert_eq!(index, INDEX, "must report the ordinal of the REPEAT");
        }
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}
