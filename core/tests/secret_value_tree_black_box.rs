//! Black-box coverage for `SecretValueTree` / `SecretEntries` (#547 / #548,
//! audit C-4) from *outside* `secretary-core`.
//!
//! Two things this file is and is not:
//!
//! - It genuinely exercises the crate-root `secretary_core::cbor::cbor_test_api`
//!   re-export path, the same reason `canonical_value_equivalence.rs` exercises
//!   `vault::canonical_test_api` — that path exists so both types can be
//!   declared `pub` (see `core/src/cbor/secret_tree.rs`'s module doc for why
//!   that's needed at all) without adding a caller inside `core/src/**`
//!   itself, which Task 3 deliberately does not do.
//! - It does **not** prove the wipe. `--cfg test` is not propagated to a
//!   dependent crate, so `SecretValueTree::wipe_for_test` and the
//!   `wipe_calls()` counter — both `#[cfg(test)]` inside `secretary-core` —
//!   do not exist in this binary at all; that half of the contract is
//!   covered by the unit tests in `core/src/cbor/secret_tree.rs` instead.
//!   What this file CAN and does prove, from outside the crate, is the
//!   ordinary (non-wipe) data contract: construction round-trips the value,
//!   and `SecretEntries::take_next` drains front-to-back and stops cleanly.

use ciborium::Value;
use secretary_core::cbor::cbor_test_api::{SecretEntries, SecretValueTree};

#[test]
fn secret_value_tree_as_value_round_trips_the_constructed_value() {
    let original = Value::Map(vec![(
        Value::Text("field".into()),
        Value::Bytes(vec![7, 8, 9]),
    )]);
    let tree = SecretValueTree::new(original.clone());
    assert_eq!(tree.as_value(), &original);
}

#[test]
fn secret_entries_take_next_drains_front_to_back_from_outside_the_crate() {
    let entries = vec![
        (Value::Text("k0".into()), Value::Integer(0.into())),
        (Value::Text("k1".into()), Value::Integer(1.into())),
        (Value::Text("k2".into()), Value::Integer(2.into())),
    ];
    let mut secret_entries = SecretEntries::new(entries);

    assert_eq!(secret_entries.len(), 3);
    assert!(!secret_entries.is_empty());
    assert_eq!(secret_entries.as_slice().len(), 3);

    for expected_key in ["k0", "k1", "k2"] {
        let (k, _) = secret_entries.take_next().expect("entry present");
        assert_eq!(k, Value::Text(expected_key.into()));
    }

    assert_eq!(secret_entries.len(), 0);
    assert!(secret_entries.is_empty());
    assert!(secret_entries.take_next().is_none());
}
