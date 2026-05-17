//! Property tests for `core::sync::sync_once` and `__test_dispatch`.

#![forbid(unsafe_code)]

use proptest::prelude::*;
use secretary_core::sync::{__test_dispatch, RollbackEvidence, SyncOutcome, SyncState};
use secretary_core::vault::block::VectorClockEntry;

fn entry_strategy() -> impl Strategy<Value = VectorClockEntry> {
    (any::<[u8; 16]>(), any::<u64>()).prop_map(|(device_uuid, counter)| VectorClockEntry {
        device_uuid,
        counter,
    })
}

/// Generates a canonical (sorted, deduped) vector clock — same
/// invariant SyncState enforces.
fn canonical_clock_strategy() -> impl Strategy<Value = Vec<VectorClockEntry>> {
    prop::collection::vec(entry_strategy(), 0..6).prop_map(|mut v| {
        v.sort_by_key(|e| e.device_uuid);
        v.dedup_by_key(|e| e.device_uuid);
        v
    })
}

proptest! {
    /// `sync_once`'s dispatch is deterministic: calling it twice with
    /// identical inputs must yield identical outputs.
    #[test]
    fn prop_dispatch_idempotent_under_repeat(
        vault_uuid in any::<[u8; 16]>(),
        state_clock in canonical_clock_strategy(),
        disk_clock in canonical_clock_strategy(),
    ) {
        let state = SyncState::new(vault_uuid, state_clock).unwrap();
        let first = __test_dispatch(disk_clock.clone(), &state).unwrap();
        let second = __test_dispatch(disk_clock, &state).unwrap();
        prop_assert_eq!(first, second);
    }

    /// After `AppliedAutomatically`, re-running the dispatch with the
    /// returned new_state and the same disk_clock yields `NothingToDo`.
    #[test]
    fn prop_applied_then_nothing_to_do(
        vault_uuid in any::<[u8; 16]>(),
        state_clock in canonical_clock_strategy(),
        disk_clock in canonical_clock_strategy(),
    ) {
        let state = SyncState::new(vault_uuid, state_clock).unwrap();
        if let SyncOutcome::AppliedAutomatically { new_state } =
            __test_dispatch(disk_clock.clone(), &state).unwrap()
        {
            let second = __test_dispatch(disk_clock, &new_state).unwrap();
            prop_assert_eq!(second, SyncOutcome::NothingToDo);
        }
        // Other outcomes — nothing to assert for this property.
    }

    /// Branch coverage is disjoint: exactly one of the four variants
    /// is returned, no panics, no overlaps.
    #[test]
    fn prop_branches_disjoint_and_total(
        vault_uuid in any::<[u8; 16]>(),
        state_clock in canonical_clock_strategy(),
        disk_clock in canonical_clock_strategy(),
    ) {
        let state = SyncState::new(vault_uuid, state_clock).unwrap();
        let outcome = __test_dispatch(disk_clock, &state).unwrap();
        // Pattern coverage — any future variant addition compile-errors here.
        let _classified: u8 = match outcome {
            SyncOutcome::NothingToDo => 0,
            SyncOutcome::AppliedAutomatically { .. } => 1,
            SyncOutcome::ForkDetected { .. } => 2,
            SyncOutcome::RollbackRejected(RollbackEvidence { .. }) => 3,
        };
    }
}
