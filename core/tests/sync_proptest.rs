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

    /// `AppliedAutomatically` produces a `new_state` that is a fixpoint:
    /// re-dispatching with the same `disk_clock` yields `NothingToDo`.
    ///
    /// Input construction guarantees `AppliedAutomatically` — disk strictly
    /// dominates state by appending a fresh device with a non-zero counter
    /// (the fresh device is constructed to be distinct from all state
    /// entries). Without this construction, naive random `(state, disk)`
    /// pairs over the 128-bit device-uuid space would mostly produce
    /// `ForkDetected`, and the property would silently no-op for 3 of 4
    /// outcomes — diluting its value as evidence of the fixpoint.
    #[test]
    fn prop_applied_then_nothing_to_do(
        vault_uuid in any::<[u8; 16]>(),
        state_clock in canonical_clock_strategy(),
        seed_device in any::<[u8; 16]>(),
        new_counter in 1u64..u64::MAX,
    ) {
        // Find a device that isn't already in state. Worst case loops 256
        // times (state has ≤ 6 entries, so collisions are rare on a 128-bit
        // space and the high-byte bump exhausts the namespace deterministically).
        let mut fresh_device = seed_device;
        let mut bumps = 0u32;
        while state_clock.iter().any(|e| e.device_uuid == fresh_device) {
            fresh_device[0] = fresh_device[0].wrapping_add(1);
            bumps += 1;
            prop_assert!(bumps < 256, "could not find a fresh device uuid");
        }

        let mut disk_clock = state_clock.clone();
        disk_clock.push(VectorClockEntry { device_uuid: fresh_device, counter: new_counter });
        disk_clock.sort_by_key(|e| e.device_uuid);

        let state = SyncState::new(vault_uuid, state_clock).unwrap();
        let new_state = match __test_dispatch(disk_clock.clone(), &state)
            .unwrap()
            .expect("constructed input must yield Some(AppliedAutomatically)")
        {
            SyncOutcome::AppliedAutomatically { new_state } => new_state,
            other => {
                prop_assert!(
                    false,
                    "constructed input must yield AppliedAutomatically, got {:?}",
                    other,
                );
                unreachable!()
            }
        };
        let second = __test_dispatch(disk_clock, &new_state)
            .unwrap()
            .expect("re-dispatch on fixpoint must yield Some(NothingToDo)");
        prop_assert_eq!(second, SyncOutcome::NothingToDo);
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
        let outcome_opt = __test_dispatch(disk_clock, &state).unwrap();
        // The clock-only dispatch helper returns Ok(None) on Concurrent
        // (the full ConcurrentDetected variant requires folder I/O).
        // Pattern coverage on the inner outcome — any future variant
        // addition compile-errors here.
        let _classified: u8 = match outcome_opt {
            None => 2, // signals Concurrent → bundle-carrying outcome
            Some(SyncOutcome::NothingToDo) => 0,
            Some(SyncOutcome::AppliedAutomatically { .. }) => 1,
            Some(SyncOutcome::ConcurrentDetected { .. }) => 2,
            Some(SyncOutcome::RollbackRejected(RollbackEvidence { .. })) => 3,
        };
    }
}
