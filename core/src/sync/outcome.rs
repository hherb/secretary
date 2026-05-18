//! Typed result of `sync_once` — one of four disjoint outcomes.

use crate::sync::bundle::{ManifestHash, VaultBundle};
use crate::sync::state::SyncState;
use crate::vault::block::VectorClockEntry;

/// Evidence accompanying a `RollbackRejected` outcome. Both the disk
/// state and the local-remembered state are surfaced so a caller's UX
/// (e.g., "I am restoring from backup, accept anyway") can show the
/// user what would be overwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackEvidence {
    pub disk_vector_clock: Vec<VectorClockEntry>,
    pub local_highest_seen: Vec<VectorClockEntry>,
}

/// Block UUIDs whose state diverges between the canonical manifest
/// and at least one authenticated conflict-copy. Computed by
/// [`crate::sync::ingest::compute_diff_plan`] from the assembled
/// [`VaultBundle`]. Consumed by C.1.1b's `prepare_merge`.
///
/// Sorted ascending (BTreeMap key order in the bundle's
/// `diverging_blocks`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPlan {
    pub diverging_blocks: Vec<[u8; 16]>,
}

/// `PartialEq` (but not `Eq`) because the C.1.1a `ConcurrentDetected`
/// variant carries a [`VaultBundle`] whose inner [`crate::vault::Manifest`]
/// derives `PartialEq` without `Eq` (the unknown-keys forward-compat
/// `BTreeMap` value type doesn't propagate `Eq`). No call site requires
/// `Eq` on `SyncOutcome` — tests use `assert_eq!`, which only needs
/// `PartialEq`.
// `large_enum_variant` fires because ConcurrentDetected carries a
// VaultBundle whose ManifestSnapshot is several hundred bytes deeper
// than the other variants. Boxing would force every caller's match
// arm to deref; allow it instead — this enum is one-per-call return
// value, not a hot Vec<SyncOutcome>.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum SyncOutcome {
    /// Disk has nothing new since the last sync. No state mutation.
    NothingToDo,

    /// Disk strictly dominates local highest_seen. The disk state is
    /// the new canonical truth. Caller persists `new_state` to OS
    /// keystore before the next call.
    AppliedAutomatically { new_state: SyncState },

    /// Disk and local highest_seen are concurrent (incomparable).
    /// `sync_once` has scanned the vault folder for conflict-copy
    /// files, authenticated each per spec §1a-D4, and packaged the
    /// result into `bundle`. Caller invokes C.1.1b's `prepare_merge`
    /// with `(folder, identity, bundle, plan)` to compute the draft
    /// merge before committing.
    ///
    /// `disk_vector_clock` and `local_highest_seen` are preserved
    /// from the predecessor `ForkDetected` variant (diagnostics + caller
    /// UX). `manifest_hash` is the TOCTOU freshness anchor the C.1.1b
    /// commit path re-checks against the on-disk canonical manifest
    /// before applying the merged result.
    ConcurrentDetected {
        bundle: VaultBundle,
        plan: DiffPlan,
        manifest_hash: ManifestHash,
        disk_vector_clock: Vec<VectorClockEntry>,
        local_highest_seen: Vec<VectorClockEntry>,
    },

    /// Disk vector clock is strictly dominated by local highest_seen.
    /// Per `docs/crypto-design.md` §10 — rollback rejected.
    RollbackRejected(RollbackEvidence),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_do_eq() {
        assert_eq!(SyncOutcome::NothingToDo, SyncOutcome::NothingToDo);
    }

    #[test]
    fn applied_automatically_eq_when_new_state_matches() {
        let s = SyncState::empty([1u8; 16]);
        assert_eq!(
            SyncOutcome::AppliedAutomatically {
                new_state: s.clone()
            },
            SyncOutcome::AppliedAutomatically { new_state: s },
        );
    }

    #[test]
    fn rollback_evidence_carries_both_clocks() {
        let entry = VectorClockEntry {
            device_uuid: [1u8; 16],
            counter: 5,
        };
        let evidence = RollbackEvidence {
            disk_vector_clock: vec![entry.clone()],
            local_highest_seen: vec![entry.clone()],
        };
        assert_eq!(evidence.disk_vector_clock.len(), 1);
        assert_eq!(evidence.local_highest_seen.len(), 1);
    }

    #[test]
    fn diff_plan_eq_is_bytewise() {
        let a = DiffPlan {
            diverging_blocks: vec![[0xAA; 16], [0xBB; 16]],
        };
        let b = DiffPlan {
            diverging_blocks: vec![[0xAA; 16], [0xBB; 16]],
        };
        let c = DiffPlan {
            diverging_blocks: vec![[0xCC; 16]],
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
