//! Typed result of `sync_once` — one of four disjoint outcomes.

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Disk has nothing new since the last sync. No state mutation.
    NothingToDo,

    /// Disk strictly dominates local highest_seen. The disk state is
    /// the new canonical truth. Caller persists `new_state` to OS
    /// keystore before the next call.
    AppliedAutomatically { new_state: SyncState },

    /// Disk and local highest_seen are concurrent (incomparable). The
    /// vault has forked across devices. Per `docs/threat-model.md` §4
    /// limit 3, detection is sufficient at this layer; C.1.1 extends.
    ForkDetected {
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
}
