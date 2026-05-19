//! `prepare_merge` — turn the C.1.1a [`crate::sync::VaultBundle`] into a
//! [`crate::sync::DraftMerge`] by decrypting each diverging block on
//! demand and composing the existing `merge_block` primitive into an
//! N-way pairwise fold.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"prepare_merge". This module currently exposes only
//! [`tombstone_veto_set`], the pure-function core of veto detection;
//! `prepare_merge` itself lands in Task 8 of the
//! C.1.1b plan.

use crate::sync::draft::{BlockId, RecordTombstoneVeto};
use crate::vault::record::Record;

/// Pure-function veto check: given the local (canonical) record and
/// the per-copy peer records that share its `record_uuid`, return a
/// [`RecordTombstoneVeto`] iff any peer copy would tombstone the
/// record at a timestamp strictly later than the local `last_mod_ms`,
/// AND the local copy is still live (`!local.tombstone`).
///
/// **Why "strictly later":** equality is the C.1.1a §11.3
/// staleness-filter boundary — a tombstone observed AT the same
/// instant as the local edit applies under LWW without needing user
/// veto. Strict-later is the "peer saw my live edit, then deleted,
/// while I made a newer edit they haven't seen yet" case the user
/// must adjudicate.
///
/// When multiple peers tombstone after the local edit, the returned
/// veto carries the *latest* peer's `tombstoned_at_ms` and the
/// best-effort device uuid attached to it. Tests assert there's at
/// most one canonical peer for the same `record_uuid` in a
/// well-formed bundle (each copy must be signed by the canonical
/// owner identity — an attacker forging multiple copies cannot bypass
/// the design).
///
/// **Pure:** borrows all inputs, allocates only the returned
/// [`RecordTombstoneVeto`] (which `clone()`s `local` so the caller
/// retains ownership).
///
/// # Caller-side invariants (not enforced here)
///
/// - All peers in `remote_per_copy` are expected to share
///   `local.record_uuid`. Peers with a different `record_uuid` are
///   compared timestamps-only and would still trigger a veto, but
///   that would be a [`prepare_merge`]-side correctness bug rather
///   than this helper's concern.
/// - `block_id` is forwarded into the returned veto unchanged.
#[must_use]
// First real consumer lands in Task 8 (`prepare_merge`). The shim
// keeps the per-task TDD cadence green; Task 17's pre-merge audit
// confirms the consumer exists before the C.1.1b PR ships.
#[allow(dead_code)]
pub(crate) fn tombstone_veto_set(
    local: &Record,
    block_id: BlockId,
    remote_per_copy: &[&Record],
) -> Option<RecordTombstoneVeto> {
    if local.tombstone {
        return None;
    }
    let mut latest: Option<(u64, [u8; 16])> = None;
    for peer in remote_per_copy {
        if peer.tombstone && peer.tombstoned_at_ms > local.last_mod_ms {
            let cand = (
                peer.tombstoned_at_ms,
                last_modifier_device(peer).unwrap_or([0u8; 16]),
            );
            latest = Some(match latest {
                Some(prev) if prev.0 >= cand.0 => prev,
                _ => cand,
            });
        }
    }
    latest.map(|(at_ms, device)| RecordTombstoneVeto {
        record_id: local.record_uuid,
        block_id,
        local_state: local.clone(),
        disk_tombstone_at_ms: at_ms,
        disk_tombstoner_device: device,
    })
}

/// Best-effort recovery of the device uuid that performed the last
/// modification on a record. Records don't carry a record-level
/// `device_uuid`; the per-field `device_uuid` of the field with the
/// highest `last_mod` is the closest available signal. Tombstoned
/// records with empty `fields` return `None`; callers fall back to a
/// sentinel (the all-zero uuid).
// Indirect-only consumer until Task 8 wires `prepare_merge`; reached
// today through `tombstone_veto_set`'s test paths that hit the empty-
// fields branch (returns `None`).
#[allow(dead_code)]
fn last_modifier_device(record: &Record) -> Option<[u8; 16]> {
    record
        .fields
        .values()
        .max_by_key(|f| f.last_mod)
        .map(|f| f.device_uuid)
}

#[cfg(test)]
mod tests {
    use super::tombstone_veto_set;
    use crate::sync::draft::BlockId;
    use crate::vault::record::Record;
    use std::collections::BTreeMap;

    /// Construct a test [`Record`] with explicit tombstone state. All
    /// other fields take placeholder defaults — `tombstone_veto_set`
    /// only inspects `record_uuid`, `last_mod_ms`, `tombstone`,
    /// `tombstoned_at_ms`, and (via `last_modifier_device`) `fields`.
    fn rec(uuid: u8, last_mod_ms: u64, tombstone: bool, tombstoned_at_ms: u64) -> Record {
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: 0,
            last_mod_ms,
            tombstone,
            tombstoned_at_ms,
            unknown: BTreeMap::new(),
        }
    }

    /// Block-uuid placeholder used by every veto-set assertion. The
    /// value is opaque — `tombstone_veto_set` only forwards it into
    /// the returned `RecordTombstoneVeto.block_id`.
    const TEST_BLOCK_UUID: BlockId = [0xBB; 16];

    #[test]
    fn no_peers_no_veto() {
        let local = rec(1, 100, false, 0);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[]).is_none());
    }

    #[test]
    fn peer_live_no_veto() {
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 200, false, 0);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_before_local_edit_no_veto() {
        // local edited at t=100; peer tombstoned at t=50. Local
        // last_mod_ms (100) > peer.tombstoned_at_ms (50). LWW already
        // wins; no veto needed.
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 50, true, 50);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_at_same_instant_as_local_edit_no_veto() {
        // Boundary: strict-later predicate. Equality goes silent.
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 100, true, 100);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_after_local_edit_vetoes() {
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 200, true, 200);
        let veto = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).expect("expected veto");
        assert_eq!(veto.record_id, [1; 16]);
        assert_eq!(veto.block_id, TEST_BLOCK_UUID);
        assert_eq!(veto.disk_tombstone_at_ms, 200);
    }

    #[test]
    fn local_tombstoned_no_veto_regardless_of_peer() {
        let local = rec(1, 100, true, 100);
        let peer = rec(1, 200, true, 200);
        assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
    }

    #[test]
    fn multiple_peers_latest_wins() {
        let local = rec(1, 100, false, 0);
        let peer_a = rec(1, 200, true, 200);
        let peer_b = rec(1, 300, true, 300);
        let veto = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer_a, &peer_b])
            .expect("expected veto");
        assert_eq!(veto.disk_tombstone_at_ms, 300);
    }
}
