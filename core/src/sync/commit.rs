//! `commit_with_decisions` — atomic disk write of a merged + decided
//! vault state. This module currently ships the pure helper
//! [`apply_decisions`] (C.1.1b Task 10); the full
//! `commit_with_decisions` orchestrator lands in Task 11.
//!
//! [`apply_decisions`] enforces the bijection between
//! [`DraftMerge::vetoes`] and the caller's [`VetoDecision`] slice and
//! returns the post-decision merged record set. The freshness re-check
//! against `draft.manifest_hash`, the block-first manifest-last write
//! ordering, and the post-commit [`crate::sync::SyncState`] return all
//! belong to [`commit_with_decisions`].
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"commit_with_decisions".

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::sync::draft::{DraftMerge, RecordId, RecordTombstoneVeto, VetoDecision};
use crate::sync::error::SyncError;
use crate::vault::record::Record;

/// Apply caller decisions to a [`DraftMerge`]'s `merged_records`, after
/// enforcing a strict bijection between `draft.vetoes` and `decisions`.
///
/// Bijection rules:
/// - Every `decision.record_id()` is in `{v.record_id for v in draft.vetoes}`
/// - Every `veto.record_id` is in `{d.record_id() for d in decisions}`
///
/// Note: `BTreeSet` dedupe means duplicate decisions for the same
/// `record_id` collapse to a single entry, so two `KeepLocal` entries
/// for the same id are not a cardinality error. Tightening this to a
/// typed duplicate-decision error is tracked in
/// [issue #98](https://github.com/hherb/secretary/issues/98).
///
/// Violations → typed [`SyncError::MissingVetoDecision`] /
/// [`SyncError::UnknownVetoDecision`]. The error always points at the
/// smallest offending `record_id` in canonical sort order so test
/// assertions are deterministic.
///
/// Semantics per veto/decision pair:
/// - [`VetoDecision::KeepLocal`] — restore the matching record in
///   `merged_records` to the veto's `local_state` (clearing any
///   peer-side tombstone the merge picked up).
/// - [`VetoDecision::AcceptTombstone`] — leave the record in
///   `merged_records` as-is (the merge already wrote the death clock).
///
/// Pure function: takes `&DraftMerge` + `&[VetoDecision]`, returns
/// `Result<Vec<Record>, SyncError>` (the post-decision record set,
/// sorted by `record_uuid` to match `prepare_merge`'s output shape).
/// The vector clock + manifest fields stay on `draft`; callers re-read
/// them after this helper to build the new on-disk manifest in Task 11.
#[allow(dead_code)] // Consumed by commit_with_decisions in Task 11.
pub(crate) fn apply_decisions(
    draft: &DraftMerge,
    decisions: &[VetoDecision],
) -> Result<Vec<Record>, SyncError> {
    // Index vetoes by record_id so the KeepLocal lookup below is O(log n)
    // and structurally cannot fail once the bijection check passes.
    let vetoes_by_id: BTreeMap<RecordId, &RecordTombstoneVeto> =
        draft.vetoes.iter().map(|v| (v.record_id, v)).collect();
    let decision_ids: BTreeSet<RecordId> = decisions.iter().map(|d| d.record_id()).collect();

    // Bijection check. BTreeSet view of vetoes_by_id.keys() preserves
    // canonical-sort ordering so the smallest offending id is reported
    // deterministically by test assertions.
    let veto_ids: BTreeSet<RecordId> = vetoes_by_id.keys().copied().collect();
    if let Some(missing) = veto_ids.difference(&decision_ids).next() {
        return Err(SyncError::MissingVetoDecision {
            record_id: *missing,
        });
    }
    if let Some(unknown) = decision_ids.difference(&veto_ids).next() {
        return Err(SyncError::UnknownVetoDecision {
            record_id: *unknown,
        });
    }

    // Index merged records by id for O(log n) per-decision update and
    // canonical sort-by-uuid output (matches prepare_merge::merged_records
    // construction via BTreeMap::into_values).
    let mut records_by_id: BTreeMap<RecordId, Record> = draft
        .merged_records
        .iter()
        .cloned()
        .map(|r| (r.record_uuid, r))
        .collect();

    for d in decisions {
        match d {
            VetoDecision::AcceptTombstone { .. } => {}
            VetoDecision::KeepLocal { record_id } => {
                // Both lookups are infallible by construction:
                //  - vetoes_by_id: the bijection check above guarantees
                //    every decision.record_id is a key.
                //  - records_by_id: prepare_merge only emits a veto for
                //    a record_id it has just placed in merged_records
                //    (see prepare.rs::prepare_merge — the veto pass is
                //    nested inside `for (record_uuid, _) in acc_records`,
                //    and acc_records flows into merged_records).
                let veto = vetoes_by_id
                    .get(record_id)
                    .expect("bijection check guarantees a veto for this decision.record_id");
                let slot = records_by_id
                    .get_mut(record_id)
                    .expect("prepare_merge guarantees veto.record_id is in merged_records");
                *slot = veto.local_state.clone();
            }
        }
    }
    Ok(records_by_id.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::bundle::ManifestHash;
    use crate::sync::draft::RecordTombstoneVeto;
    use crate::sync::outcome::DiffPlan;
    use std::collections::BTreeMap;

    /// Fixed UUID bytes used across the table tests. Picked from the
    /// 0xAA / 0xBB / 0xCC space already used in `draft.rs` so the
    /// fixture bytes stay readable in failing-test output.
    const VETO_BLOCK_ID: [u8; 16] = [0xBB; 16];
    const VETO_TOMBSTONER_DEVICE: [u8; 16] = [0xCC; 16];
    const DRAFT_VAULT_UUID: [u8; 16] = [9; 16];
    /// Synthetic tombstone clock used by the peer side; chosen so that
    /// `local_state.last_mod_ms` (100) is strictly less than this and
    /// the resurrection-vs-tombstone story is self-consistent in
    /// failing-test output.
    const DISK_TOMBSTONE_AT_MS: u64 = 200;

    /// Construct a minimal well-formed live [`Record`]. `last_mod_ms`
    /// doubles as the synthetic clock anchor; `created_at_ms` is set
    /// 1000 ms earlier so `created_at_ms <= last_mod_ms` holds.
    fn rec(uuid: u8, last_mod_ms: u64) -> Record {
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: last_mod_ms.saturating_sub(1_000),
            last_mod_ms,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    /// Minimal [`RecordTombstoneVeto`] whose `local_state` is the live
    /// record with `last_mod_ms = 100`.
    fn veto(uuid: u8) -> RecordTombstoneVeto {
        RecordTombstoneVeto {
            record_id: [uuid; 16],
            block_id: VETO_BLOCK_ID,
            local_state: rec(uuid, 100),
            disk_tombstone_at_ms: DISK_TOMBSTONE_AT_MS,
            disk_tombstoner_device: VETO_TOMBSTONER_DEVICE,
        }
    }

    fn draft_with_vetoes(vetoes: Vec<RecordTombstoneVeto>, merged: Vec<Record>) -> DraftMerge {
        DraftMerge {
            vault_uuid: DRAFT_VAULT_UUID,
            plan: DiffPlan {
                diverging_blocks: vec![],
            },
            manifest_hash: ManifestHash([0; 32]),
            merged_records: merged,
            vetoes,
            post_merge_clock: vec![],
        }
    }

    /// Empty vetoes + empty decisions is a no-op: the merged record
    /// set is returned unchanged. This is the silent-merge happy path.
    #[test]
    fn empty_vetoes_empty_decisions_returns_unchanged_records() {
        let d = draft_with_vetoes(vec![], vec![rec(1, 100)]);
        let out = apply_decisions(&d, &[]).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record_uuid, [1; 16]);
    }

    /// `KeepLocal` restores the veto's `local_state` over a tombstoned
    /// merged record. The post-decision record is the live version with
    /// `tombstone == false` and `last_mod_ms == 100`.
    #[test]
    fn keep_local_overrides_tombstoned_record() {
        let live = rec(1, 100);
        let tombstoned = Record {
            tombstone: true,
            tombstoned_at_ms: DISK_TOMBSTONE_AT_MS,
            ..rec(1, DISK_TOMBSTONE_AT_MS)
        };
        let v = RecordTombstoneVeto {
            record_id: [1; 16],
            block_id: VETO_BLOCK_ID,
            local_state: live.clone(),
            disk_tombstone_at_ms: DISK_TOMBSTONE_AT_MS,
            disk_tombstoner_device: VETO_TOMBSTONER_DEVICE,
        };
        let d = draft_with_vetoes(vec![v], vec![tombstoned]);
        let out =
            apply_decisions(&d, &[VetoDecision::KeepLocal { record_id: [1; 16] }]).expect("ok");
        assert_eq!(out.len(), 1);
        assert!(!out[0].tombstone);
        assert_eq!(out[0].last_mod_ms, 100);
    }

    /// `AcceptTombstone` is a no-op: the merged set already holds the
    /// tombstoned record (the merge wrote the death clock), and the
    /// decision just records caller assent.
    #[test]
    fn accept_tombstone_is_noop() {
        let tombstoned = Record {
            tombstone: true,
            tombstoned_at_ms: DISK_TOMBSTONE_AT_MS,
            ..rec(1, DISK_TOMBSTONE_AT_MS)
        };
        let d = draft_with_vetoes(vec![veto(1)], vec![tombstoned]);
        let out = apply_decisions(&d, &[VetoDecision::AcceptTombstone { record_id: [1; 16] }])
            .expect("ok");
        assert_eq!(out.len(), 1);
        assert!(out[0].tombstone);
    }

    /// Two vetoes, one decision → `MissingVetoDecision` points at the
    /// smallest unmatched veto `record_id` (BTreeSet ordering is
    /// canonical).
    #[test]
    fn missing_decision_returns_missing_veto_decision() {
        let d = draft_with_vetoes(vec![veto(1), veto(2)], vec![rec(1, 100), rec(2, 100)]);
        let err = apply_decisions(&d, &[VetoDecision::KeepLocal { record_id: [1; 16] }])
            .expect_err("expected missing");
        match err {
            SyncError::MissingVetoDecision { record_id } => assert_eq!(record_id, [2; 16]),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// One veto, two decisions (one matching, one stray) → the stray
    /// fires `UnknownVetoDecision`.
    #[test]
    fn unknown_decision_returns_unknown_veto_decision() {
        let d = draft_with_vetoes(vec![veto(1)], vec![rec(1, 100)]);
        let err = apply_decisions(
            &d,
            &[
                VetoDecision::KeepLocal { record_id: [1; 16] },
                VetoDecision::KeepLocal { record_id: [9; 16] },
            ],
        )
        .expect_err("expected unknown");
        match err {
            SyncError::UnknownVetoDecision { record_id } => assert_eq!(record_id, [9; 16]),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Two `KeepLocal` decisions targeting the same `record_id` collapse
    /// to one (BTreeSet-based bijection check). Pins current behaviour;
    /// upgrading to a typed duplicate-decision error is tracked in
    /// [issue #98](https://github.com/hherb/secretary/issues/98).
    #[test]
    fn duplicate_decisions_for_same_id_treated_as_one() {
        let d = draft_with_vetoes(vec![veto(1)], vec![rec(1, 100)]);
        let out = apply_decisions(
            &d,
            &[
                VetoDecision::KeepLocal { record_id: [1; 16] },
                VetoDecision::KeepLocal { record_id: [1; 16] },
            ],
        )
        .expect("ok");
        assert_eq!(out.len(), 1);
    }
}
