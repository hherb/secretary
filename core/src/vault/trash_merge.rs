//! Block-level trash-list reconciliation for conflict-copy merges (#401).
//!
//! When two conflict copies of a vault are merged, their `manifest.trash`
//! lists must be unioned and each entry's lifecycle fields reconciled. This
//! is the block-level analog of the record-level CRDT merge in
//! [`super::conflict`]; it lives in its own module because it is a distinct
//! concept (block tombstone lifecycle, not record field LWW) and because
//! `conflict.rs` is already large.
//!
//! All functions are pure. The merge is commutative, associative, and
//! idempotent (proved by `core/tests/proptest.rs`). Normative semantics:
//! `docs/crypto-design.md` §11.6. Cross-language witness:
//! `core/tests/python/conformance.py::py_merge_trash`.

use std::collections::BTreeMap;

use crate::vault::block::VectorClockEntry;
use crate::vault::conflict::{clock_relation, merge_unknown_map, ClockRelation};
use crate::vault::manifest::{BlockEntry, TrashEntry};

/// Merge two [`TrashEntry`] that share a `block_uuid` (§11.6).
///
/// - Tombstone triple `(tombstoned_at_ms, tombstoned_by, fingerprint)`:
///   the coherent triple from the side greatest under the tuple total order
///   (latest tombstone wins; ties by `tombstoned_by` then `fingerprint`,
///   `None < Some`). Never mixed across sides.
/// - `purged_at_ms`: independent + monotone — `Some` if either side is,
///   `max` millis, `None` loses to `Some`. `Option<u64>`'s `Ord` (`None <
///   Some`) makes `max` yield exactly this.
/// - `unknown`: §11.1 per-key union via `merge_unknown_map` (reused from
///   [`super::conflict`]).
pub fn merge_trash_entry(a: &TrashEntry, b: &TrashEntry) -> TrashEntry {
    debug_assert_eq!(
        a.block_uuid, b.block_uuid,
        "merge_trash_entry called on differing block_uuid"
    );
    let a_key = (a.tombstoned_at_ms, a.tombstoned_by, a.fingerprint);
    let b_key = (b.tombstoned_at_ms, b.tombstoned_by, b.fingerprint);
    let winner = if a_key >= b_key { a } else { b };
    TrashEntry {
        block_uuid: a.block_uuid,
        tombstoned_at_ms: winner.tombstoned_at_ms,
        tombstoned_by: winner.tombstoned_by,
        fingerprint: winner.fingerprint,
        purged_at_ms: a.purged_at_ms.max(b.purged_at_ms),
        unknown: merge_unknown_map(&a.unknown, &b.unknown),
    }
}

/// Union + reconcile trash lists across conflict copies (§11.6).
///
/// Folds every entry of every input list into a
/// `BTreeMap<block_uuid, TrashEntry>` via [`merge_trash_entry`], so the
/// output is sorted ascending by `block_uuid` with no duplicate `block_uuid`
/// — even if an individual input list is itself malformed (duplicate uuids).
/// Never drops an entry.
pub fn merge_trash_lists(lists: &[&[TrashEntry]]) -> Vec<TrashEntry> {
    let mut acc: BTreeMap<[u8; 16], TrashEntry> = BTreeMap::new();
    for list in lists {
        for entry in *list {
            acc.entry(entry.block_uuid)
                .and_modify(|existing| *existing = merge_trash_entry(existing, entry))
                .or_insert_with(|| entry.clone());
        }
    }
    acc.into_values().collect()
}

/// How one §11.6 live-vs-trash collision resolves: a block in the merged
/// trash that some folded manifest still lists in `blocks`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashCollision {
    /// Purge or trash wins: the block leaves `blocks`, the entry stays.
    TrashWins,
    /// Some live version holds an edit the trashing device never saw: the
    /// entry is dropped and the block stays live, its uncovered live versions
    /// merged with the trashed one.
    LiveWins,
    /// The rule needs the trashed file's clock and that file was not read.
    TrashedVersionUnavailable,
}

/// Whether deciding `entry` against the `live` versions needs the trashed
/// file's signed header clock: the entry is not purged, names a version, and
/// some live version is not that version.
#[must_use]
pub fn needs_trashed_clock(entry: &TrashEntry, live: &[&BlockEntry]) -> bool {
    match entry.fingerprint {
        Some(fp) if entry.purged_at_ms.is_none() => live.iter().any(|v| v.fingerprint != fp),
        _ => false,
    }
}

/// Resolve a live-vs-trash collision (crypto-design §11.6) from the merged
/// trash `entry`, every folded manifest's entry for the block (`live`), and
/// the trashed file's signed header clock if it was read. Depends only on
/// those inputs, never on which manifest is local.
///
/// A live version is covered when it is the trashed version (equal
/// fingerprint) or `trashed_clock` equals or dominates its clock.
#[must_use]
pub fn resolve_trash_collision(
    entry: &TrashEntry,
    live: &[&BlockEntry],
    trashed_clock: Option<&[VectorClockEntry]>,
) -> TrashCollision {
    if entry.purged_at_ms.is_some() {
        return TrashCollision::TrashWins;
    }
    let Some(fp) = entry.fingerprint else {
        return TrashCollision::LiveWins;
    };
    if !needs_trashed_clock(entry, live) {
        return TrashCollision::TrashWins;
    }
    let Some(trashed_clock) = trashed_clock else {
        return TrashCollision::TrashedVersionUnavailable;
    };
    let covered = |v: &&BlockEntry| {
        v.fingerprint == fp
            || matches!(
                clock_relation(trashed_clock, &v.vector_clock_summary),
                ClockRelation::Equal | ClockRelation::IncomingDominated
            )
    };
    if live.iter().all(covered) {
        TrashCollision::TrashWins
    } else {
        TrashCollision::LiveWins
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::record::UnknownValue;

    fn te(uuid: u8, t_at: u64, by: u8, fp: Option<u8>, purged: Option<u64>) -> TrashEntry {
        TrashEntry {
            block_uuid: [uuid; 16],
            tombstoned_at_ms: t_at,
            tombstoned_by: [by; 16],
            fingerprint: fp.map(|b| [b; 32]),
            purged_at_ms: purged,
            unknown: BTreeMap::new(),
        }
    }

    #[test]
    fn union_of_disjoint_uuids_sorted() {
        let a = te(0x02, 100, 1, None, None);
        let b = te(0x01, 100, 1, None, None);
        let merged = merge_trash_lists(&[&[a][..], &[b][..]]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].block_uuid, [0x01; 16]);
        assert_eq!(merged[1].block_uuid, [0x02; 16]);
    }

    #[test]
    fn collision_keeps_latest_triple() {
        let a = te(0x05, 100, 0xAA, Some(0x11), None);
        let b = te(0x05, 200, 0xBB, Some(0x22), None);
        let m = merge_trash_entry(&a, &b);
        assert_eq!(m.tombstoned_at_ms, 200);
        assert_eq!(m.tombstoned_by, [0xBB; 16]);
        assert_eq!(m.fingerprint, Some([0x22; 32]));
    }

    #[test]
    fn merge_lists_folds_colliding_uuid() {
        let a = te(0x05, 100, 0xAA, Some(0x11), None);
        let b = te(0x05, 200, 0xBB, Some(0x22), Some(40));
        let expected = merge_trash_entry(&a, &b);

        // Same list: two entries sharing block_uuid must fold, not overwrite.
        let merged_same_list = merge_trash_lists(&[&[a.clone(), b.clone()][..]]);
        assert_eq!(merged_same_list.len(), 1, "colliding uuid must dedupe");
        assert_eq!(merged_same_list[0], expected);

        // Across two lists: same fold must happen when entries arrive from
        // separate conflict-copy lists rather than the same slice.
        let merged_across_lists = merge_trash_lists(&[&[a][..], &[b][..]]);
        assert_eq!(merged_across_lists.len(), 1, "colliding uuid must dedupe");
        assert_eq!(merged_across_lists[0], expected);
    }

    #[test]
    fn purge_some_if_either_and_max() {
        assert_eq!(
            merge_trash_entry(&te(1, 10, 0, None, None), &te(1, 10, 0, None, Some(50)))
                .purged_at_ms,
            Some(50)
        );
        assert_eq!(
            merge_trash_entry(&te(1, 10, 0, None, Some(30)), &te(1, 10, 0, None, Some(70)))
                .purged_at_ms,
            Some(70)
        );
        assert_eq!(
            merge_trash_entry(&te(1, 10, 0, None, None), &te(1, 10, 0, None, None)).purged_at_ms,
            None
        );
    }

    #[test]
    fn purge_marker_independent_of_triple_winner() {
        // a has the later triple but is unpurged; b is earlier but purged.
        // Merged keeps a's triple AND b's purge marker.
        let a = te(0x07, 200, 0xAA, Some(0x11), None);
        let b = te(0x07, 100, 0xBB, Some(0x22), Some(50));
        let m = merge_trash_entry(&a, &b);
        assert_eq!(m.tombstoned_at_ms, 200);
        assert_eq!(m.fingerprint, Some([0x11; 32]));
        assert_eq!(m.purged_at_ms, Some(50));
    }

    #[test]
    fn unknown_maps_union() {
        let mut a = te(0x09, 100, 0, None, None);
        a.unknown.insert(
            "ka".into(),
            UnknownValue::from_canonical_cbor(&[0x0a]).unwrap(),
        );
        let mut b = te(0x09, 100, 0, None, None);
        b.unknown.insert(
            "kb".into(),
            UnknownValue::from_canonical_cbor(&[0x0b]).unwrap(),
        );
        let m = merge_trash_entry(&a, &b);
        assert_eq!(m.unknown.len(), 2);
        assert!(m.unknown.contains_key("ka") && m.unknown.contains_key("kb"));
    }

    const FP: [u8; 32] = [0x11; 32];
    const OTHER_FP: [u8; 32] = [0x22; 32];

    fn vc(counter: u64) -> Vec<VectorClockEntry> {
        vec![VectorClockEntry {
            device_uuid: [0x0D; 16],
            counter,
        }]
    }

    fn concurrent_vc() -> Vec<VectorClockEntry> {
        vec![VectorClockEntry {
            device_uuid: [0x0E; 16],
            counter: 1,
        }]
    }

    fn live(fingerprint: [u8; 32], clock: Vec<VectorClockEntry>) -> BlockEntry {
        BlockEntry {
            block_uuid: [0x0A; 16],
            block_name: String::new(),
            fingerprint,
            recipients: vec![],
            vector_clock_summary: clock,
            suite_id: 1,
            created_at_ms: 0,
            last_mod_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    /// The entry for block 0x0A recording `FP` as the trashed version.
    fn trashed(purged: Option<u64>) -> TrashEntry {
        te(0x0A, 100, 0, Some(0x11), purged)
    }

    #[test]
    fn purge_wins_over_any_live_version() {
        let v = live(OTHER_FP, concurrent_vc());
        assert_eq!(
            resolve_trash_collision(&trashed(Some(50)), &[&v], None),
            TrashCollision::TrashWins
        );
    }

    /// A copy that never saw the trash holds the trashed version itself;
    /// no file is needed to tell.
    #[test]
    fn the_trashed_version_itself_loses_to_the_trash() {
        let v = live(FP, vc(1));
        let t = trashed(None);
        assert!(!needs_trashed_clock(&t, &[&v]));
        assert_eq!(
            resolve_trash_collision(&t, &[&v], None),
            TrashCollision::TrashWins
        );
    }

    /// An older version the trashing device had seen is covered.
    #[test]
    fn a_version_the_trashed_one_dominates_loses_to_the_trash() {
        let v = live(OTHER_FP, vc(1));
        let t = trashed(None);
        assert!(needs_trashed_clock(&t, &[&v]));
        assert_eq!(
            resolve_trash_collision(&t, &[&v], Some(&vc(2))),
            TrashCollision::TrashWins
        );
    }

    /// An edit the trashing device never saw keeps the block live, whatever
    /// else is covered.
    #[test]
    fn an_uncovered_version_keeps_the_block_live() {
        let stale = live(FP, vc(1));
        for edit in [live(OTHER_FP, vc(3)), live(OTHER_FP, concurrent_vc())] {
            assert_eq!(
                resolve_trash_collision(&trashed(None), &[&stale, &edit], Some(&vc(2))),
                TrashCollision::LiveWins
            );
        }
    }

    /// Order of the live versions does not matter.
    #[test]
    fn the_outcome_does_not_depend_on_version_order() {
        let a = live(FP, vc(1));
        let b = live(OTHER_FP, concurrent_vc());
        let t = trashed(None);
        assert_eq!(
            resolve_trash_collision(&t, &[&a, &b], Some(&vc(2))),
            resolve_trash_collision(&t, &[&b, &a], Some(&vc(2)))
        );
    }

    #[test]
    fn a_needed_trashed_file_that_was_not_read_is_unavailable() {
        let v = live(OTHER_FP, vc(1));
        assert_eq!(
            resolve_trash_collision(&trashed(None), &[&v], None),
            TrashCollision::TrashedVersionUnavailable
        );
    }

    /// A legacy entry names no version, so nothing is covered.
    #[test]
    fn a_legacy_entry_without_a_fingerprint_loses_to_live() {
        let v = live(FP, vc(1));
        let t = te(0x0A, 100, 0, None, None);
        assert!(!needs_trashed_clock(&t, &[&v]));
        assert_eq!(
            resolve_trash_collision(&t, &[&v], None),
            TrashCollision::LiveWins
        );
    }
}
