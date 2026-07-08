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

use std::collections::{BTreeMap, BTreeSet};

use crate::vault::conflict::merge_unknown_map;
use crate::vault::manifest::TrashEntry;

/// Merge two [`TrashEntry`] that share a `block_uuid` (§11.6).
///
/// - Tombstone triple `(tombstoned_at_ms, tombstoned_by, fingerprint)`:
///   the coherent triple from the side greatest under the tuple total order
///   (latest tombstone wins; ties by `tombstoned_by` then `fingerprint`,
///   `None < Some`). Never mixed across sides.
/// - `purged_at_ms`: independent + monotone — `Some` if either side is,
///   `max` millis, `None` loses to `Some`. `Option<u64>`'s `Ord` (`None <
///   Some`) makes `max` yield exactly this.
/// - `unknown`: §11.1 per-key union via [`merge_unknown_map`].
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

/// Purge-terminal live-vs-trash collision resolution (§11.6).
///
/// Given the live block uuids and the reconciled trash list, returns
/// `(blocks_to_remove, trash)`:
///
/// - `blocks_to_remove` — block uuids the caller must drop from
///   `manifest.blocks` because a **purged** trash entry collides with them
///   (purge wins).
/// - `trash` — the trash list with **non-purged** live collisions dropped
///   (live wins). Purged entries are always kept.
///
/// The result guarantees `blocks` and `trash` are disjoint after the caller
/// applies `blocks_to_remove`.
pub fn resolve_live_vs_trash(
    live_block_uuids: &BTreeSet<[u8; 16]>,
    trash: Vec<TrashEntry>,
) -> (BTreeSet<[u8; 16]>, Vec<TrashEntry>) {
    let blocks_to_remove: BTreeSet<[u8; 16]> = trash
        .iter()
        .filter(|t| t.purged_at_ms.is_some() && live_block_uuids.contains(&t.block_uuid))
        .map(|t| t.block_uuid)
        .collect();
    let trash = trash
        .into_iter()
        .filter(|t| t.purged_at_ms.is_some() || !live_block_uuids.contains(&t.block_uuid))
        .collect();
    (blocks_to_remove, trash)
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

    #[test]
    fn resolve_purge_terminal_removes_live_block() {
        let live: BTreeSet<[u8; 16]> = [[0x0A; 16]].into_iter().collect();
        let (remove, trash) = resolve_live_vs_trash(&live, vec![te(0x0A, 100, 0, None, Some(50))]);
        assert_eq!(remove, [[0x0A; 16]].into_iter().collect());
        assert_eq!(trash.len(), 1, "purged entry kept");
    }

    #[test]
    fn resolve_live_wins_over_nonpurged() {
        let live: BTreeSet<[u8; 16]> = [[0x0A; 16]].into_iter().collect();
        let (remove, trash) = resolve_live_vs_trash(&live, vec![te(0x0A, 100, 0, None, None)]);
        assert!(remove.is_empty());
        assert!(trash.is_empty(), "non-purged live collision dropped");
    }

    #[test]
    fn resolve_no_collision_keeps_everything() {
        let live: BTreeSet<[u8; 16]> = [[0x0B; 16]].into_iter().collect();
        let (remove, trash) = resolve_live_vs_trash(&live, vec![te(0x0A, 100, 0, None, Some(50))]);
        assert!(remove.is_empty());
        assert_eq!(trash.len(), 1);
    }
}
