//! The live-vs-trash collisions of one merge (crypto-design §11.6, #783).
//!
//! A block in the merged trash that some folded manifest still lists in
//! `blocks` is resolved by [`resolve_trash_collision`] from the manifests and
//! the trashed file's signed header clock alone, never from which manifest is
//! canonical. Ingest uses the outcome to choose which block files to read, and
//! `prepare_merge` uses the same outcome to refuse, fold and write, so the two
//! cannot disagree.

use std::collections::BTreeMap;

use crate::crypto::hash::hash as blake3_hash;
use crate::sync::bundle::{BlockDivergence, BlockEnvelope, ManifestSnapshot};
use crate::sync::ingest::{copy_version_is_uncovered, listed_block_diverges};
use crate::vault::block::{decode_block_file, VectorClockEntry};
use crate::vault::manifest::TrashEntry;
use crate::vault::trash_merge::merge_trash_lists;
use crate::vault::{
    clock_relation, resolve_trash_collision, BlockEntry, ClockRelation, Manifest, TrashCollision,
};

/// The folded manifests (the canonical one, then each copy) that are not
/// superseded (crypto-design §11.7): a manifest whose clock another one's
/// dominates, or equals with that one earlier in the list, holds nothing the
/// other lacks. Counting it would bring back a trash entry a later restore
/// removed, since a trash entry carries no clock.
#[must_use]
pub(crate) fn counted_manifests<'a>(
    canonical: &'a Manifest,
    copies: &'a [ManifestSnapshot],
) -> Vec<&'a Manifest> {
    let all: Vec<&Manifest> = std::iter::once(canonical)
        .chain(copies.iter().map(|c| &c.manifest))
        .collect();
    all.iter()
        .enumerate()
        .filter(|(i, m)| {
            !all.iter().enumerate().any(|(j, other)| {
                j != *i
                    && match clock_relation(&other.vector_clock, &m.vector_clock) {
                        ClockRelation::IncomingDominated => true,
                        ClockRelation::Equal => j < *i,
                        _ => false,
                    }
            })
        })
        .map(|(_, m)| *m)
        .collect()
}

/// The trash lists of the [`counted_manifests`], reconciled by §11.6's union
/// (before any collision is resolved).
#[must_use]
pub(crate) fn merged_trash(canonical: &Manifest, copies: &[ManifestSnapshot]) -> Vec<TrashEntry> {
    let lists: Vec<&[TrashEntry]> = counted_manifests(canonical, copies)
        .into_iter()
        .map(|m| m.trash.as_slice())
        .collect();
    merge_trash_lists(&lists)
}

/// Every [`counted_manifests`] entry for `block_uuid` in `blocks`, the
/// canonical one first.
#[must_use]
pub(crate) fn live_versions<'a>(
    block_uuid: &[u8; 16],
    canonical: &'a Manifest,
    copies: &'a [ManifestSnapshot],
) -> Vec<&'a BlockEntry> {
    counted_manifests(canonical, copies)
        .into_iter()
        .flat_map(|m| m.blocks.iter())
        .filter(|e| e.block_uuid == *block_uuid)
        .collect()
}

/// The signed header clock of `block_uuid`'s trashed file, if ingest read it
/// and its fingerprint is the one `entry` records.
fn trashed_clock(
    entry: &TrashEntry,
    trashed: &BTreeMap<[u8; 16], BlockEnvelope>,
) -> Option<Vec<VectorClockEntry>> {
    let envelope = trashed.get(&entry.block_uuid)?;
    if entry.fingerprint != Some(*blake3_hash(&envelope.bytes).as_bytes()) {
        return None;
    }
    decode_block_file(&envelope.bytes)
        .ok()
        .map(|f| f.header.vector_clock)
}

/// The outcome of every collision in this merge, keyed by `block_uuid`. A
/// trash entry no folded manifest lists live is no collision and is absent.
#[must_use]
pub(crate) fn collisions(
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    trashed: &BTreeMap<[u8; 16], BlockEnvelope>,
) -> BTreeMap<[u8; 16], TrashCollision> {
    merged_trash(canonical, copies)
        .iter()
        .filter_map(|entry| {
            let live = live_versions(&entry.block_uuid, canonical, copies);
            if live.is_empty() {
                return None;
            }
            let clock = trashed_clock(entry, trashed);
            Some((
                entry.block_uuid,
                resolve_trash_collision(entry, &live, clock.as_deref()),
            ))
        })
        .collect()
}

/// The merged trash the commit writes: [`merged_trash`] without the entries
/// a live block beat.
#[must_use]
pub(crate) fn resolved_trash(
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    collisions: &BTreeMap<[u8; 16], TrashCollision>,
) -> Vec<TrashEntry> {
    merged_trash(canonical, copies)
        .into_iter()
        .filter(|t| collisions.get(&t.block_uuid) != Some(&TrashCollision::LiveWins))
        .collect()
}

/// Whether the merged trash removes `block_uuid` from `blocks`: it holds an
/// entry for it that no live block beat. That covers a collision the trash
/// won and an entry no counted manifest lists live (the only live listing
/// may be a superseded copy's).
#[must_use]
pub(crate) fn trash_removes(
    block_uuid: &[u8; 16],
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    collisions: &BTreeMap<[u8; 16], TrashCollision>,
) -> bool {
    collisions.get(block_uuid) != Some(&TrashCollision::LiveWins)
        && merged_trash(canonical, copies)
            .iter()
            .any(|t| t.block_uuid == *block_uuid)
}

/// Whether a block `canonical` lists must be merged: it diverges by its
/// manifests, or live beat the trash and the trashed version holds content
/// the canonical one does not. A block the trash removes is never merged: it
/// leaves `blocks`, so none of its versions is read.
#[must_use]
pub(crate) fn listed_block_needs_merge(
    canonical_entry: &BlockEntry,
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    trashed: &BTreeMap<[u8; 16], BlockEnvelope>,
    collisions: &BTreeMap<[u8; 16], TrashCollision>,
) -> bool {
    if trash_removes(&canonical_entry.block_uuid, canonical, copies, collisions) {
        return false;
    }
    match collisions.get(&canonical_entry.block_uuid) {
        Some(TrashCollision::LiveWins) => {
            listed_block_diverges(canonical_entry, copies)
                || merged_trash(canonical, copies)
                    .iter()
                    .find(|t| t.block_uuid == canonical_entry.block_uuid)
                    .and_then(|t| trashed_clock(t, trashed))
                    .is_some_and(|c| {
                        copy_version_is_uncovered(&canonical_entry.vector_clock_summary, &c)
                    })
        }
        _ => listed_block_diverges(canonical_entry, copies),
    }
}

/// The trashed version to fold into `block_uuid` when live beat the trash,
/// with its signed header clock: absent when live did not win, the entry
/// names no version, or the version is the canonical envelope itself. It
/// may also be one of `divergence`'s copy envelopes (a concurrent restore
/// left it beside the block); the caller pairs that one with this clock,
/// since no counted manifest need list it.
#[must_use]
pub(crate) fn trashed_fold_input<'a>(
    block_uuid: &[u8; 16],
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    trashed: &'a BTreeMap<[u8; 16], BlockEnvelope>,
    collisions: &BTreeMap<[u8; 16], TrashCollision>,
    divergence: &BlockDivergence,
) -> Option<(&'a BlockEnvelope, Vec<VectorClockEntry>)> {
    if collisions.get(block_uuid) != Some(&TrashCollision::LiveWins) {
        return None;
    }
    let entry = merged_trash(canonical, copies)
        .into_iter()
        .find(|t| t.block_uuid == *block_uuid)?;
    let clock = trashed_clock(&entry, trashed)?;
    let envelope = trashed.get(block_uuid)?;
    (divergence.canonical_envelope.bytes != envelope.bytes).then_some((envelope, clock))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::prepare::parent_block_clock_tests::{block_entry, empty_manifest, snapshot};

    const BLOCK: [u8; 16] = [0xAA; 16];
    const TRASHED_FP: [u8; 32] = [0x11; 32];

    fn vc(counter: u64) -> Vec<VectorClockEntry> {
        vec![VectorClockEntry {
            device_uuid: [0x01; 16],
            counter,
        }]
    }

    fn trash_entry(purged_at_ms: Option<u64>) -> TrashEntry {
        TrashEntry {
            block_uuid: BLOCK,
            tombstoned_at_ms: 5,
            tombstoned_by: [0x01; 16],
            fingerprint: Some(TRASHED_FP),
            purged_at_ms,
            unknown: BTreeMap::new(),
        }
    }

    /// A manifest whose clock names `device` alone: concurrent with every
    /// other such manifest, so none is superseded.
    fn manifest_of(device: u8) -> Manifest {
        let mut m = empty_manifest();
        m.vector_clock = vec![VectorClockEntry {
            device_uuid: [device; 16],
            counter: 1,
        }];
        m
    }

    /// Canonical lists `BLOCK` at `fp`; one copy trashed it.
    fn pair(fp: [u8; 32], purged_at_ms: Option<u64>) -> (Manifest, Vec<ManifestSnapshot>) {
        let mut canonical = manifest_of(0x0B);
        canonical.blocks.push(block_entry(BLOCK, fp, vc(1)));
        let mut copy = manifest_of(0x0C);
        copy.trash.push(trash_entry(purged_at_ms));
        (canonical, vec![snapshot(copy)])
    }

    /// A manifest another one's clock dominates is not counted, the canonical
    /// one included; of two equal clocks the first is kept.
    #[test]
    fn superseded_manifests_are_not_counted() {
        let older = manifest_of(0x0B);
        let mut newer = manifest_of(0x0B);
        newer.vector_clock[0].counter = 2;
        let other = manifest_of(0x0C);
        let ids = |ms: Vec<&Manifest>| {
            ms.iter()
                .map(|m| m.vector_clock.clone())
                .collect::<Vec<_>>()
        };
        let copies = [
            snapshot(newer.clone()),
            snapshot(other.clone()),
            snapshot(other.clone()),
        ];
        assert_eq!(
            ids(counted_manifests(&older, &copies)),
            vec![newer.vector_clock.clone(), other.vector_clock.clone()],
            "dominated canonical and the second equal copy dropped"
        );
        assert_eq!(
            ids(counted_manifests(&newer, &[snapshot(older)])),
            vec![newer.vector_clock],
            "a dominated copy dropped"
        );
    }

    /// The outcome is the same with either manifest canonical.
    #[test]
    fn a_collision_is_found_whichever_side_is_canonical() {
        let (listing, trashing) = pair(TRASHED_FP, None);
        let swapped = (
            trashing[0].manifest.clone(),
            vec![snapshot(listing.clone())],
        );
        let none = BTreeMap::new();
        let want = [(BLOCK, TrashCollision::TrashWins)].into_iter().collect();
        assert_eq!(collisions(&listing, &trashing, &none), want);
        assert_eq!(collisions(&swapped.0, &swapped.1, &none), want);
    }

    #[test]
    fn a_trash_entry_nobody_lists_live_is_no_collision() {
        let mut copy = manifest_of(0x0C);
        copy.trash.push(trash_entry(None));
        let canonical = manifest_of(0x0B);
        assert!(collisions(&canonical, &[snapshot(copy)], &BTreeMap::new()).is_empty());
    }

    /// A version other than the trashed one needs the trashed file.
    #[test]
    fn a_differing_live_version_without_the_file_is_undecided() {
        let (canonical, copies) = pair([0x22; 32], None);
        assert_eq!(
            collisions(&canonical, &copies, &BTreeMap::new()).get(&BLOCK),
            Some(&TrashCollision::TrashedVersionUnavailable)
        );
    }

    /// An envelope whose bytes are not the recorded version is ignored.
    #[test]
    fn an_envelope_of_another_version_does_not_decide_it() {
        let (canonical, copies) = pair([0x22; 32], None);
        let wrong = BlockEnvelope {
            bytes: b"not the trashed file".to_vec(),
            source_path: std::path::PathBuf::from("/dev/null"),
        };
        let trashed = [(BLOCK, wrong)].into_iter().collect();
        assert_eq!(
            collisions(&canonical, &copies, &trashed).get(&BLOCK),
            Some(&TrashCollision::TrashedVersionUnavailable)
        );
    }

    /// The trash beats the listed block: kept in the trash, never merged.
    #[test]
    fn a_block_the_trash_beats_keeps_its_entry_and_is_not_merged() {
        let (canonical, copies) = pair(TRASHED_FP, None);
        // A copy version the canonical one does not cover would otherwise
        // make the block diverge.
        let mut newer = manifest_of(0x0D);
        newer.blocks.push(block_entry(BLOCK, TRASHED_FP, vc(2)));
        let copies = [copies, vec![snapshot(newer)]].concat();
        let outcomes = collisions(&canonical, &copies, &BTreeMap::new());
        assert_eq!(resolved_trash(&canonical, &copies, &outcomes).len(), 1);
        assert!(!listed_block_needs_merge(
            &canonical.blocks[0],
            &canonical,
            &copies,
            &BTreeMap::new(),
            &outcomes
        ));
    }

    #[test]
    fn a_block_live_beat_the_trash_for_loses_its_entry() {
        let (canonical, copies) = pair(TRASHED_FP, None);
        let outcomes = [(BLOCK, TrashCollision::LiveWins)].into_iter().collect();
        assert!(resolved_trash(&canonical, &copies, &outcomes).is_empty());
    }

    #[test]
    fn a_purged_entry_beats_any_live_version_without_its_file() {
        let (canonical, copies) = pair([0x22; 32], Some(9));
        assert_eq!(
            collisions(&canonical, &copies, &BTreeMap::new()).get(&BLOCK),
            Some(&TrashCollision::TrashWins)
        );
    }
}
