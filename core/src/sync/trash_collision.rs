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
use crate::vault::{resolve_trash_collision, BlockEntry, Manifest, TrashCollision};

/// The trash lists of the canonical manifest and every copy, reconciled by
/// §11.6's union (before any collision is resolved).
#[must_use]
pub(crate) fn merged_trash(canonical: &Manifest, copies: &[ManifestSnapshot]) -> Vec<TrashEntry> {
    let lists: Vec<&[TrashEntry]> = std::iter::once(canonical.trash.as_slice())
        .chain(copies.iter().map(|c| c.manifest.trash.as_slice()))
        .collect();
    merge_trash_lists(&lists)
}

/// Every folded manifest's entry for `block_uuid` in `blocks`: the canonical
/// one first, then each copy's.
#[must_use]
pub(crate) fn live_versions<'a>(
    block_uuid: &[u8; 16],
    canonical: &'a Manifest,
    copies: &'a [ManifestSnapshot],
) -> Vec<&'a BlockEntry> {
    std::iter::once(canonical)
        .chain(copies.iter().map(|c| &c.manifest))
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

/// Whether a block `canonical` lists must be merged: it diverges by its
/// manifests, or live beat the trash and the trashed version holds content
/// the canonical one does not. A block the trash beats is never merged: it
/// leaves `blocks`, so none of its versions is read.
#[must_use]
pub(crate) fn listed_block_needs_merge(
    canonical_entry: &BlockEntry,
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    trashed: &BTreeMap<[u8; 16], BlockEnvelope>,
    collisions: &BTreeMap<[u8; 16], TrashCollision>,
) -> bool {
    match collisions.get(&canonical_entry.block_uuid) {
        Some(TrashCollision::TrashWins) => false,
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
/// names no version, or the version is already among `divergence`'s
/// envelopes.
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
    let already_read = std::iter::once(&divergence.canonical_envelope)
        .chain(&divergence.copy_envelopes)
        .any(|e| e.bytes == envelope.bytes);
    (!already_read).then_some((envelope, clock))
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

    /// Canonical lists `BLOCK` at `fp`; one copy trashed it.
    fn pair(fp: [u8; 32], purged_at_ms: Option<u64>) -> (Manifest, Vec<ManifestSnapshot>) {
        let mut canonical = empty_manifest();
        canonical.blocks.push(block_entry(BLOCK, fp, vc(1)));
        let mut copy = empty_manifest();
        copy.trash.push(trash_entry(purged_at_ms));
        (canonical, vec![snapshot(copy)])
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
        let mut copy = empty_manifest();
        copy.trash.push(trash_entry(None));
        assert!(collisions(&empty_manifest(), &[snapshot(copy)], &BTreeMap::new()).is_empty());
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
        let mut newer = empty_manifest();
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
