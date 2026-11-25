//! Blocks new to the merging device (crypto-design §11.7, #781).
//!
//! A block that a conflict copy lists, and the canonical manifest does not,
//! was created on a device this one has not merged with yet, or is one the
//! canonical manifest trashed while a copy edited it (§11.6, live wins). The merged manifest's clock covers that copy, so dropping
//! the block would lose it for good. It is ingested as a diverging block whose
//! own file stands in for the local side.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::block_files::{canonical_block_path, read_block_envelope, read_sibling_envelopes};
use crate::crypto::sig::{Ed25519Public, MlDsa65Public};
use crate::identity::fingerprint::Fingerprint;
use crate::sync::bundle::{BlockDivergence, ManifestSnapshot};
use crate::vault::{Manifest, TrashCollision};

/// Every block a copy manifest lists that `canonical` does not, ascending,
/// unless it is in the merged trash and live did not win there (`collisions`,
/// crypto-design §11.6). A block the trash beats leaves `blocks`; one whose
/// collision cannot be decided yet is refused by `prepare_merge` instead.
#[must_use]
pub(crate) fn blocks_new_to_canonical(
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    collisions: &BTreeMap<[u8; 16], TrashCollision>,
) -> BTreeSet<[u8; 16]> {
    let known: BTreeSet<[u8; 16]> = canonical.blocks.iter().map(|b| b.block_uuid).collect();
    copies
        .iter()
        .flat_map(|c| c.manifest.blocks.iter())
        .map(|b| b.block_uuid)
        .filter(|uuid| !known.contains(uuid))
        .filter(|uuid| matches!(collisions.get(uuid), None | Some(TrashCollision::LiveWins)))
        .collect()
}

/// Add a [`BlockDivergence`] to `out` for each of `new_blocks` (see
/// [`blocks_new_to_canonical`]): the authenticated file at its own path is
/// the canonical envelope, its authenticated siblings the copies. A block
/// whose own file is unreadable or fails authentication is left out, and
/// `prepare_merge` then refuses the merge until it arrives. Folder-level I/O
/// errors propagate.
pub(super) fn ingest_new_blocks(
    folder: &Path,
    new_blocks: BTreeSet<[u8; 16]>,
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
    out: &mut BTreeMap<[u8; 16], BlockDivergence>,
) -> Result<(), std::io::Error> {
    for block_uuid in new_blocks {
        let Some(canonical_envelope) = read_block_envelope(
            canonical_block_path(folder, &block_uuid),
            canonical_owner_fp,
            owner_ed25519_pk,
            owner_ml_dsa_65_pk,
        ) else {
            continue;
        };
        let copy_envelopes = read_sibling_envelopes(
            folder,
            &block_uuid,
            canonical_owner_fp,
            owner_ed25519_pk,
            owner_ml_dsa_65_pk,
        )?;
        out.insert(
            block_uuid,
            BlockDivergence {
                canonical_envelope,
                copy_envelopes,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::manifest::TrashEntry;
    use crate::vault::{BlockEntry, KdfParamsRef};
    use std::path::PathBuf;

    const BLOCK: [u8; 16] = [0xAA; 16];
    const FP: [u8; 32] = [0x11; 32];

    fn manifest(blocks: Vec<BlockEntry>, trash: Vec<TrashEntry>) -> Manifest {
        Manifest {
            manifest_version: 1,
            vault_uuid: [0; 16],
            format_version: 1,
            suite_id: 1,
            owner_user_uuid: [0; 16],
            vector_clock: vec![],
            blocks,
            trash,
            kdf_params: KdfParamsRef {
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 1,
                salt: [0; 32],
            },
            unknown: BTreeMap::new(),
        }
    }

    fn live(fingerprint: [u8; 32]) -> BlockEntry {
        BlockEntry {
            block_uuid: BLOCK,
            block_name: String::new(),
            fingerprint,
            recipients: vec![],
            vector_clock_summary: vec![],
            suite_id: 1,
            created_at_ms: 0,
            last_mod_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    fn trashed(fingerprint: Option<[u8; 32]>) -> TrashEntry {
        TrashEntry {
            block_uuid: BLOCK,
            tombstoned_at_ms: 1,
            tombstoned_by: [0; 16],
            fingerprint,
            purged_at_ms: None,
            unknown: BTreeMap::new(),
        }
    }

    fn snap(m: Manifest) -> ManifestSnapshot {
        ManifestSnapshot {
            manifest: m,
            raw_envelope_bytes: vec![],
            source_path: PathBuf::from("/dev/null"),
        }
    }

    fn new(canonical: &Manifest, copies: &[ManifestSnapshot]) -> Vec<[u8; 16]> {
        let collisions =
            crate::sync::trash_collision::collisions(canonical, copies, &BTreeMap::new());
        blocks_new_to_canonical(canonical, copies, &collisions)
            .into_iter()
            .collect()
    }

    #[test]
    fn a_block_only_a_copy_lists_is_new() {
        let copies = [snap(manifest(vec![live(FP)], vec![]))];
        assert_eq!(new(&manifest(vec![], vec![]), &copies), vec![BLOCK]);
    }

    /// The canonical manifest trashed exactly the version the copy lists, so
    /// the trash wins (§11.6).
    #[test]
    fn a_block_the_canonical_manifest_trashed_is_not_new() {
        let copies = [snap(manifest(vec![live(FP)], vec![]))];
        let canonical = manifest(vec![], vec![trashed(Some(FP))]);
        assert!(new(&canonical, &copies).is_empty());
    }

    /// Another copy trashed exactly that version: the trash wins.
    #[test]
    fn a_version_another_copy_trashed_is_not_new() {
        let copies = [
            snap(manifest(vec![live(FP)], vec![])),
            snap(manifest(vec![], vec![trashed(Some(FP))])),
        ];
        assert!(new(&manifest(vec![], vec![]), &copies).is_empty());
    }

    /// A legacy entry recording no fingerprint loses to the live copy, so the
    /// block is carried.
    #[test]
    fn a_block_a_legacy_entry_trashed_is_new() {
        let copies = [
            snap(manifest(vec![live(FP)], vec![])),
            snap(manifest(vec![], vec![trashed(None)])),
        ];
        assert_eq!(new(&manifest(vec![], vec![]), &copies), vec![BLOCK]);
    }

    /// A trash entry for another version needs the trashed file to decide;
    /// without it the block is not carried (`prepare_merge` refuses).
    #[test]
    fn a_block_whose_collision_is_undecided_is_not_new() {
        let copies = [
            snap(manifest(vec![live(FP)], vec![])),
            snap(manifest(vec![], vec![trashed(Some([0x22; 32]))])),
        ];
        assert!(new(&manifest(vec![], vec![]), &copies).is_empty());
    }

    /// Live beat the trash: carried, even though the canonical manifest
    /// trashed it.
    #[test]
    fn a_block_live_won_for_is_new() {
        let copies = [snap(manifest(vec![live(FP)], vec![]))];
        let canonical = manifest(vec![], vec![trashed(Some([0x22; 32]))]);
        let collisions = [(BLOCK, TrashCollision::LiveWins)].into_iter().collect();
        assert_eq!(
            blocks_new_to_canonical(&canonical, &copies, &collisions).len(),
            1
        );
    }
}
