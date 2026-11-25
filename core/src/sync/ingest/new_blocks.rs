//! Blocks new to the merging device (crypto-design §11.7, #781).
//!
//! A block that a conflict copy lists, and the canonical manifest lists in
//! neither `blocks` nor `trash`, was created on a device this one has not
//! merged with yet. The merged manifest's clock covers that copy, so dropping
//! the block would lose it for good. It is ingested as a diverging block whose
//! own file stands in for the local side.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::block_files::{canonical_block_path, read_block_envelope, read_sibling_envelopes};
use crate::crypto::sig::{Ed25519Public, MlDsa65Public};
use crate::identity::fingerprint::Fingerprint;
use crate::sync::bundle::{BlockDivergence, ManifestSnapshot};
use crate::vault::Manifest;

/// Every block a copy manifest lists that `canonical` lists in neither
/// `blocks` nor `trash`, ascending. A block `canonical` has trashed is
/// reconciled by the trash merge (§11.6), not here. So is a copy's version
/// whose fingerprint a trash entry in any copy records: that exact file was
/// trashed, and its own path no longer holds it, so requiring it would refuse
/// every retry.
#[must_use]
pub(crate) fn blocks_new_to_canonical(
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
) -> BTreeSet<[u8; 16]> {
    let known: BTreeSet<[u8; 16]> = canonical
        .blocks
        .iter()
        .map(|b| b.block_uuid)
        .chain(canonical.trash.iter().map(|t| t.block_uuid))
        .collect();
    let trashed: BTreeSet<([u8; 16], [u8; 32])> = copies
        .iter()
        .flat_map(|c| c.manifest.trash.iter())
        .filter_map(|t| t.fingerprint.map(|fp| (t.block_uuid, fp)))
        .collect();
    copies
        .iter()
        .flat_map(|c| c.manifest.blocks.iter())
        .filter(|b| !known.contains(&b.block_uuid))
        .filter(|b| !trashed.contains(&(b.block_uuid, b.fingerprint)))
        .map(|b| b.block_uuid)
        .collect()
}

/// Add a [`BlockDivergence`] to `out` for each block new to `canonical`: the
/// authenticated file at its own path is the canonical envelope, its
/// authenticated siblings the copies. A block whose own file is unreadable
/// or fails authentication is left out, and `prepare_merge` then refuses the
/// merge until it arrives. Folder-level I/O errors propagate.
pub(super) fn ingest_new_blocks(
    folder: &Path,
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
    out: &mut BTreeMap<[u8; 16], BlockDivergence>,
) -> Result<(), std::io::Error> {
    for block_uuid in blocks_new_to_canonical(canonical, copies) {
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

    #[test]
    fn a_block_only_a_copy_lists_is_new() {
        let copies = [snap(manifest(vec![live(FP)], vec![]))];
        let got = blocks_new_to_canonical(&manifest(vec![], vec![]), &copies);
        assert_eq!(got.into_iter().collect::<Vec<_>>(), vec![BLOCK]);
    }

    /// §11.6 reconciles a block the canonical manifest has trashed.
    #[test]
    fn a_block_the_canonical_manifest_trashed_is_not_new() {
        let copies = [snap(manifest(vec![live(FP)], vec![]))];
        let canonical = manifest(vec![], vec![trashed(Some(FP))]);
        assert!(blocks_new_to_canonical(&canonical, &copies).is_empty());
    }

    /// Another copy trashed exactly that file, so its path no longer holds
    /// it: requiring it would refuse every retry.
    #[test]
    fn a_version_another_copy_trashed_is_not_new() {
        let copies = [
            snap(manifest(vec![live(FP)], vec![])),
            snap(manifest(vec![], vec![trashed(Some(FP))])),
        ];
        assert!(blocks_new_to_canonical(&manifest(vec![], vec![]), &copies).is_empty());
    }

    /// A trash entry for another version, or one recording no fingerprint,
    /// does not account for this version.
    #[test]
    fn a_version_no_trash_entry_records_is_new() {
        for t in [trashed(Some([0x22; 32])), trashed(None)] {
            let copies = [
                snap(manifest(vec![live(FP)], vec![])),
                snap(manifest(vec![], vec![t])),
            ];
            assert_eq!(
                blocks_new_to_canonical(&manifest(vec![], vec![]), &copies).len(),
                1
            );
        }
    }
}
