//! #788: the blocks a counted, authenticated conflict-copy manifest has
//! trashed.
//!
//! A device that trashes a block moves its file to `trash/`. A device that
//! has not seen that trash can write the canonical manifest meanwhile, which
//! still lists the block, so the listed file is missing until a merge
//! commits. `verify_vault_state` on open and refresh (vault-format §4.3,
//! "Block files at open") excuses exactly those missing files, so a client
//! that opens before it syncs can reach the merge that decides the block
//! (crypto-design §11.6). The merge commit does not use this excuse.

use std::collections::BTreeSet;
use std::path::Path;

use crate::crypto::sig::MlDsa65Public;
use crate::identity::card::ContactCard;
use crate::identity::fingerprint::fingerprint;
use crate::sync::bundle::ManifestSnapshot;
use crate::sync::ingest::ingest_manifest_copies;
use crate::sync::trash_collision::merged_trash;
use crate::unlock::UnlockedIdentity;
use crate::vault::manifest::Manifest;

/// The uuids with a trash entry in the manifests a merge counts (the
/// canonical one and every copy no other manifest supersedes, crypto-design
/// §11.7), whatever the entry's fingerprint: an edit made just before the
/// trash leaves the canonical listing an older fingerprint than the entry's.
/// A superseded copy's entry is not counted, since a later restore may have
/// brought the block back, and no merge would ever trash it again.
pub(crate) fn blocks_trashed_in(
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
) -> BTreeSet<[u8; 16]> {
    merged_trash(canonical, copies)
        .into_iter()
        .map(|t| t.block_uuid)
        .collect()
}

/// The blocks trashed by the counted conflict-copy manifests in `folder`
/// that `ingest_manifest_copies` authenticates under the vault's owner.
/// Best-effort: any failure (the owner card cannot be encoded or its
/// ML-DSA key parsed, or the folder cannot be listed) yields the empty
/// set, so a missing file is refused as before.
pub(crate) fn blocks_trashed_by_conflict_copies(
    folder: &Path,
    canonical: &Manifest,
    owner_card: &ContactCard,
    identity: &UnlockedIdentity,
) -> BTreeSet<[u8; 16]> {
    let card_bytes = match owner_card.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::debug!(error = %err, "#788 excuse skipped: owner card encode failed");
            return BTreeSet::new();
        }
    };
    let owner_pq_pk = match MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk) {
        Ok(pk) => pk,
        Err(err) => {
            tracing::debug!(error = %err, "#788 excuse skipped: owner ML-DSA key invalid");
            return BTreeSet::new();
        }
    };
    match ingest_manifest_copies(
        folder,
        canonical.vault_uuid,
        fingerprint(&card_bytes),
        &owner_card.ed25519_pk,
        &owner_pq_pk,
        &identity.identity_block_key,
    ) {
        Ok(copies) => blocks_trashed_in(canonical, &copies),
        Err(err) => {
            tracing::debug!(error = %err, "#788 excuse skipped: folder scan failed");
            BTreeSet::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::manifest::{KdfParamsRef, TrashEntry};
    use crate::vault::VectorClockEntry;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn trash_entry(block_uuid: [u8; 16], fingerprint: Option<[u8; 32]>) -> TrashEntry {
        TrashEntry {
            block_uuid,
            tombstoned_at_ms: 1,
            tombstoned_by: [0; 16],
            fingerprint,
            purged_at_ms: None,
            unknown: BTreeMap::new(),
        }
    }

    /// A manifest with `clock` (device byte, counter) pairs and `trash`.
    fn manifest(clock: &[(u8, u64)], trash: Vec<TrashEntry>) -> Manifest {
        Manifest {
            manifest_version: 1,
            vault_uuid: [0x01; 16],
            format_version: crate::version::FORMAT_VERSION,
            suite_id: crate::version::SUITE_ID,
            owner_user_uuid: [0x02; 16],
            vector_clock: clock
                .iter()
                .map(|&(d, counter)| VectorClockEntry {
                    device_uuid: [d; 16],
                    counter,
                })
                .collect(),
            blocks: Vec::new(),
            trash,
            kdf_params: KdfParamsRef {
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 1,
                salt: [0x03; 32],
            },
            unknown: BTreeMap::new(),
        }
    }

    fn copy(m: Manifest) -> ManifestSnapshot {
        ManifestSnapshot {
            manifest: m,
            raw_envelope_bytes: Vec::new(),
            source_path: PathBuf::new(),
        }
    }

    #[test]
    fn collects_every_concurrent_copys_trash_entries_whatever_their_fingerprint() {
        let canonical = manifest(&[(0xB, 1)], Vec::new());
        let copies = [
            copy(manifest(
                &[(0xA, 1)],
                vec![trash_entry([1; 16], Some([9; 32]))],
            )),
            copy(manifest(&[(0xC, 1)], vec![trash_entry([2; 16], None)])),
        ];
        let got = blocks_trashed_in(&canonical, &copies);
        assert_eq!(got, BTreeSet::from([[1; 16], [2; 16]]));
    }

    /// crypto-design §11.7: a copy the canonical manifest dominates (a later
    /// restore saw its trash) is not counted.
    #[test]
    fn a_superseded_copys_trash_entry_is_not_counted() {
        let canonical = manifest(&[(0xA, 2), (0xB, 1)], Vec::new());
        let copies = [copy(manifest(
            &[(0xA, 1)],
            vec![trash_entry([1; 16], None)],
        ))];
        assert!(blocks_trashed_in(&canonical, &copies).is_empty());
    }

    #[test]
    fn no_copies_trash_nothing() {
        let canonical = manifest(&[(0xB, 1)], Vec::new());
        assert!(blocks_trashed_in(&canonical, &[]).is_empty());
    }
}
