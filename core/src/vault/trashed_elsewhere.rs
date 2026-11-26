//! #788: the blocks an authenticated conflict-copy manifest has trashed.
//!
//! A device that trashes a block moves its file to `trash/`. A device that
//! has not seen that trash can write the canonical manifest meanwhile, which
//! still lists the block, so the listed file is missing until a merge
//! commits. Open (vault-format §4.3, "Block files at open") excuses
//! exactly those missing files: the next sync's merge decides the block
//! (crypto-design §11.6). Every app opens before it syncs, so refusing here
//! left no way out.

use std::collections::BTreeSet;
use std::path::Path;

use crate::crypto::sig::MlDsa65Public;
use crate::identity::card::ContactCard;
use crate::identity::fingerprint::fingerprint;
use crate::sync::ingest::ingest_manifest_copies;
use crate::unlock::UnlockedIdentity;
use crate::vault::manifest::Manifest;

/// The uuids with a trash entry in any of `copies`, whatever the entry's
/// fingerprint: an edit made just before the trash leaves the canonical
/// listing an older fingerprint than the entry's.
pub(crate) fn blocks_trashed_in<'a>(
    copies: impl IntoIterator<Item = &'a Manifest>,
) -> BTreeSet<[u8; 16]> {
    copies
        .into_iter()
        .flat_map(|m| m.trash.iter().map(|t| t.block_uuid))
        .collect()
}

/// The blocks trashed by a conflict-copy manifest in `folder` that
/// authenticates under the vault's owner (the same five checks the sync
/// ingest applies). Best-effort: a folder scan that fails yields the empty
/// set, so a missing file is refused as before.
pub(crate) fn blocks_trashed_by_conflict_copies(
    folder: &Path,
    canonical: &Manifest,
    owner_card: &ContactCard,
    identity: &UnlockedIdentity,
) -> BTreeSet<[u8; 16]> {
    let Ok(card_bytes) = owner_card.to_canonical_cbor() else {
        return BTreeSet::new();
    };
    let Ok(owner_pq_pk) = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk) else {
        return BTreeSet::new();
    };
    match ingest_manifest_copies(
        folder,
        canonical.vault_uuid,
        fingerprint(&card_bytes),
        &owner_card.ed25519_pk,
        &owner_pq_pk,
        &identity.identity_block_key,
    ) {
        Ok(copies) => blocks_trashed_in(copies.iter().map(|c| &c.manifest)),
        Err(_) => BTreeSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::manifest::{KdfParamsRef, TrashEntry};
    use std::collections::BTreeMap;

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

    fn manifest_trashing(trash: Vec<TrashEntry>) -> Manifest {
        Manifest {
            manifest_version: 1,
            vault_uuid: [0x01; 16],
            format_version: crate::version::FORMAT_VERSION,
            suite_id: crate::version::SUITE_ID,
            owner_user_uuid: [0x02; 16],
            vector_clock: Vec::new(),
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

    #[test]
    fn collects_every_copys_trash_entries_whatever_their_fingerprint() {
        let one = manifest_trashing(vec![trash_entry([1; 16], Some([9; 32]))]);
        let two = manifest_trashing(vec![trash_entry([2; 16], None)]);
        let got = blocks_trashed_in([&one, &two]);
        assert_eq!(got, BTreeSet::from([[1; 16], [2; 16]]));
    }

    #[test]
    fn no_copies_trash_nothing() {
        assert!(blocks_trashed_in(std::iter::empty::<&Manifest>()).is_empty());
    }
}
