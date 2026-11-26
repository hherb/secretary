//! The trashed file a live-vs-trash collision needs (crypto-design §11.6).
//!
//! When a folded manifest lists a block live at a version other than the one
//! the merged trash entry records, deciding the collision needs the trashed
//! file's signed header clock, and a live win folds its content. That file is
//! normally `trash/<uuid>.cbor.enc.<tombstoned_at_ms>`; a concurrent restore
//! moves it back to `blocks/`, so the block's own path and its conflict
//! copies are searched too.

use std::collections::BTreeMap;
use std::path::Path;

use super::block_files::{canonical_block_path, read_block_envelope};
use super::enumerate_block_siblings;
use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::sig::{Ed25519Public, MlDsa65Public};
use crate::identity::fingerprint::Fingerprint;
use crate::sync::bundle::{BlockEnvelope, ManifestSnapshot};
use crate::sync::trash_collision::{live_versions, merged_trash};
use crate::vault::orchestrators::{format_uuid_hyphenated, BLOCK_FILE_EXTENSION, TRASH_SUBDIR};
use crate::vault::{needs_trashed_clock, Manifest};

/// The authenticated trashed file of every collision that needs one, keyed
/// by `block_uuid`: the first candidate whose BLAKE3-256 fingerprint is the
/// one the merged trash entry records. A collision whose file is missing,
/// out of size bounds or fails authentication is absent, and `prepare_merge`
/// refuses the merge until it arrives. Folder-level I/O errors propagate.
pub(super) fn ingest_trashed_envelopes(
    folder: &Path,
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
) -> Result<BTreeMap<[u8; 16], BlockEnvelope>, std::io::Error> {
    let mut out = BTreeMap::new();
    for entry in merged_trash(canonical, copies) {
        let live = live_versions(&entry.block_uuid, canonical, copies);
        let Some(fp) = entry.fingerprint else {
            continue;
        };
        if !needs_trashed_clock(&entry, &live) {
            continue;
        }
        let trash_path = folder.join(TRASH_SUBDIR).join(format!(
            "{}{BLOCK_FILE_EXTENSION}.{}",
            format_uuid_hyphenated(&entry.block_uuid),
            entry.tombstoned_at_ms
        ));
        let candidates = [trash_path, canonical_block_path(folder, &entry.block_uuid)]
            .into_iter()
            .chain(enumerate_block_siblings(folder, &entry.block_uuid)?);
        let found = candidates
            .filter_map(|path| {
                read_block_envelope(
                    path,
                    canonical_owner_fp,
                    owner_ed25519_pk,
                    owner_ml_dsa_65_pk,
                )
            })
            .find(|env| *blake3_hash(&env.bytes).as_bytes() == fp);
        if let Some(envelope) = found {
            out.insert(entry.block_uuid, envelope);
        }
    }
    Ok(out)
}
