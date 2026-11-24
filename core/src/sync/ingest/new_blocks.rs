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
/// reconciled by the trash merge (§11.6), not here.
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
    copies
        .iter()
        .flat_map(|c| c.manifest.blocks.iter().map(|b| b.block_uuid))
        .filter(|uuid| !known.contains(uuid))
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
