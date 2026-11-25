//! Reading a block's own file and its conflict copies off disk, each
//! authenticated against the owner identity before it reaches a merge.

use std::path::{Path, PathBuf};

use super::{authenticate_block_envelope, enumerate_block_siblings, MAX_BLOCK_FILE_SIZE};
use crate::crypto::sig::{Ed25519Public, MlDsa65Public};
use crate::identity::fingerprint::Fingerprint;
use crate::sync::bundle::BlockEnvelope;

/// `blocks/<uuid>.cbor.enc` under `folder`: the block's own file, beside which
/// a sync tool leaves its conflict copies.
pub(super) fn canonical_block_path(folder: &Path, block_uuid: &[u8; 16]) -> PathBuf {
    folder
        .join(crate::vault::orchestrators::BLOCKS_SUBDIR)
        .join(
            crate::vault::orchestrators::format_uuid_hyphenated(block_uuid)
                + crate::vault::orchestrators::BLOCK_FILE_EXTENSION,
        )
}

/// Every authenticated sibling of `block_uuid`'s block file, in path order
/// (see [`read_block_envelope`]). Folder-level I/O errors propagate.
pub(super) fn read_sibling_envelopes(
    folder: &Path,
    block_uuid: &[u8; 16],
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
) -> Result<Vec<BlockEnvelope>, std::io::Error> {
    Ok(enumerate_block_siblings(folder, block_uuid)?
        .into_iter()
        .filter_map(|path| {
            read_block_envelope(
                path,
                canonical_owner_fp,
                owner_ed25519_pk,
                owner_ml_dsa_65_pk,
            )
        })
        .collect())
}

/// Read one candidate block file and authenticate it against the owner
/// identity. `None`, logged at debug level, when it is unreadable, empty or
/// over [`MAX_BLOCK_FILE_SIZE`], or fails authentication (spec §1a-D3).
pub(super) fn read_block_envelope(
    path: PathBuf,
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
) -> Option<BlockEnvelope> {
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(err) => {
            tracing::debug!(
                path = %path.display(),
                error = %err,
                "block file skipped: read error"
            );
            return None;
        }
    };
    if bytes.is_empty() || bytes.len() > MAX_BLOCK_FILE_SIZE {
        tracing::debug!(
            path = %path.display(),
            size = bytes.len(),
            "block file skipped: size out of bounds"
        );
        return None;
    }
    authenticate_block_envelope(
        &bytes,
        path,
        canonical_owner_fp,
        owner_ed25519_pk,
        owner_ml_dsa_65_pk,
    )
}
