//! The local side of a block new to the merging device (crypto-design §11.7).

use crate::sync::bundle::ManifestSnapshot;
use crate::sync::error::SyncError;
use crate::vault::block::{decode_block_file, VectorClockEntry};
use crate::vault::BlockEntry;

/// The clock and manifest entry a block new to the canonical manifest starts
/// its fold from. Its own file (`envelope_bytes`, already authenticated at
/// ingest) stands in for the local side.
///
/// The clock is the file's own owner-signed header clock, not a manifest
/// pairing: the file can hold a version no manifest names yet, because its
/// device edited it again and the file landed first, or because a merge
/// commit wrote it and stopped before the manifest. Pairing by fingerprint
/// would then refuse every retry. The entry is the first copy entry listing
/// the block; the commit overwrites every field that differs between its
/// versions except `created_at_ms`, which they share.
///
/// # Errors
///
/// `SyncError::Vault` if the envelope does not decode, and
/// `SyncError::InvalidArgument` if its header names another block or no copy
/// lists the block (a bundle/plan disagreement).
pub(super) fn new_block_seed(
    block_uuid: &[u8; 16],
    envelope_bytes: &[u8],
    copies: &[ManifestSnapshot],
) -> Result<(Vec<VectorClockEntry>, BlockEntry), SyncError> {
    let header = decode_block_file(envelope_bytes)
        .map_err(|e| SyncError::Vault(crate::vault::VaultError::from(e)))?
        .header;
    if header.block_uuid != *block_uuid {
        return Err(SyncError::InvalidArgument {
            detail: format!(
                "block file for {block_uuid:02x?} names block {:02x?}",
                header.block_uuid
            ),
        });
    }
    let entry = copies
        .iter()
        .flat_map(|c| c.manifest.blocks.iter())
        .find(|e| e.block_uuid == *block_uuid)
        .ok_or_else(|| SyncError::InvalidArgument {
            detail: format!("no copy manifest lists new block {block_uuid:02x?}"),
        })?;
    Ok((header.vector_clock, entry.clone()))
}
