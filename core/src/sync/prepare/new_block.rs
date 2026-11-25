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
/// the block. The commit rewrites its `fingerprint`, `block_name`,
/// `vector_clock_summary` and `last_mod_ms`; `created_at_ms`, which every
/// version shares, `recipients`, `suite_id` and `unknown` are kept from that
/// first entry.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::prepare::parent_block_clock_tests::{block_entry, empty_manifest, snapshot};

    /// The golden vault's one block, named in its own header.
    const GOLDEN_BLOCK: &str = "11223344-5566-7788-99aa-bbccddeeff00.cbor.enc";

    /// A hostile host can copy another owner-signed block's file to this
    /// block's path; the header names the block, so the seed refuses it.
    #[test]
    fn a_file_naming_another_block_is_refused() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/golden_vault_001/blocks")
            .join(GOLDEN_BLOCK);
        let bytes = std::fs::read(path).expect("read golden block");
        let other = [0x77; 16];
        // A copy lists `other`, so only the header check can refuse.
        let mut listing = empty_manifest();
        listing.blocks.push(block_entry(other, [0; 32], vec![]));
        assert!(matches!(
            new_block_seed(&other, &bytes, &[snapshot(listing)]),
            Err(SyncError::InvalidArgument { .. })
        ));
    }
}
