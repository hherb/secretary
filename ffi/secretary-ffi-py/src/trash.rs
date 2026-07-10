//! Block-trash entry point (B.5).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Move a live block into trash. See
/// `docs/vault-format.md` §7 for the normative sequence.
///
/// `block_uuid` and `device_uuid` must each be exactly 16 bytes;
/// otherwise raises `ValueError` (mirrors `save_block`, `share_block`,
/// and `read_block`).
///
/// On failure, the bridge handle is byte-identical to its pre-call
/// state; the on-disk state may have a partial rename (manifest
/// updated to list the block as trashed, but file still in `blocks/`)
/// due to the manifest-write-first semantics of #350 — harmless because
/// `open_vault` reads only listed entries and ignores orphans.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
pub(crate) fn trash_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::trash_block(&identity.0, &manifest.0, block_uuid, device_uuid, now_ms)
        .map_err(ffi_vault_error_to_pyerr)
}

/// One trashed block, projected by name for a Trash view. Output-only;
/// never constructed from Python. Carries only the block name (already
/// plaintext in manifest summaries) + tombstone metadata — no record
/// material (the bridge decrypts-then-zeroizes internally).
#[pyclass(frozen, get_all)]
pub struct TrashedBlock {
    /// 16-byte UUID of the trashed block.
    pub block_uuid: Vec<u8>,
    /// Human-readable block name, recovered from the newest trashed file.
    pub block_name: String,
    /// Unix-millis the block was moved to trash.
    pub tombstoned_at_ms: u64,
    /// 16-byte UUID of the device that trashed the block.
    pub tombstoned_by: Vec<u8>,
}

impl From<secretary_ffi_bridge::TrashedBlock> for TrashedBlock {
    fn from(b: secretary_ffi_bridge::TrashedBlock) -> Self {
        Self {
            block_uuid: b.block_uuid.to_vec(),
            block_name: b.block_name,
            tombstoned_at_ms: b.tombstoned_at_ms,
            tombstoned_by: b.tombstoned_by.to_vec(),
        }
    }
}

/// List every not-yet-purged trashed block, projected by name (#402
/// follow-up). Raises `CorruptVault` (wiped handle / missing not-yet-purged
/// file / decrypt failure) or `FolderInvalid` (unreadable file).
#[pyfunction]
pub(crate) fn list_trashed_blocks(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> PyResult<Vec<TrashedBlock>> {
    secretary_ffi_bridge::list_trashed_blocks(&identity.0, &manifest.0)
        .map(|v| v.into_iter().map(TrashedBlock::from).collect())
        .map_err(ffi_vault_error_to_pyerr)
}
