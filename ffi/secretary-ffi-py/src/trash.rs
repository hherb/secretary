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
