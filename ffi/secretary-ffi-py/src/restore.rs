//! Block-restore entry point (B.5).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Restore the most recent trashed copy of a block, purging older
/// copies best-effort. See `docs/vault-format.md` §7.1 for the
/// normative sequence.
///
/// `block_uuid` and `device_uuid` must each be exactly 16 bytes;
/// otherwise raises `ValueError`.
///
/// Failure modes:
///
/// - `VaultBlockUuidAlreadyLive` — the UUID is currently live; caller
///   must trash the live copy before restoring.
/// - `VaultBlockNotInTrash` — no matching file in
///   `trash/<uuid>.cbor.enc.*` and no matching `TrashEntry`.
/// - `VaultCorruptVault` — the trashed file failed §6.1 hybrid-
///   signature verification (folded from `RestoreVerificationFailed`).
/// - `VaultMissingRecipientCard` — a wrap recipient cannot be
///   resolved to a `contact_uuid` via the contacts/-scan; the trash
///   file and manifest are untouched.
/// - `VaultFolderInvalid` — I/O failure during the rename or manifest
///   atomic-write.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
pub(crate) fn restore_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::restore_block(&identity.0, &manifest.0, block_uuid, device_uuid, now_ms)
        .map_err(ffi_vault_error_to_pyerr)
}
