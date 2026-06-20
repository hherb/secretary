//! Block-CRUD entry points (block-CRUD slice): `create_block`,
//! `rename_block`, `move_record`.
//!
//! Three thin wrappers over `secretary_ffi_bridge::{create_block,
//! rename_block, move_record}`, mirroring the uniffi projection
//! (`secretary-ffi-uniffi/src/namespace/block_crud.rs`). Each
//! length-validates its uuid arguments (16 bytes each → otherwise
//! `ValueError`, via `uuid_array_or_value_error`). `move_record`
//! additionally enforces `source_block_uuid != target_block_uuid` here —
//! the bridge trusts its caller on that precondition (per `move_record.rs`'s
//! doc comment), so the wrapper raises `ValueError` for a same-block move.
//!
//! The error surface reuses the already-registered typed exceptions
//! (`VaultBlockNotFound` / `VaultRecordNotFound` / `VaultCorruptVault` /
//! the save-tail classes) — no new exception class is introduced.

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Create a new, empty block in an open vault. `block_uuid` / `device_uuid`
/// must each be 16 bytes (else `ValueError`). The caller is expected to
/// supply a fresh CSPRNG-minted UUID; uniqueness is not enforced at the
/// bridge level (a 2⁻¹²⁸ collision would update the colliding block in place
/// rather than error). Empty `block_name` is allowed. Raises
/// `VaultCorruptVault` on a wiped handle; `VaultFolderInvalid` on an IO
/// failure during the atomic write; `VaultSaveCryptoFailure` on a
/// crypto/encoding failure.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn create_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    block_name: String,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::create_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        block_name,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Rename a block: replace only `block_name`, preserving every record and
/// all forward-compat `unknown` maps. `block_uuid` / `device_uuid` must each
/// be 16 bytes (else `ValueError`). Empty `new_block_name` is allowed.
/// Raises `VaultBlockNotFound` for an unknown block; `VaultCorruptVault` on
/// a decrypt failure / wiped handle; `VaultFolderInvalid` on an IO failure
/// during the atomic write; `VaultSaveCryptoFailure` on a crypto/encoding
/// failure.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn rename_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    new_block_name: String,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::rename_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        new_block_name,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Move a live record from one block to another under a caller-supplied UUID.
/// All five uuid arguments must each be 16 bytes (else `ValueError`).
/// `source_block_uuid` and `target_block_uuid` must differ — passing the same
/// UUID for both raises `ValueError` (the bridge does not check this; the
/// guard lives here).
///
/// Semantics are copy-before-delete: the copy lands in the target before the
/// source is tombstoned, so a mid-move crash leaves the source intact.
/// `created_at_ms`, per-field `last_mod`/`device_uuid`, field values, and all
/// `unknown` maps are preserved; only `record_uuid` and record-level
/// `last_mod_ms` are fresh. Raises `VaultBlockNotFound` if either block is
/// unknown; `VaultRecordNotFound` if no LIVE record with `source_record_uuid`
/// in the source block; `VaultCorruptVault` on a decrypt failure / wiped
/// handle; `VaultFolderInvalid` / `VaultSaveCryptoFailure` on the save tail.
#[pyfunction]
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub(crate) fn move_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    source_block_uuid: Vec<u8>,
    target_block_uuid: Vec<u8>,
    source_record_uuid: Vec<u8>,
    new_record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let source_block_uuid = uuid_array_or_value_error(&source_block_uuid, "source_block_uuid")?;
    let target_block_uuid = uuid_array_or_value_error(&target_block_uuid, "target_block_uuid")?;
    let source_record_uuid = uuid_array_or_value_error(&source_record_uuid, "source_record_uuid")?;
    let new_record_uuid = uuid_array_or_value_error(&new_record_uuid, "new_record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;

    if source_block_uuid == target_block_uuid {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "source_block_uuid and target_block_uuid must differ",
        ));
    }

    secretary_ffi_bridge::move_record(
        &identity.0,
        &manifest.0,
        source_block_uuid,
        target_block_uuid,
        source_record_uuid,
        new_record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}
