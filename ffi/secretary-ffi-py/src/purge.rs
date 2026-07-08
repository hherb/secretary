//! Permanent block-purge entry point (#399). Mirrors `trash.rs`'s
//! shape; the output DTO mirrors `vault.rs`'s `BlockSummary` for the
//! raw-bytes `block_uuid` field convention (top-level return type, no
//! nested `Vec` getter, so no `Clone` / `skip_from_py_object` needed —
//! see [[project_secretary_pyo3_028_fromtopyobject_deprecation]]).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Report of a completed (or already-completed) `purge_block` call.
/// Output-only; never constructed from Python.
#[pyclass(frozen, get_all)]
pub struct PurgeReport {
    /// 16-byte UUID of the purged block (echoes the caller's input).
    pub block_uuid: Vec<u8>,
    /// `True` iff the block had at least one non-owner recipient at
    /// classification time, `False` for owner-only, `None` when
    /// classification was not possible (idempotent re-purge, or the
    /// trash file was already gone).
    pub was_shared: Option<bool>,
    /// Number of recipients on the block's recipient table at
    /// classification time; `None` under the same conditions as
    /// `was_shared`.
    pub recipient_count: Option<u16>,
    /// Number of on-disk trash files removed by this call (best-effort;
    /// normally 0 or 1).
    pub files_removed: u32,
}

impl From<secretary_ffi_bridge::PurgeReport> for PurgeReport {
    fn from(r: secretary_ffi_bridge::PurgeReport) -> Self {
        Self {
            block_uuid: r.block_uuid.to_vec(),
            was_shared: r.was_shared,
            recipient_count: r.recipient_count,
            files_removed: r.files_removed,
        }
    }
}

/// Permanently purge a trashed block. See
/// `docs/vault-format.md` §7 (purge extension, #399) for the normative
/// sequence.
///
/// `block_uuid` and `device_uuid` must each be exactly 16 bytes;
/// otherwise raises `ValueError` (mirrors `trash_block` / `restore_block`).
///
/// On failure, the bridge handle is byte-identical to its pre-call
/// state.
///
/// # Raises
///
/// - `ValueError` — `block_uuid` / `device_uuid` length != 16.
/// - `VaultBlockNotInTrash` — no `TrashEntry` exists for `block_uuid`.
/// - `VaultFolderInvalid` — I/O failure (e.g. an atomic-write failure
///   on the manifest).
/// - `VaultSaveCryptoFailure` — crypto / encoding failure on
///   already-validated inputs.
/// - `CorruptVault` — either handle has been wiped.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
pub(crate) fn purge_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<PurgeReport> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::purge_block(&identity.0, &manifest.0, block_uuid, device_uuid, now_ms)
        .map(PurgeReport::from)
        .map_err(ffi_vault_error_to_pyerr)
}

/// Report of a completed `empty_trash` call: aggregate counts across
/// every `TrashEntry` purged by this call. Output-only; never
/// constructed from Python.
#[pyclass(frozen, get_all)]
pub struct EmptyTrashReport {
    /// Number of `TrashEntry` records newly marked purged by this call.
    pub purged_count: u32,
    /// Of `purged_count`, how many were classified as shared (at least
    /// one non-owner recipient) at classification time.
    pub shared_count: u32,
    /// Of `purged_count`, how many were classified as owner-only.
    pub owner_only_count: u32,
    /// Of `purged_count`, how many could not be classified (trash file
    /// unreadable/undecodable).
    pub unknown_count: u32,
    /// Total on-disk trash files removed across every purged entry.
    pub files_removed: u32,
    /// Total on-disk trash file removals that errored (benign orphans;
    /// never fatal).
    pub files_failed: u32,
}

impl From<secretary_ffi_bridge::EmptyTrashReport> for EmptyTrashReport {
    fn from(r: secretary_ffi_bridge::EmptyTrashReport) -> Self {
        Self {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
        }
    }
}

/// Permanently purge every currently-trashed, not-already-purged,
/// not-live block in one batch — the "empty trash" user operation. See
/// `docs/vault-format.md` §7 (purge extension, #399) for the normative
/// sequence.
///
/// `device_uuid` must be exactly 16 bytes; otherwise raises `ValueError`
/// (mirrors `purge_block` / `trash_block` / `restore_block`).
///
/// On failure, the bridge handle is byte-identical to its pre-call
/// state.
///
/// # Raises
///
/// - `ValueError` — `device_uuid` length != 16.
/// - `VaultFolderInvalid` — I/O failure (e.g. an atomic-write failure
///   on the manifest).
/// - `VaultSaveCryptoFailure` — crypto / encoding failure on
///   already-validated inputs.
/// - `CorruptVault` — either handle has been wiped.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
pub(crate) fn empty_trash(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<EmptyTrashReport> {
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::empty_trash(&identity.0, &manifest.0, device_uuid, now_ms)
        .map(EmptyTrashReport::from)
        .map_err(ffi_vault_error_to_pyerr)
}
