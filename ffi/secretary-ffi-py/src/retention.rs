//! Retention auto-purge entry points (#402). Preview (`expired_trash_entries`,
//! pure/infallible) + commit (`auto_purge_expired`). Output DTOs mirror
//! `purge.rs`'s `EmptyTrashReport` shape (top-level return types, raw-bytes
//! `block_uuid`, so no `Clone` / `skip_from_py_object` needed — see
//! [[project_secretary_pyo3_028_fromtopyobject_deprecation]]).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// One trash entry eligible for retention auto-purge. Output-only; never
/// constructed from Python.
#[pyclass(frozen, get_all)]
pub struct ExpiredEntry {
    /// 16-byte UUID of the trashed block.
    pub block_uuid: Vec<u8>,
    /// Signed death-clock (unix-millis) the age was computed from.
    pub tombstoned_at_ms: u64,
    /// `now_ms - tombstoned_at_ms` — how far past trashing this entry is.
    pub age_ms: u64,
}

impl From<secretary_ffi_bridge::ExpiredEntry> for ExpiredEntry {
    fn from(e: secretary_ffi_bridge::ExpiredEntry) -> Self {
        Self {
            block_uuid: e.block_uuid.to_vec(),
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        }
    }
}

/// Aggregate outcome of an `auto_purge_expired` call. Output-only; never
/// constructed from Python.
#[pyclass(frozen, get_all)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: u32,
    /// Of `purged_count`, classified shared (>=1 non-owner recipient).
    pub shared_count: u32,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: u32,
    /// Of `purged_count`, unclassifiable (trash file unreadable).
    pub unknown_count: u32,
    /// On-disk trash files removed across every purged entry.
    pub files_removed: u32,
    /// Trash-file removals that errored (benign orphans; never fatal).
    pub files_failed: u32,
    /// The retention window this call applied (echoes the caller).
    pub window_ms: u64,
}

impl From<secretary_ffi_bridge::RetentionPurgeReport> for RetentionPurgeReport {
    fn from(r: secretary_ffi_bridge::RetentionPurgeReport) -> Self {
        Self {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
            window_ms: r.window_ms,
        }
    }
}

/// Pure preview of the entries retention auto-purge would remove for
/// `(window_ms, now_ms)`. No I/O; returns `[]` on a wiped handle. See
/// `docs/vault-format.md` §7 step 5.
#[pyfunction]
pub(crate) fn expired_trash_entries(
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    secretary_ffi_bridge::expired_trash_entries(&manifest.0, window_ms, now_ms)
        .into_iter()
        .map(ExpiredEntry::from)
        .collect()
}

/// Permanently purge every trashed block older than `window_ms`. See
/// `docs/vault-format.md` §7 step 5 (#402) for the normative sequence.
///
/// `device_uuid` must be exactly 16 bytes; otherwise raises `ValueError`.
/// On failure the bridge handle is byte-identical to its pre-call state.
///
/// # Raises
///
/// - `ValueError` — `device_uuid` length != 16.
/// - `VaultFolderInvalid` — I/O failure (atomic-write on the manifest).
/// - `VaultSaveCryptoFailure` — crypto / encoding failure on
///   already-validated inputs.
/// - `CorruptVault` — either handle has been wiped.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
pub(crate) fn auto_purge_expired(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
    device_uuid: Vec<u8>,
) -> PyResult<RetentionPurgeReport> {
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::auto_purge_expired(
        &identity.0,
        &manifest.0,
        window_ms,
        now_ms,
        device_uuid,
    )
    .map(RetentionPurgeReport::from)
    .map_err(ffi_vault_error_to_pyerr)
}
