//! Retention auto-purge FFI projection (#402): the pure `expired_trash_entries`
//! preview, the `auto_purge_expired` commit, their bridge-side DTOs, and an
//! exhaustive core-error mapper. Sibling of [`crate::purge`]; the commit is
//! byte-for-byte `empty_trash`'s orchestration plus two scalar args
//! (`window_ms`, `now_ms`) and one pass-through report field (`window_ms`).
//! `docs/vault-format.md` §7 step 5.

use rand_core::OsRng;
use secretary_core::vault::{OpenVault, VaultError};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// One trash entry eligible for retention auto-purge — the pure preview
/// record a platform shows before committing. Bridge projection of
/// [`secretary_core::vault::ExpiredEntry`], field-for-field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredEntry {
    /// The trashed block's UUID.
    pub block_uuid: [u8; 16],
    /// The signed death-clock the age was computed from.
    pub tombstoned_at_ms: u64,
    /// `now_ms.saturating_sub(tombstoned_at_ms)` — how far past trashing
    /// this entry is (always `> window_ms` for an eligible entry).
    pub age_ms: u64,
}

impl From<secretary_core::vault::ExpiredEntry> for ExpiredEntry {
    fn from(e: secretary_core::vault::ExpiredEntry) -> Self {
        ExpiredEntry {
            block_uuid: e.block_uuid,
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        }
    }
}

/// Aggregate outcome of an [`auto_purge_expired`] call. Bridge projection
/// of [`secretary_core::vault::RetentionPurgeReport`]: every count narrowed
/// `usize`→`u32` for uniffi/pyo3 portability (a vault with more than 2^32
/// trashed blocks is not a realistic state); `window_ms` passes through.
///
/// Not `Default`: the empty-target return still carries the caller's real
/// `window_ms`, so a zero-count report is self-describing.
#[derive(Debug, Clone)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: u32,
    /// Of `purged_count`, classified shared (≥1 non-owner recipient).
    pub shared_count: u32,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: u32,
    /// Of `purged_count`, unclassifiable (trash file unreadable — honest
    /// "unknown", never fabricated).
    pub unknown_count: u32,
    /// On-disk `trash/` files removed across every purged entry.
    pub files_removed: u32,
    /// `trash/` removals that errored (benign orphans; never fatal).
    pub files_failed: u32,
    /// The retention window this call applied (echoes the caller).
    pub window_ms: u64,
}

impl From<secretary_core::vault::RetentionPurgeReport> for RetentionPurgeReport {
    fn from(r: secretary_core::vault::RetentionPurgeReport) -> Self {
        RetentionPurgeReport {
            purged_count: r.purged_count as u32,
            shared_count: r.shared_count as u32,
            owner_only_count: r.owner_only_count as u32,
            unknown_count: r.unknown_count as u32,
            files_removed: r.files_removed as u32,
            files_failed: r.files_failed as u32,
            window_ms: r.window_ms,
        }
    }
}

/// Pure, side-effect-free preview of the entries retention auto-purge would
/// permanently remove for `(window_ms, now_ms)`. Reads only the manifest; no
/// identity, no I/O. Returns an empty vec on a wiped handle (safe-default
/// convention, matching `block_summaries`). `docs/vault-format.md` §7 step 5.
pub fn expired_trash_entries(
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    match manifest.manifest_body() {
        Some(body) => secretary_core::vault::expired_trash_entries(&body, window_ms, now_ms)
            .into_iter()
            .map(ExpiredEntry::from)
            .collect(),
        None => Vec::new(),
    }
}

/// Permanently purge every trashed block older than `window_ms` — the
/// retention auto-purge commit. See
/// [`secretary_core::vault::auto_purge_expired`] for the normative sequence
/// (single manifest commit; empty target set → zero-count report carrying
/// the real `window_ms`, no manifest write). Same handle-snapshot shape as
/// [`crate::empty_trash`], with `window_ms` threaded to the core call.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped, or
///   `replace_manifest_and_file` failed.
/// - [`FfiVaultError::FolderInvalid`] — I/O failure (atomic-write, cross-fs
///   rename).
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure on
///   already-validated inputs.
pub fn auto_purge_expired(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    window_ms: u64,
    now_ms: u64,
    device_uuid: [u8; 16],
) -> Result<RetentionPurgeReport, FfiVaultError> {
    // Step 1: snapshot manifest (5-tuple) under one lock acquisition.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot identity (re-sign needs the secret keys).
    let identity_clone =
        identity
            .clone_inner_bundle()
            .ok_or_else(|| FfiVaultError::CorruptVault {
                detail: "identity handle has been closed".into(),
            })?;

    // Step 3: build a temporary OpenVault from the snapshots.
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 4: call core.
    let result = secretary_core::vault::auto_purge_expired(
        &vault_folder,
        &mut open_vault,
        window_ms,
        now_ms,
        device_uuid,
        &mut OsRng,
    );

    // Step 5: on Ok, write back; on Err, the bridge handle is untouched
    // (the OpenVault clone owned the only mutated state and drops).
    match result {
        Ok(report) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map(|()| RetentionPurgeReport::from(report))
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_retention(e)),
    }
}

/// Map `core::VaultError` → `FfiVaultError` for the retention path.
///
/// Exhaustive (no `_ =>` catchall) per issue #40. Identical arm set to
/// `map_core_vault_error_empty_trash`: retention takes no `block_uuid`, so
/// `BlockNotInTrash` cannot fire and folds to the crypto/encoding umbrella.
/// Adding a new `core::VaultError` variant becomes a compile error here.
fn map_core_vault_error_retention(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::BlockNotInTrash { .. }
        | VaultError::Record(_)
        | VaultError::Block(_)
        | VaultError::Manifest(_)
        | VaultError::Conflict(_)
        | VaultError::Rollback { .. }
        | VaultError::Unlock(_)
        | VaultError::Card(_)
        | VaultError::Sig(_)
        | VaultError::OwnerUuidMismatch { .. }
        | VaultError::ManifestAuthorMismatch
        | VaultError::ManifestVaultUuidMismatch { .. }
        | VaultError::KdfParamsMismatch
        | VaultError::ClockOverflow { .. }
        | VaultError::ContactCardUuidMismatch { .. }
        | VaultError::NotAuthor { .. }
        | VaultError::BlockNotFound { .. }
        | VaultError::RecipientAlreadyPresent
        | VaultError::RecipientNotPresent
        | VaultError::CannotRevokeOwner
        | VaultError::MissingRecipientCard { .. }
        | VaultError::BlockUuidAlreadyLive { .. }
        | VaultError::RestoreVerificationFailed { .. }
        | VaultError::RestoreTargetMissing { .. }
        | VaultError::BlockPurged { .. }
        | VaultError::BlockFingerprintMismatch { .. }
        | VaultError::BlockFileMissing { .. }
        | VaultError::RepairRejected { .. }
        | VaultError::DeviceSlotNotFound => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_entry_from_core_projects_all_fields() {
        let core = secretary_core::vault::ExpiredEntry {
            block_uuid: [0xAB; 16],
            tombstoned_at_ms: 1_000,
            age_ms: 4_000,
        };
        let bridge = ExpiredEntry::from(core);
        assert_eq!(bridge.block_uuid, [0xAB; 16]);
        assert_eq!(bridge.tombstoned_at_ms, 1_000);
        assert_eq!(bridge.age_ms, 4_000);
    }

    #[test]
    fn retention_report_from_core_narrows_usize_and_passes_window() {
        let core = secretary_core::vault::RetentionPurgeReport {
            purged_count: 3,
            shared_count: 1,
            owner_only_count: 2,
            unknown_count: 0,
            files_removed: 3,
            files_failed: 0,
            window_ms: 7_776_000_000,
        };
        let bridge = RetentionPurgeReport::from(core);
        assert_eq!(bridge.purged_count, 3);
        assert_eq!(bridge.shared_count, 1);
        assert_eq!(bridge.owner_only_count, 2);
        assert_eq!(bridge.unknown_count, 0);
        assert_eq!(bridge.files_removed, 3);
        assert_eq!(bridge.files_failed, 0);
        assert_eq!(bridge.window_ms, 7_776_000_000);
    }

    #[test]
    fn default_window_re_export_matches_core() {
        assert_eq!(
            crate::DEFAULT_RETENTION_WINDOW_MS,
            secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS
        );
    }

    #[test]
    fn map_core_io_routes_to_folder_invalid() {
        let core_err = VaultError::Io {
            context: "test",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        assert!(matches!(
            map_core_vault_error_retention(core_err),
            FfiVaultError::FolderInvalid { .. }
        ));
    }

    #[test]
    fn map_core_clock_overflow_folds_to_save_crypto_failure() {
        let core_err = VaultError::ClockOverflow {
            device_uuid: [0xff; 16],
        };
        assert!(matches!(
            map_core_vault_error_retention(core_err),
            FfiVaultError::SaveCryptoFailure { .. }
        ));
    }

    #[test]
    fn map_core_block_not_in_trash_folds_to_save_crypto_failure() {
        // retention takes no block_uuid, so BlockNotInTrash cannot fire;
        // folds to the umbrella (mirrors empty_trash's mapper).
        let core_err = VaultError::BlockNotInTrash {
            block_uuid: [0xbb; 16],
        };
        assert!(matches!(
            map_core_vault_error_retention(core_err),
            FfiVaultError::SaveCryptoFailure { .. }
        ));
    }
}
