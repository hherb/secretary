//! `purge_block` — free-function entry point that snapshots both
//! bridge handles under single locks, builds a temporary
//! `core::vault::OpenVault` from those snapshots, calls
//! `core::vault::purge_block`, and on Ok writes back the mutated
//! manifest + manifest_file into the bridge handle. Same shape as
//! [`crate::trash::orchestration::trash_block`], but the core call
//! returns a report (`core::vault::PurgeReport`) rather than `()`,
//! which this module maps into the bridge's uniffi/pyo3-portable
//! [`PurgeReport`] (`usize` → `u32`).
//!
//! Failure invariant: bridge in-memory state is byte-identical to
//! pre-call on Err. On-disk state may have a partial purge (manifest
//! updated to mark the `TrashEntry` purged, but one or more
//! `trash/<uuid>.cbor.enc.*` files still present) due to the
//! manifest-write-first semantics `core::vault::purge_block` documents —
//! harmless: `open_vault` never re-adds a purged UUID to
//! `manifest.blocks`, so a lingering file is a benign orphan, not a
//! correctness problem.

use rand_core::OsRng;
use secretary_core::vault::{OpenVault, VaultError};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Report of a completed (or already-completed) [`purge_block`] call.
///
/// Bridge-side projection of [`secretary_core::vault::PurgeReport`]:
/// identical field-for-field except `files_removed`, which is narrowed
/// from `usize` to `u32` for uniffi/pyo3 portability (a block's trash
/// directory holding more than 2^32 files is not a realistic vault
/// state).
///
/// `was_shared` / `recipient_count` are `None` when the trash file could
/// not be read/decoded at classification time (already purged on a prior
/// call, or the file was independently lost) — an honest "unknown",
/// never a fabricated `false`/`0`.
#[derive(Debug, Clone)]
pub struct PurgeReport {
    /// The purged block's UUID (echoes the caller's input).
    pub block_uuid: [u8; 16],
    /// `Some(true)` iff the block had at least one non-owner recipient
    /// at classification time; `Some(false)` for owner-only;
    /// `None` when classification was not possible (idempotent
    /// re-purge, or the trash file was already gone).
    pub was_shared: Option<bool>,
    /// Number of recipients on the block's §6.2 recipient table at
    /// classification time; `None` under the same conditions as
    /// `was_shared`.
    pub recipient_count: Option<u16>,
    /// Number of on-disk `trash/<uuid>.cbor.enc.*` files removed by
    /// this call (best-effort; normally 0 or 1).
    pub files_removed: u32,
}

impl From<secretary_core::vault::PurgeReport> for PurgeReport {
    fn from(r: secretary_core::vault::PurgeReport) -> Self {
        PurgeReport {
            block_uuid: r.block_uuid,
            was_shared: r.was_shared,
            recipient_count: r.recipient_count,
            files_removed: r.files_removed as u32,
        }
    }
}

/// Permanently purge a trashed block. See
/// [`secretary_core::vault::purge_block`] for the normative sequence.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped,
///   or `replace_manifest_and_file` failed.
/// - [`FfiVaultError::BlockNotInTrash`] — no `TrashEntry` exists for
///   `block_uuid`.
/// - [`FfiVaultError::FolderInvalid`] — I/O failure (e.g. cross-
///   filesystem rename `EXDEV`, or an atomic-write failure on the
///   manifest).
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure
///   on already-validated inputs.
pub fn purge_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<PurgeReport, FfiVaultError> {
    // Step 1: snapshot manifest (5-tuple) under one lock acquisition.
    // Re-uses save's snapshot fn unchanged — purge needs the same
    // 5-tuple shape as trash/restore.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot identity. purge_block re-signs the manifest
    // (Ed25519 + ML-DSA-65 secret keys) — the bundle clone is consumed
    // by OpenVault, and core::purge_block re-wraps the raw seeds
    // internally.
    let identity_clone =
        identity
            .clone_inner_bundle()
            .ok_or_else(|| FfiVaultError::CorruptVault {
                detail: "identity handle has been closed".into(),
            })?;

    // Step 3: build temporary OpenVault from the snapshots.
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 4: call core.
    let result = secretary_core::vault::purge_block(
        &vault_folder,
        &mut open_vault,
        block_uuid,
        device_uuid,
        now_ms,
        &mut OsRng,
    );

    // Step 5: on Ok, write back via the existing replace_manifest_and_file
    // helper. On Err, the bridge handle is untouched (the OpenVault
    // clone owned the only mutated state and is about to drop).
    match result {
        Ok(report) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map(|()| PurgeReport::from(report))
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_purge(e)),
    }
}

/// Map `core::VaultError` → `FfiVaultError` for the purge path.
///
/// Exhaustive (no `_ =>` catchall) per issue #40. Adding a new
/// `core::VaultError` variant becomes a *compile* error here rather
/// than a silent fold to `SaveCryptoFailure`.
fn map_core_vault_error_purge(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::BlockNotInTrash { block_uuid } => FfiVaultError::BlockNotInTrash {
            detail: hex::encode(block_uuid),
        },
        // The remaining variants either cannot fire from
        // core::purge_block (e.g. NotAuthor, RecipientAlreadyPresent,
        // RecipientNotPresent, CannotRevokeOwner — those are
        // share/revoke-only; BlockUuidAlreadyLive, BlockPurged,
        // RestoreVerificationFailed, RestoreTargetMissing,
        // MissingRecipientCard — those are restore-only; BlockNotFound —
        // purge doesn't look up a live BlockEntry by UUID) or are
        // crypto / encoding failures on already-validated inputs. All
        // fold to SaveCryptoFailure as the umbrella variant: a typed
        // FfiVaultError variant for each would be drift surface with no
        // foreign-side recovery story.
        VaultError::Record(_)
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
        // #399: restore-only; unreachable from purge_block, listed for
        // exhaustiveness per issue #40.
        | VaultError::BlockPurged { .. }
        // Unreachable from purge_block (open_vault always precedes and
        // would have surfaced this earlier), but listed for exhaustiveness
        // per issue #40. The generic `From<VaultError>` impl routes this
        // to `CorruptVault` on the read path.
        | VaultError::BlockFingerprintMismatch { .. }
        // #350: unreachable from purge_block (repair is a separate
        // orchestrator entry point); listed for exhaustiveness per
        // issue #40.
        | VaultError::BlockFileMissing { .. }
        | VaultError::RepairRejected { .. }
        // ADR 0009 (B.1): unreachable from purge_block; listed for
        // exhaustiveness per issue #40.
        | VaultError::DeviceSlotNotFound => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_core_block_not_in_trash_routes_typed() {
        let core_err = VaultError::BlockNotInTrash {
            block_uuid: [0xbb; 16],
        };
        let ffi = map_core_vault_error_purge(core_err);
        let FfiVaultError::BlockNotInTrash { detail } = ffi else {
            panic!("expected BlockNotInTrash");
        };
        assert!(detail.contains("bb"));
    }

    #[test]
    fn map_core_io_routes_to_folder_invalid() {
        let core_err = VaultError::Io {
            context: "test",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        let ffi = map_core_vault_error_purge(core_err);
        assert!(matches!(ffi, FfiVaultError::FolderInvalid { .. }));
    }

    #[test]
    fn map_core_block_purged_folds_to_save_crypto_failure() {
        // BlockPurged routing through the purge mapper would be a
        // programmer error (it cannot fire from core::purge_block —
        // it's the terminal state purge itself produces, surfaced only
        // by restore), so it folds to SaveCryptoFailure as the umbrella
        // surface.
        let core_err = VaultError::BlockPurged {
            block_uuid: [0; 16],
        };
        let ffi = map_core_vault_error_purge(core_err);
        assert!(matches!(ffi, FfiVaultError::SaveCryptoFailure { .. }));
    }

    #[test]
    fn map_core_clock_overflow_folds_to_save_crypto_failure() {
        let core_err = VaultError::ClockOverflow {
            device_uuid: [0xff; 16],
        };
        let ffi = map_core_vault_error_purge(core_err);
        assert!(matches!(ffi, FfiVaultError::SaveCryptoFailure { .. }));
    }
}
