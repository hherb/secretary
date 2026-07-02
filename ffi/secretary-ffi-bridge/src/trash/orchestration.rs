//! `trash_block` — free-function entry point that snapshots both
//! bridge handles under single locks, builds a temporary
//! `core::vault::OpenVault` from those snapshots, calls
//! `core::vault::trash_block`, and on Ok writes back the mutated
//! manifest + manifest_file into the bridge handle.
//!
//! Failure invariant: bridge in-memory state is byte-identical to
//! pre-call on Err. On-disk state may have a partial rename (block
//! file in `trash/`, manifest still pointing at `blocks/`) — harmless
//! because `open_vault` reads only entries listed in the manifest
//! (the trashed file is then detectable as an orphan and the
//! operation can be retried).

use rand_core::OsRng;
use secretary_core::vault::{OpenVault, VaultError};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Move a live block into trash. See
/// [`secretary_core::vault::trash_block`] for the normative sequence.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped,
///   or `replace_manifest_and_file` failed.
/// - [`FfiVaultError::BlockNotFound`] — the UUID is absent from
///   `manifest.blocks`.
/// - [`FfiVaultError::FolderInvalid`] — I/O failure (e.g. cross-
///   filesystem rename `EXDEV`, or an atomic-write failure on the
///   manifest).
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure
///   on already-validated inputs.
pub fn trash_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Step 1: snapshot manifest (5-tuple) under one lock acquisition.
    // Re-uses save's snapshot fn unchanged — trash needs the same
    // 5-tuple shape. A future cleanup pass could rename it to
    // `snapshot_for_mutating_orchestrator`; not in scope this PR.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot identity. trash_block reads from `open.identity`
    // for the manifest re-sign (Ed25519 + ML-DSA-65 secret keys) — the
    // bundle clone is consumed by OpenVault, and core::trash_block
    // re-wraps the raw seeds internally.
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
    let result = secretary_core::vault::trash_block(
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
        Ok(()) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_trash(e)),
    }
}

/// Map `core::VaultError` → `FfiVaultError` for the trash path.
///
/// Exhaustive (no `_ =>` catchall) per issue #40. Adding a new
/// `core::VaultError` variant becomes a *compile* error here rather
/// than a silent fold to `SaveCryptoFailure`.
fn map_core_vault_error_trash(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::BlockNotFound { block_uuid } => FfiVaultError::BlockNotFound {
            uuid_hex: hex::encode(block_uuid),
        },
        // The remaining variants either cannot fire from
        // core::trash_block (e.g. NotAuthor, RecipientAlreadyPresent,
        // RecipientNotPresent, CannotRevokeOwner — those are
        // share/revoke-only) or are crypto / encoding failures
        // on already-validated inputs. All fold to SaveCryptoFailure as
        // the umbrella variant: a typed FfiVaultError variant for each
        // would be drift surface with no foreign-side recovery story.
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
        | VaultError::RecipientAlreadyPresent
        | VaultError::RecipientNotPresent
        | VaultError::CannotRevokeOwner
        | VaultError::MissingRecipientCard { .. }
        | VaultError::BlockUuidAlreadyLive { .. }
        | VaultError::BlockNotInTrash { .. }
        | VaultError::RestoreVerificationFailed { .. }
        // #205: restore-only; unreachable from trash_block, listed for
        // exhaustiveness per issue #40.
        | VaultError::RestoreTargetMissing { .. }
        // Unreachable from trash_block (open_vault always precedes and
        // would have surfaced this earlier), but listed for exhaustiveness
        // per issue #40. The generic `From<VaultError>` impl routes this
        // to `CorruptVault` on the read path.
        | VaultError::BlockFingerprintMismatch { .. }
        // #350: unreachable from trash_block (repair is a separate
        // orchestrator entry point); listed for exhaustiveness per
        // issue #40.
        | VaultError::BlockFileMissing { .. }
        | VaultError::RepairRejected { .. }
        // ADR 0009 (B.1): unreachable from trash_block; listed for
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
    fn map_core_block_not_found_routes_to_block_not_found() {
        let core_err = VaultError::BlockNotFound {
            block_uuid: [0xab; 16],
        };
        let ffi = map_core_vault_error_trash(core_err);
        let FfiVaultError::BlockNotFound { uuid_hex } = ffi else {
            panic!("expected BlockNotFound");
        };
        assert!(uuid_hex.contains("ab"));
    }

    #[test]
    fn map_core_io_routes_to_folder_invalid() {
        let core_err = VaultError::Io {
            context: "test",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        let ffi = map_core_vault_error_trash(core_err);
        assert!(matches!(ffi, FfiVaultError::FolderInvalid { .. }));
    }

    #[test]
    fn map_core_clock_overflow_folds_to_save_crypto_failure() {
        let core_err = VaultError::ClockOverflow {
            device_uuid: [0xff; 16],
        };
        let ffi = map_core_vault_error_trash(core_err);
        assert!(matches!(ffi, FfiVaultError::SaveCryptoFailure { .. }));
    }

    #[test]
    fn map_core_restore_verification_failed_folds_to_save_crypto_failure() {
        // RestoreVerificationFailed routing through the trash mapper
        // would be a programmer error (it cannot fire from
        // core::trash_block), so it folds to SaveCryptoFailure as the
        // umbrella surface.
        let core_err = VaultError::RestoreVerificationFailed {
            block_uuid: [0; 16],
            detail: "n/a".into(),
        };
        let ffi = map_core_vault_error_trash(core_err);
        assert!(matches!(ffi, FfiVaultError::SaveCryptoFailure { .. }));
    }
}
