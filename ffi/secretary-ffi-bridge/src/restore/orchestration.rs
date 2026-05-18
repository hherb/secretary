//! `restore_block` — free-function entry point. Same shape as
//! [`crate::trash::orchestration::trash_block`] but with the richer
//! error mapper: restore can surface the trash-side rejection variants
//! (`BlockUuidAlreadyLive`, `BlockNotInTrash`), the verification-
//! failure variant (`RestoreVerificationFailed` folded to
//! `CorruptVault`), and `MissingRecipientCard` from the contacts/-scan
//! step.
//!
//! Failure invariant: bridge in-memory state is byte-identical to
//! pre-call on Err. On-disk state may have a partial restore (file
//! moved trash → blocks, manifest still pointing at trash) if a step-7
//! crash occurs — recoverable on next open by re-attempting the
//! restore.

use rand_core::OsRng;
use secretary_core::vault::{OpenVault, VaultError};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Restore the most recent trashed copy of a block. See
/// [`secretary_core::vault::restore_block`] for the normative sequence
/// (`docs/vault-format.md` §7.1).
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped,
///   the trashed file failed §6.1 hybrid-signature verification (folded
///   from `RestoreVerificationFailed`), or `replace_manifest_and_file`
///   failed.
/// - [`FfiVaultError::BlockUuidAlreadyLive`] — caller requested
///   restore on a UUID that is currently live; caller must trash the
///   live copy first.
/// - [`FfiVaultError::BlockNotInTrash`] — no matching file in
///   `trash/<uuid>.cbor.enc.*` and no matching `TrashEntry`.
/// - [`FfiVaultError::MissingRecipientCard`] — a recipient on the
///   trashed file's wrap table cannot be resolved to a `contact_uuid`
///   via the contacts/-scan; the trash file and manifest are untouched.
/// - [`FfiVaultError::FolderInvalid`] — I/O failure (e.g. cross-
///   filesystem rename `EXDEV`, or an atomic-write failure on the
///   manifest).
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto / encoding failure
///   on already-validated inputs.
pub fn restore_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;
    let identity_clone =
        identity
            .clone_inner_bundle()
            .ok_or_else(|| FfiVaultError::CorruptVault {
                detail: "identity handle has been closed".into(),
            })?;
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    let result = secretary_core::vault::restore_block(
        &vault_folder,
        &mut open_vault,
        block_uuid,
        device_uuid,
        now_ms,
        &mut OsRng,
    );

    match result {
        Ok(()) => manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            }),
        Err(e) => Err(map_core_vault_error_restore(e)),
    }
}

/// Map `core::VaultError` → `FfiVaultError` for the restore path.
///
/// Exhaustive (no `_ =>` catchall) per issue #40. The four restore-
/// specific routings are typed (`BlockUuidAlreadyLive`,
/// `BlockNotInTrash`, `RestoreVerificationFailed`,
/// `MissingRecipientCard`); the rest fold to `SaveCryptoFailure` as
/// the umbrella variant.
fn map_core_vault_error_restore(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
        VaultError::BlockUuidAlreadyLive { block_uuid } => FfiVaultError::BlockUuidAlreadyLive {
            detail: hex::encode(block_uuid),
        },
        VaultError::BlockNotInTrash { block_uuid } => FfiVaultError::BlockNotInTrash {
            detail: hex::encode(block_uuid),
        },
        // "Data on disk doesn't match what we signed" — the
        // CorruptVault contract.
        VaultError::RestoreVerificationFailed { block_uuid, detail } => {
            FfiVaultError::CorruptVault {
                detail: format!(
                    "trashed block {} failed verification: {detail}",
                    hex::encode(block_uuid),
                ),
            }
        }
        // The contacts/-scan in restore step 5 surfaces this when a
        // wrap's recipient is not in contacts/.
        VaultError::MissingRecipientCard { fingerprint } => FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex: hex::encode(fingerprint),
        },
        // The remaining variants either cannot fire from
        // core::restore_block (NotAuthor, RecipientAlreadyPresent —
        // those are share_block-only; BlockNotFound — restore doesn't
        // look up a live BlockEntry by UUID) or are crypto / encoding
        // failures on already-validated inputs.
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
        | VaultError::NotAuthor { .. }
        | VaultError::BlockNotFound { .. }
        | VaultError::RecipientAlreadyPresent
        // Unreachable from restore_block (open_vault always precedes
        // and would have surfaced this earlier), but listed for
        // exhaustiveness per issue #40. The generic `From<VaultError>`
        // impl routes this to `CorruptVault` on the read path.
        | VaultError::BlockFingerprintMismatch { .. } => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_core_block_uuid_already_live_routes_typed() {
        let core_err = VaultError::BlockUuidAlreadyLive {
            block_uuid: [0xaa; 16],
        };
        let ffi = map_core_vault_error_restore(core_err);
        let FfiVaultError::BlockUuidAlreadyLive { detail } = ffi else {
            panic!("expected BlockUuidAlreadyLive");
        };
        assert!(detail.contains("aa"));
    }

    #[test]
    fn map_core_block_not_in_trash_routes_typed() {
        let core_err = VaultError::BlockNotInTrash {
            block_uuid: [0xbb; 16],
        };
        let ffi = map_core_vault_error_restore(core_err);
        let FfiVaultError::BlockNotInTrash { detail } = ffi else {
            panic!("expected BlockNotInTrash");
        };
        assert!(detail.contains("bb"));
    }

    #[test]
    fn map_core_restore_verification_failed_folds_to_corrupt_vault() {
        let core_err = VaultError::RestoreVerificationFailed {
            block_uuid: [0xcc; 16],
            detail: "sig mismatch".into(),
        };
        let ffi = map_core_vault_error_restore(core_err);
        let FfiVaultError::CorruptVault { detail } = ffi else {
            panic!("expected CorruptVault");
        };
        assert!(detail.contains("sig mismatch"));
        assert!(detail.contains("verification"));
    }

    #[test]
    fn map_core_missing_recipient_card_routes_typed() {
        let core_err = VaultError::MissingRecipientCard {
            fingerprint: [0xdd; 16],
        };
        let ffi = map_core_vault_error_restore(core_err);
        let FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } = ffi
        else {
            panic!("expected MissingRecipientCard");
        };
        assert!(recipient_fingerprint_hex.contains("dd"));
    }

    #[test]
    fn map_core_block_not_found_folds_to_save_crypto_failure() {
        // BlockNotFound can't fire from core::restore_block (restore
        // looks up TrashEntry, not BlockEntry); routes to the umbrella
        // surface as a programmer-error signal.
        let core_err = VaultError::BlockNotFound {
            block_uuid: [0xee; 16],
        };
        let ffi = map_core_vault_error_restore(core_err);
        assert!(matches!(ffi, FfiVaultError::SaveCryptoFailure { .. }));
    }
}
