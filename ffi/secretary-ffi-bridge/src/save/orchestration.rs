//! `save_block` — free-function entry point that locks both handles,
//! builds a temporary `core::vault::OpenVault` from clones, calls
//! `core::vault::save_block`, and on Ok writes back the mutated manifest +
//! manifest_file into the bridge handle.
//!
//! Failure invariant: bridge in-memory state is byte-identical to pre-call
//! on Err. On-disk state may have a partial write (block file present,
//! manifest re-sign failed) — harmless because `open_vault` reads only
//! entries listed in the manifest.
//!
//! v1 single-author: recipients = `[owner_card]`. Multi-recipient is B.4d.
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §5.

use rand_core::OsRng;
use secretary_core::vault::{OpenVault, VaultError};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::save::input::BlockInput;
use crate::vault::OpenVaultManifest;

/// Encrypt and atomically persist one block of records.
///
/// Mirrors the free-function shape of [`crate::record::read_block`].
/// v1 single-author: recipients are owner-only; multi-recipient is B.4d.
///
/// # Behavior
///
/// On `Ok(())`: the block file is written to
/// `<vault>/blocks/<uuid>.cbor.enc` and the manifest is re-signed and
/// atomically replaced. The bridge-held [`OpenVaultManifest`] is updated
/// in place to reflect the new manifest body and envelope.
///
/// On `Err`: bridge in-memory state is byte-identical to pre-call. The
/// on-disk state may have a partial write (block file persisted but
/// manifest re-sign failed); §9 atomicity is per-file, and a divergent
/// block-file-without-manifest-entry is harmless because `open_vault`
/// reads only entries listed in the manifest.
///
/// # Errors
///
/// - [`FfiVaultError::CorruptVault`] — either handle has been wiped.
/// - [`FfiVaultError::FolderInvalid`] — IO failure during atomic write.
/// - [`FfiVaultError::SaveCryptoFailure`] — crypto/encoding failure on
///   already-validated inputs (clock overflow, post-unlock memory
///   corruption, encoder failure on freshly-built struct, signature
///   primitive failure).
pub fn save_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    input: BlockInput,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Step 1: snapshot the manifest under one lock acquisition. Holds the
    // five fields save_block needs (manifest, manifest_file, owner_card,
    // IBK clone, vault folder). Lock is released at the end of the
    // statement.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot the identity. We only need an owned clone of the
    // IdentityBundle (which carries all four secret keys); core::save_block
    // uses ed25519_sk / ml_dsa_65_sk for signing.
    let identity_clone =
        identity
            .clone_inner_bundle()
            .ok_or_else(|| FfiVaultError::CorruptVault {
                detail: "identity handle has been closed".into(),
            })?;

    // Step 3: build BlockPlaintext from BlockInput. The conversion moves
    // the SecretString / SecretBytes wrappers into core::RecordFieldValue
    // (no plaintext reallocation; zeroize-on-drop preserved through the
    // move).
    let plaintext = input.into_block_plaintext(now_ms, device_uuid);

    // Step 4: build the temporary OpenVault from clones. The manifest +
    // manifest_file clones are the unmodified-on-failure invariant: if
    // core::save_block returns Err, these temporaries drop without
    // touching the bridge handle's state. Clone owner_card a second time
    // so we can pass it as both the OpenVault.owner_card field AND the
    // recipients list (without simultaneous mutable+immutable borrow of
    // open_vault).
    let recipients_list = [owner_card.clone()];
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 5: call core. Owner-only recipients — multi-recipient is B.4d.
    let result = secretary_core::vault::save_block(
        &vault_folder,
        &mut open_vault,
        plaintext,
        &recipients_list,
        device_uuid,
        now_ms,
        &mut OsRng,
    );

    // Step 6: on Ok, write back the mutated manifest + manifest_file into
    // the bridge handle. The handle could in theory have been wiped
    // between Step 1 and now (concurrent wipe race). If so, the on-disk
    // write already succeeded; we surface CorruptVault to the caller
    // because the bridge state is no longer authoritative.
    match result {
        Ok(()) => {
            // Test-only hook: exposes the concurrent-wipe race window
            // (lock NOT held between `core::save_block` succeeding and
            // `replace_manifest_and_file` taking the write-back lock) to
            // integration tests. Always present in all builds — pays one
            // uncontended `Mutex` lock + `Option::is_none` check per
            // call (negligible vs. the surrounding crypto work). No-op
            // unless a hook was explicitly installed via
            // `OpenVaultManifest::install_mid_call_hook`, which only
            // integration tests call. See issue #35 and
            // tests::save_block::save_block_wipe_during_call_*.
            manifest.run_mid_call_hook();
            // Atomic write-back of the mutated manifest body and envelope.
            // The handle could have been wiped between Step 1 and now in a
            // theoretical concurrent-wipe race — if so, the on-disk write
            // already succeeded but the bridge state is no longer
            // authoritative; surface as CorruptVault.
            manifest
                .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
                .map_err(|e| FfiVaultError::CorruptVault {
                    detail: e.to_string(),
                })
            // open_vault has been consumed by replace_manifest_and_file
            // (manifest + manifest_file moved out). The remaining fields
            // (identity, owner_card, ibk) drop here, zeroizing via
            // ZeroizeOnDrop.
        }
        Err(e) => Err(map_core_vault_error(e)),
    }
}

/// Map [`secretary_core::vault::VaultError`] to [`FfiVaultError`] per the
/// spec §6 error table. IO failures fold to `FolderInvalid`; everything
/// else folds to `SaveCryptoFailure` (since for save these are by
/// construction in-memory failures on already-validated inputs, not
/// on-disk corruption).
///
/// Per-variant arms (no `_ =>` catchall) per issue #40: adding a new
/// `core::VaultError` variant becomes a *compile* error here rather than
/// silently folding to `SaveCryptoFailure`, forcing a deliberate routing
/// decision at the save-mapper boundary. The share-validation variants
/// (`NotAuthor` / `RecipientAlreadyPresent` / `RecipientNotPresent` /
/// `CannotRevokeOwner` / `MissingRecipientCard` / `BlockNotFound`) are
/// unreachable from `core::save_block` today but are
/// listed explicitly to keep the match exhaustive across the full
/// `VaultError` surface; if they did fire they would represent a
/// programmer error from the save path's perspective and folding to
/// `SaveCryptoFailure` is the right surface.
pub(crate) fn map_core_vault_error(e: VaultError) -> FfiVaultError {
    match &e {
        VaultError::Io { context, source } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {source}"),
        },
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
        | VaultError::BlockNotInTrash { .. }
        | VaultError::RestoreVerificationFailed { .. }
        // #205: restore-only; unreachable from save_block, listed for
        // exhaustiveness per issue #40.
        | VaultError::RestoreTargetMissing { .. }
        // Unreachable from save_block (open_vault always precedes and
        // would have surfaced this earlier), but listed for exhaustiveness
        // per issue #40. The generic `From<VaultError>` impl routes this
        // to `CorruptVault` on the read path.
        | VaultError::BlockFingerprintMismatch { .. }
        // #350: unreachable from save_block (repair is a separate
        // orchestrator entry point); listed for exhaustiveness per
        // issue #40.
        | VaultError::BlockFileMissing { .. }
        | VaultError::RepairRejected { .. }
        // ADR 0009 (B.1): unreachable from save_block; listed for
        // exhaustiveness per issue #40.
        | VaultError::DeviceSlotNotFound => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}
