//! Folder-in vault open orchestrators ([`open_vault_with_password`] /
//! [`open_vault_with_recovery`]) plus the [`OpenVaultOutput`] return shape
//! and the bridge-internal `split_core_open_vault` helper that lifts a
//! `core::vault::OpenVault` into the two FFI handles.

use std::path::Path;

use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::vault::{manifest::is_rollback, OpenVault, Unlocker, VaultError};
use zeroize::Zeroize as _;

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;

use super::inner::OpenVaultManifestInner;
use super::manifest::OpenVaultManifest;

/// Output of [`open_vault_with_password`] / [`open_vault_with_recovery`].
/// Holds two opaque handles — the live identity and the read-only manifest.
///
/// # Drop discipline
///
/// Fields drop in source order. Both handles zeroize their own inner state
/// on drop; the order is observable but not load-bearing.
///
/// Debug output is redacted via the fields' own Debug impls — no secret
/// material leaks through `{:?}`.
#[derive(Debug)]
pub struct OpenVaultOutput {
    /// Live opaque handle to the unlocked identity. Re-used unchanged from
    /// B.2 / B.3a / B.3b. Same `display_name()` / `user_uuid()` / `wipe()`
    /// accessors.
    pub identity: UnlockedIdentity,
    /// Opaque handle to the decrypted manifest. Holds the IBK, manifest
    /// body, manifest envelope, and verified owner card internally; B.4a
    /// exposes only read-only block-list accessors.
    pub manifest: OpenVaultManifest,
}

/// Open a vault folder using its master password. Reads `vault.toml`,
/// `identity.bundle.enc`, `manifest.cbor.enc`, and the owner contact card
/// from `folder`; performs full unlock + manifest decode + signature
/// verification. Returns two opaque handles: the live `UnlockedIdentity`
/// and the read-only `OpenVaultManifest`.
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants. See module-level docs
/// on `crate::error` for the full surface.
pub fn open_vault_with_password(
    folder: &Path,
    password: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Password(&pw), None)?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    // The caller's foreign-side password buffer is THEIR concern.
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase. Reads the
/// same set of files as [`open_vault_with_password`]. The mnemonic input is
/// UTF-8 bytes; the bridge runs `std::str::from_utf8` and surfaces
/// malformed-UTF-8 input as [`FfiVaultError::InvalidMnemonic`] with
/// `detail: "phrase contained invalid UTF-8"` — same shape as B.3a's
/// [`crate::open_with_recovery`].
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants.
pub fn open_vault_with_recovery(
    folder: &Path,
    mnemonic_bytes: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase =
        std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        })?;
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Recovery(phrase), None)?;
    enforce_rollback_resistance(&core_out)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}

/// §10 manifest rollback resistance for app-facing opens (#352).
///
/// `open_vault` is invoked with `local_highest_clock = None` because the
/// `vault_uuid` needed to locate this device's persisted `SyncState` lives
/// inside the *encrypted* manifest body — it is only known after decode. So §10
/// is enforced here, on the just-decoded manifest: load this device's
/// OS-local `highest_vector_clock_seen` for the vault and reject if the opened
/// manifest's clock is strictly dominated by it — a cloud host replaying an
/// older signed snapshot to a device that opens *without* syncing (threat-model
/// adversary 2.1). The sync layer enforces the same on its own path; this
/// closes the browse-without-sync gap.
///
/// A never-synced device has no state file → an empty baseline → no false
/// positive. A detected rollback surfaces as [`VaultError::Rollback`] →
/// [`FfiVaultError::CorruptVault`] (fail-closed: the caller never receives a
/// usable handle, and blocks are only read on-demand *after* this returns, so a
/// rolled-back vault can never be browsed).
///
/// The state directory is OS-local and outside the cloud-replay threat surface,
/// so if it cannot be read (missing dir, corrupt/mismatched state file), the
/// check is skipped rather than bricking the open — availability over a defense
/// against a threat (local-state tampering) that already implies device
/// compromise. `load` itself returns an empty state for a missing *file*.
pub(crate) fn enforce_rollback_resistance(core_out: &OpenVault) -> Result<(), FfiVaultError> {
    let Some(state_dir) = secretary_cli::state::default_state_dir() else {
        return Ok(());
    };
    enforce_rollback_resistance_in(&state_dir, core_out)
}

/// Explicit-`state_dir` seam for [`enforce_rollback_resistance`] (host-testable).
pub(crate) fn enforce_rollback_resistance_in(
    state_dir: &Path,
    core_out: &OpenVault,
) -> Result<(), FfiVaultError> {
    let Ok(state) = secretary_cli::state::load(state_dir, core_out.manifest.vault_uuid) else {
        return Ok(()); // unreadable local baseline → skip (see fn docs)
    };
    if is_rollback(
        &state.highest_vector_clock_seen,
        &core_out.manifest.vector_clock,
    ) {
        return Err(VaultError::Rollback {
            local_clock: state.highest_vector_clock_seen,
            incoming_clock: core_out.manifest.vector_clock.clone(),
        }
        .into());
    }
    Ok(())
}

/// Split a `core::vault::OpenVault` into the two FFI handles.
///
/// `Sensitive<[u8; 32]>` does not implement `Clone`, so we copy the 32 raw
/// bytes out via `expose()` and mint a second `Sensitive` for the manifest
/// handle.  Both copies carry `ZeroizeOnDrop`; the intermediate stack array
/// is explicitly zeroized per `CLAUDE.md`'s stack-residue discipline.
pub(crate) fn split_core_open_vault(
    core_out: secretary_core::vault::OpenVault,
    vault_folder: std::path::PathBuf,
) -> OpenVaultOutput {
    let secretary_core::vault::OpenVault {
        identity_block_key,
        identity,
        owner_card,
        manifest,
        manifest_file,
    } = core_out;

    // Mint a second Sensitive copy for OpenVaultManifestInner.
    // identity_block_key.expose() returns &[u8; 32]; dereference copies the
    // 32-byte array onto the stack.  Sensitive::new moves that stack copy in,
    // but [u8; 32]: Copy so the stack slot is not cleared by the move.
    // Explicit zeroize per CLAUDE.md memory-hygiene-audit-internal §stack-residue.
    let mut ibk_bytes: [u8; 32] = *identity_block_key.expose();
    let ibk_for_manifest = Sensitive::new(ibk_bytes);
    ibk_bytes.zeroize();

    // UnlockedIdentity wraps the core unlock type (IBK + IdentityBundle).
    let unlocked_for_handle = secretary_core::unlock::UnlockedIdentity {
        identity_block_key,
        identity,
    };

    OpenVaultOutput {
        identity: UnlockedIdentity::new(unlocked_for_handle),
        manifest: OpenVaultManifest::new(OpenVaultManifestInner {
            identity_block_key: ibk_for_manifest,
            manifest,
            manifest_file,
            owner_card,
            vault_folder,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use secretary_core::crypto::kdf::Argon2idParams;
    use secretary_core::vault::{create_vault, open_vault, VectorClockEntry};

    /// Create an on-disk vault in `dir` and open it. `create_vault` enforces the
    /// v1 KDF floor, so we use exactly the 64 MiB floor (one cheap-ish Argon2
    /// pass in the release test profile).
    fn create_and_open(dir: &Path) -> OpenVault {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let pw = SecretBytes::new(b"correct horse battery".to_vec());
        create_vault(
            dir,
            &pw,
            "Tester",
            Argon2idParams::new(65536, 1, 1),
            0,
            &mut rng,
        )
        .expect("create_vault");
        open_vault(dir, Unlocker::Password(&pw), None).expect("open_vault")
    }

    #[test]
    fn no_state_file_means_no_rollback_check() {
        let vault = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap(); // empty: never synced
        let core_out = create_and_open(vault.path());
        assert!(enforce_rollback_resistance_in(state.path(), &core_out).is_ok());
    }

    #[test]
    fn dominating_local_clock_is_rejected_as_rollback() {
        let vault = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let core_out = create_and_open(vault.path());

        // A highest-seen clock that strictly dominates the just-opened manifest
        // (increment every entry; synthesize one if the clock is empty) — i.e. a
        // device that already saw a newer version than the replayed manifest.
        let mut dominating: Vec<VectorClockEntry> = core_out
            .manifest
            .vector_clock
            .iter()
            .map(|e| VectorClockEntry {
                device_uuid: e.device_uuid,
                counter: e.counter + 1,
            })
            .collect();
        if dominating.is_empty() {
            dominating.push(VectorClockEntry {
                device_uuid: [1u8; 16],
                counter: 1,
            });
        }
        dominating.sort_by_key(|e| e.device_uuid);
        let synced =
            secretary_core::sync::SyncState::new(core_out.manifest.vault_uuid, dominating).unwrap();
        secretary_cli::state::save(state_dir.path(), &synced).unwrap();

        let err = enforce_rollback_resistance_in(state_dir.path(), &core_out).unwrap_err();
        assert!(
            matches!(err, FfiVaultError::CorruptVault { .. }),
            "rollback must fail-closed as CorruptVault, got {err:?}",
        );
    }

    #[test]
    fn equal_local_clock_is_not_a_rollback() {
        let vault = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let core_out = create_and_open(vault.path());
        let mut same: Vec<VectorClockEntry> = core_out.manifest.vector_clock.clone();
        same.sort_by_key(|e| e.device_uuid);
        let synced =
            secretary_core::sync::SyncState::new(core_out.manifest.vault_uuid, same).unwrap();
        secretary_cli::state::save(state_dir.path(), &synced).unwrap();
        assert!(enforce_rollback_resistance_in(state_dir.path(), &core_out).is_ok());
    }
}
