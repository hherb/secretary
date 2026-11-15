//! "Reset sync state for this vault" (#746): the user-confirmed recovery from
//! [`FfiVaultError::RollbackDetected`].
//!
//! A device whose saved §10 baseline dominates the disk cannot open the vault
//! (the open check refuses) and cannot sync (the pass returns
//! `RollbackRejected`). Before #730 a SilentMerge saved a clock it did not
//! write, so a device could reach that state with no attack involved. This
//! entry point lets the user accept the vault as it is on disk now.
//!
//! What it does, in order:
//! 1. A full password open: unlock, manifest decrypt and hybrid verify. A
//!    wrong password changes nothing.
//! 2. Under the per-vault lockfile, delete this vault's state file. §10 then
//!    treats this device as never synced, so the manifest it just verified is
//!    accepted; the next sync records a fresh baseline from it.
//! 3. Return the open handles. The rollback check is deliberately skipped.
//!
//! It accepts whatever signed manifest is on disk, including a replayed older
//! one: that is what the user is confirming, and why it is a separate call
//! the apps reach only from the rollback error, never automatically. The
//! master password is the re-authentication. A device-secret variant is
//! deliberately absent, so a biometric prompt alone cannot drop rollback
//! protection.

use std::path::Path;

use secretary_cli::state::{delete, LockfileGuard};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::Unlocker;

use super::orchestration::{split_core_open_vault, OpenVaultOutput};
use crate::error::FfiVaultError;
use crate::sync::pass::default_state_dir_or_err;
use crate::sync::status::map_state_error;

/// Open `folder` with its master password, deleting this device's sync state
/// for the vault first so the current on-disk manifest is accepted. See the
/// module docs for when the apps offer it.
///
/// # Errors
///
/// The password open's errors (a wrong password, a corrupt vault), plus
/// [`FfiVaultError::SyncInProgress`] if a sync holds the lockfile and
/// [`FfiVaultError::SyncFailed`] if the state file cannot be deleted. On any
/// error the state file is left as it was.
pub fn reset_sync_state_and_open_with_password(
    folder: &Path,
    password: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    reset_sync_state_and_open_with_password_in(&default_state_dir_or_err()?, folder, password)
}

/// Explicit-`state_dir` form of [`reset_sync_state_and_open_with_password`],
/// for callers that pass their sync-state dir to every sync call (the uniffi
/// surface) and for tests.
pub fn reset_sync_state_and_open_with_password_in(
    state_dir: &Path,
    folder: &Path,
    password: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Password(&pw), None)?;
    let vault_uuid = core_out.manifest.vault_uuid;
    let _guard = LockfileGuard::acquire(state_dir, vault_uuid).map_err(map_state_error)?;
    delete(state_dir, vault_uuid).map_err(map_state_error)?;
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::orchestration::enforce_rollback_resistance_in;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use secretary_cli::state::{save, state_file_path};
    use secretary_core::crypto::kdf::Argon2idParams;
    use secretary_core::sync::SyncState;
    use secretary_core::vault::{create_vault, open_vault, VectorClockEntry};

    const PASSWORD: &[u8] = b"correct horse battery";

    /// A vault in `dir` plus a saved state in `state_dir` whose clock strictly
    /// dominates its manifest: the pre-#730 poisoned device. Returns the
    /// vault uuid.
    fn poisoned(dir: &Path, state_dir: &Path) -> [u8; 16] {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let pw = SecretBytes::new(PASSWORD.to_vec());
        create_vault(dir, &pw, "T", Argon2idParams::new(65536, 1, 1), 0, &mut rng).unwrap();
        let open = open_vault(dir, Unlocker::Password(&pw), None).unwrap();
        let mut ahead: Vec<VectorClockEntry> = open.manifest.vector_clock.clone();
        ahead.push(VectorClockEntry {
            device_uuid: [0xee; 16],
            counter: 1,
        });
        ahead.sort_by_key(|e| e.device_uuid);
        let uuid = open.manifest.vault_uuid;
        save(state_dir, &SyncState::new(uuid, ahead).unwrap()).unwrap();
        assert!(matches!(
            enforce_rollback_resistance_in(state_dir, &open),
            Err(FfiVaultError::RollbackDetected)
        ));
        uuid
    }

    #[test]
    fn reset_recovers_a_device_whose_baseline_dominates_the_disk() {
        let vault = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let uuid = poisoned(vault.path(), state.path());

        let out = reset_sync_state_and_open_with_password_in(state.path(), vault.path(), PASSWORD)
            .expect("reset opens");
        assert_eq!(out.manifest.vault_uuid(), uuid.to_vec());
        assert!(!state_file_path(state.path(), uuid).exists());

        // The next ordinary open's rollback check now passes.
        let pw = SecretBytes::new(PASSWORD.to_vec());
        let reopened = open_vault(vault.path(), Unlocker::Password(&pw), None).unwrap();
        assert!(enforce_rollback_resistance_in(state.path(), &reopened).is_ok());
    }

    #[test]
    fn a_wrong_password_leaves_the_state_file_alone() {
        let vault = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let uuid = poisoned(vault.path(), state.path());

        let err = reset_sync_state_and_open_with_password_in(state.path(), vault.path(), b"nope")
            .unwrap_err();
        assert!(
            matches!(err, FfiVaultError::WrongPasswordOrCorrupt),
            "got {err:?}"
        );
        assert!(state_file_path(state.path(), uuid).exists());
    }

    #[test]
    fn a_held_lockfile_leaves_the_state_file_alone() {
        let vault = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let uuid = poisoned(vault.path(), state.path());
        let _held = LockfileGuard::acquire(state.path(), uuid).unwrap();

        let err = reset_sync_state_and_open_with_password_in(state.path(), vault.path(), PASSWORD)
            .unwrap_err();
        assert!(matches!(err, FfiVaultError::SyncInProgress), "got {err:?}");
        assert!(state_file_path(state.path(), uuid).exists());
    }
}
