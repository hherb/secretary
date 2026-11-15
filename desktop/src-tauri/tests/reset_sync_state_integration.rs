//! Integration tests for the `reset_sync_state_and_unlock` command (#746).
//!
//! A device whose saved §10 baseline strictly dominates the vault on disk has
//! its ordinary open refused (`rollback_detected`). The reset command is the
//! user-confirmed recovery: a full password open, then this vault's sync-state
//! file is deleted. Each test drives the explicit-state-dir core against an
//! ephemeral copy of the golden vault and a `TempDir` state dir, so nothing
//! touches the user's real sync-state directory.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncState;
use secretary_core::vault::{open_vault, Unlocker, VectorClockEntry};
use secretary_desktop::commands::unlock;
use secretary_desktop::errors::AppError;
use secretary_desktop::path_auth::{canonicalize_for_auth, PathPurpose};
use secretary_desktop::session::VaultSession;
use tempfile::TempDir;

/// A device the golden vault's clock has never seen; its entry is what makes
/// the seeded baseline strictly dominate the disk.
const UNSEEN_DEVICE: [u8; 16] = [0xee; 16];

fn golden_vault_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop/")
        .parent()
        .expect("workspace root")
        .join("core/tests/data/golden_vault_001")
}

/// A locked session with `vault` approved, as a `pick_vault_folder` would.
fn approved_state(vault: &Path) -> (Mutex<VaultSession>, TempDir) {
    let device_dir = tempfile::tempdir().expect("device tempdir");
    let state = Mutex::new(VaultSession::new(device_dir.path().to_path_buf()));
    state.lock().unwrap().approve_path(
        PathPurpose::VaultFolder,
        canonicalize_for_auth(vault).unwrap(),
    );
    (state, device_dir)
}

/// Seed `state_dir` with a baseline that strictly dominates `vault`'s disk
/// clock (the pre-#730 poisoned device). Returns the state file's path.
fn poison(state_dir: &Path, vault: &Path) -> PathBuf {
    let pw = SecretBytes::new(secretary_test_utils::golden_vault_001_password());
    let open = open_vault(vault, Unlocker::Password(&pw), None).expect("open golden copy");
    let mut ahead = open.manifest.vector_clock.clone();
    ahead.push(VectorClockEntry {
        device_uuid: UNSEEN_DEVICE,
        counter: 1,
    });
    ahead.sort_by_key(|e| e.device_uuid);
    let uuid = open.manifest.vault_uuid;
    secretary_cli::state::save(state_dir, &SyncState::new(uuid, ahead).unwrap())
        .expect("seed state");
    let path = secretary_cli::state::state_file_path(state_dir, uuid);
    assert!(path.exists(), "seeded state file must exist");
    path
}

#[test]
fn reset_sync_state_and_unlock_opens_a_poisoned_vault_and_deletes_its_state() {
    let vault_dir = secretary_test_utils::copy_dir_to_tempdir(&golden_vault_path());
    let state_dir = tempfile::tempdir().unwrap();
    let state_file = poison(state_dir.path(), vault_dir.path());
    let (state, _dev) = approved_state(vault_dir.path());

    let dto = unlock::reset_sync_state_and_unlock_in_impl(
        &state,
        state_dir.path(),
        vault_dir.path().to_str().unwrap(),
        &secretary_test_utils::golden_vault_001_password(),
    )
    .expect("reset opens the vault");

    assert_eq!(dto.vault_uuid_hex.len(), 32);
    assert!(state.lock().unwrap().is_unlocked());
    assert!(!state_file.exists(), "the reset must delete the state file");
}

#[test]
fn reset_sync_state_and_unlock_with_a_wrong_password_leaves_the_state_file() {
    let vault_dir = secretary_test_utils::copy_dir_to_tempdir(&golden_vault_path());
    let state_dir = tempfile::tempdir().unwrap();
    let state_file = poison(state_dir.path(), vault_dir.path());
    let (state, _dev) = approved_state(vault_dir.path());

    let err = unlock::reset_sync_state_and_unlock_in_impl(
        &state,
        state_dir.path(),
        vault_dir.path().to_str().unwrap(),
        b"definitely not the password",
    )
    .expect_err("wrong password");

    assert!(matches!(err, AppError::WrongPassword), "got {err:?}");
    assert!(!state.lock().unwrap().is_unlocked());
    assert!(state_file.exists(), "a failed reset must change nothing");
}

#[test]
fn reset_sync_state_and_unlock_refuses_an_unapproved_folder() {
    let vault_dir = secretary_test_utils::copy_dir_to_tempdir(&golden_vault_path());
    let state_dir = tempfile::tempdir().unwrap();
    let state_file = poison(state_dir.path(), vault_dir.path());
    let device_dir = tempfile::tempdir().unwrap();
    let state = Mutex::new(VaultSession::new(device_dir.path().to_path_buf()));

    let err = unlock::reset_sync_state_and_unlock_in_impl(
        &state,
        state_dir.path(),
        vault_dir.path().to_str().unwrap(),
        &secretary_test_utils::golden_vault_001_password(),
    )
    .expect_err("unapproved folder");

    assert!(
        matches!(err, AppError::PathNotApproved { .. }),
        "got {err:?}"
    );
    assert!(state_file.exists());
}
