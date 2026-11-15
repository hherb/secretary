//! `sync_now` forwards the session's per-vault device UUID as the merging
//! device (#749).
//!
//! The bridge pins that its session entry point ticks whatever UUID it is
//! given (`a_silent_merge_ticks_the_callers_device_uuid`). This pins the
//! desktop half: the UUID handed over is the one this device's writes use,
//! read here from the per-vault device file rather than from the session, so
//! a wrong field in `commands/sync.rs` cannot agree with itself.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncState;
use secretary_core::vault::{open_vault, Unlocker, VectorClockEntry};
use secretary_desktop::commands::{edit, sync, unlock};
use secretary_desktop::dtos::SyncOutcomeDto;
use secretary_desktop::path_auth::{canonicalize_for_auth, PathPurpose};
use secretary_desktop::session::VaultSession;
use secretary_desktop::settings::load_or_create_device_uuid_in;
use tempfile::TempDir;

/// The merge tick a device that never wrote to this vault receives.
const FIRST_TICK: u64 = 1;

/// Counter of the seeded entry; any value works, it only has to exist.
const SEEDED_COUNTER: u64 = 2;

fn golden_vault_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop/")
        .parent()
        .expect("workspace root")
        .join("core/tests/data/golden_vault_001")
}

fn password() -> SecretBytes {
    SecretBytes::new(secretary_test_utils::golden_vault_001_password())
}

/// A password-unlocked session over `vault`, plus its device-data dir.
fn unlocked_over(vault: &Path) -> (Mutex<VaultSession>, TempDir) {
    let device_dir = tempfile::tempdir().expect("device tempdir");
    let state = Mutex::new(VaultSession::new(device_dir.path().to_path_buf()));
    state.lock().unwrap().approve_path(
        PathPurpose::VaultFolder,
        canonicalize_for_auth(vault).unwrap(),
    );
    unlock::unlock_with_password_impl(
        &state,
        vault.to_str().unwrap(),
        &secretary_test_utils::golden_vault_001_password(),
    )
    .expect("unlock");
    (state, device_dir)
}

#[test]
fn a_silent_merge_ticks_the_sessions_own_device_uuid() {
    let vault_dir = secretary_test_utils::copy_dir_to_tempdir(&golden_vault_path());
    let vault = vault_dir.path();
    let state_dir = tempfile::tempdir().unwrap();
    let (a, a_device_dir) = unlocked_over(vault);
    let (b, _b_device_dir) = unlocked_over(vault);
    edit::create_block_impl(&b, "Other").expect("b writes");

    // A baseline concurrent with the disk: one entry the disk has never seen.
    let before = open_vault(vault, Unlocker::Password(&password()), None).expect("open");
    let vault_uuid = before.manifest.vault_uuid;
    let seeded = vec![VectorClockEntry {
        device_uuid: rand::random(),
        counter: SEEDED_COUNTER,
    }];
    secretary_cli::state::save(
        state_dir.path(),
        &SyncState::new(vault_uuid, seeded).unwrap(),
    )
    .expect("seed state");

    let outcome = sync::sync_now_in_impl(&a, state_dir.path(), 1).expect("sync");
    assert!(
        matches!(outcome, SyncOutcomeDto::SilentMerge),
        "{outcome:?}"
    );

    let a_device = load_or_create_device_uuid_in(a_device_dir.path(), &vault_uuid)
        .expect("a's device file exists after unlock");
    let disk = open_vault(vault, Unlocker::Password(&password()), None).expect("reopen");
    let want = VectorClockEntry {
        device_uuid: a_device,
        counter: FIRST_TICK,
    };
    assert!(
        disk.manifest.vector_clock.contains(&want),
        "disk clock {:?} lacks {want:?}",
        disk.manifest.vector_clock
    );
}
