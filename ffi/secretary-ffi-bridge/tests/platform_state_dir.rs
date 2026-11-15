//! #746: `set_platform_state_dir` reaches the open-time rollback check, and
//! the reset recovers a device whose saved baseline dominates the disk.
//!
//! Its own test binary, because the override is set once per process.
//! Android needs the override: before it, the open check read
//! `dirs::data_dir()`, a directory the Android app never writes, so §10 was
//! inactive at open there.

use secretary_cli::state::{load, save};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncState;
use secretary_core::vault::{open_vault, Unlocker, VectorClockEntry};
use secretary_ffi_bridge::{
    open_vault_with_password, reset_sync_state_and_open_with_password, set_platform_state_dir,
    FfiVaultError,
};
use secretary_test_utils::{copy_dir_to_tempdir, core_test_data_dir, golden_vault_001_password};

#[test]
fn the_override_reaches_the_open_check_and_the_reset_recovers() {
    let state = tempfile::tempdir().unwrap();
    set_platform_state_dir(state.path()).expect("first set");
    set_platform_state_dir(state.path()).expect("same path again is a no-op");
    let other = tempfile::tempdir().unwrap();
    assert!(matches!(
        set_platform_state_dir(other.path()),
        Err(FfiVaultError::SyncFailed { .. })
    ));

    let vault = copy_dir_to_tempdir(&core_test_data_dir().join("golden_vault_001"));
    let password = golden_vault_001_password();
    open_vault_with_password(vault.path(), &password).expect("never synced: opens");

    // Poison: a saved baseline one device-entry ahead of the disk.
    let pw = SecretBytes::new(password.to_vec());
    let core = open_vault(vault.path(), Unlocker::Password(&pw), None).unwrap();
    let mut ahead = core.manifest.vector_clock.clone();
    ahead.push(VectorClockEntry {
        device_uuid: [0xee; 16],
        counter: 1,
    });
    ahead.sort_by_key(|e| e.device_uuid);
    let uuid = core.manifest.vault_uuid;
    save(state.path(), &SyncState::new(uuid, ahead).unwrap()).unwrap();

    let err = open_vault_with_password(vault.path(), &password).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::RollbackDetected),
        "the open check must read the overridden dir, got {err:?}"
    );

    reset_sync_state_and_open_with_password(vault.path(), &password).expect("reset opens");
    assert_eq!(
        load(state.path(), uuid).unwrap().highest_vector_clock_seen,
        core.manifest.vector_clock,
        "the reset re-arms the baseline at the verified clock"
    );
    open_vault_with_password(vault.path(), &password).expect("opens after the reset");
}
