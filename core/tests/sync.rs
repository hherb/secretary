//! Integration tests for `core::sync::sync_once`.

#![forbid(unsafe_code)]

use secretary_core::sync::{sync_once, SyncError, SyncState};
use secretary_core::unlock::open_with_password;

mod fixtures;

#[test]
fn sync_once_wrong_vault_uuid_typed_error() {
    // Build a SyncState bound to a different vault_uuid than golden_vault_001's.
    let folder = std::path::Path::new("tests/data/golden_vault_001");
    let password = fixtures::golden_vault_001_password();
    let vault_toml = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vault_toml, &bundle, &password).unwrap();

    let wrong_state = SyncState::empty([0xDE; 16]);
    let err = sync_once(folder, &identity, &wrong_state, 0u64).unwrap_err();
    assert!(matches!(err, SyncError::VaultUuidMismatch { .. }));
}
