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

use secretary_core::sync::__test_dispatch;
use secretary_core::sync::{RollbackEvidence, SyncOutcome};
use secretary_core::vault::block::VectorClockEntry;

fn entry(b: u8, c: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid: [b; 16],
        counter: c,
    }
}

#[test]
fn dispatch_equal_clocks_yields_nothing_to_do() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 5)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap();
    assert_eq!(outcome, SyncOutcome::NothingToDo);
}

#[test]
fn dispatch_disk_strictly_ahead_yields_applied_automatically() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 5)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 7)], &state).unwrap();
    match outcome {
        SyncOutcome::AppliedAutomatically { new_state } => {
            assert_eq!(new_state.vault_uuid, [0x42; 16]);
            assert_eq!(new_state.highest_vector_clock_seen, vec![entry(1, 7)]);
        }
        other => panic!("expected AppliedAutomatically, got {other:?}"),
    }
}

#[test]
fn dispatch_disk_strictly_behind_yields_rollback_rejected() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 9)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap();
    match outcome {
        SyncOutcome::RollbackRejected(RollbackEvidence {
            disk_vector_clock,
            local_highest_seen,
        }) => {
            assert_eq!(disk_vector_clock, vec![entry(1, 5)]);
            assert_eq!(local_highest_seen, vec![entry(1, 9)]);
        }
        other => panic!("expected RollbackRejected, got {other:?}"),
    }
}

#[test]
fn dispatch_concurrent_clocks_yields_fork_detected() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 5), entry(2, 3)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 3), entry(2, 5)], &state).unwrap();
    match outcome {
        SyncOutcome::ForkDetected {
            disk_vector_clock,
            local_highest_seen,
        } => {
            assert_eq!(disk_vector_clock, vec![entry(1, 3), entry(2, 5)]);
            assert_eq!(local_highest_seen, vec![entry(1, 5), entry(2, 3)]);
        }
        other => panic!("expected ForkDetected, got {other:?}"),
    }
}

#[test]
fn dispatch_empty_state_disk_present_yields_applied_automatically() {
    let state = SyncState::empty([0x42; 16]);
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap();
    assert!(matches!(outcome, SyncOutcome::AppliedAutomatically { .. }));
}

#[test]
fn dispatch_both_empty_yields_nothing_to_do() {
    let state = SyncState::empty([0x42; 16]);
    let outcome = __test_dispatch(vec![], &state).unwrap();
    assert_eq!(outcome, SyncOutcome::NothingToDo);
}

mod sync_helpers;

#[test]
fn sync_once_empty_state_accepts_golden_disk() {
    let folder = std::path::Path::new("tests/data/golden_vault_001");
    let password = fixtures::golden_vault_001_password();
    let identity = {
        let vt = std::fs::read(folder.join("vault.toml")).unwrap();
        let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
        open_with_password(&vt, &bundle, &password).unwrap()
    };
    let golden_vault_uuid = extract_golden_vault_uuid();
    let state = SyncState::empty(golden_vault_uuid);

    let outcome = sync_once(folder, &identity, &state, 0u64).unwrap();
    assert!(matches!(outcome, SyncOutcome::AppliedAutomatically { .. }));
}

#[test]
fn sync_once_unchanged_disk_after_apply_yields_nothing_to_do() {
    let folder = std::path::Path::new("tests/data/golden_vault_001");
    let password = fixtures::golden_vault_001_password();
    let identity = {
        let vt = std::fs::read(folder.join("vault.toml")).unwrap();
        let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
        open_with_password(&vt, &bundle, &password).unwrap()
    };
    let golden_vault_uuid = extract_golden_vault_uuid();
    let initial = SyncState::empty(golden_vault_uuid);
    let first = sync_once(folder, &identity, &initial, 0u64).unwrap();
    let new_state = match first {
        SyncOutcome::AppliedAutomatically { new_state } => new_state,
        other => panic!("first run must be AppliedAutomatically, got {other:?}"),
    };
    let second = sync_once(folder, &identity, &new_state, 0u64).unwrap();
    assert_eq!(second, SyncOutcome::NothingToDo);
}

#[test]
fn sync_once_disk_strictly_behind_rejects_rollback() {
    use sync_helpers::fresh_vault_with_clock;
    let (folder, _tmp) = fresh_vault_with_clock(vec![entry(1, 1)]);

    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vt, &bundle, &password).unwrap();

    let golden_vault_uuid = extract_golden_vault_uuid();
    // State is at counter=9 for device 1; disk we just rewrote is at 1.
    let state = SyncState::new(golden_vault_uuid, vec![entry(1, 9)]).unwrap();
    let outcome = sync_once(&folder, &identity, &state, 0u64).unwrap();
    assert!(matches!(outcome, SyncOutcome::RollbackRejected(_)));
}

#[test]
fn sync_once_concurrent_disk_detects_fork() {
    use sync_helpers::fresh_vault_with_clock;
    // Disk has device 2 only; state has device 1 only → concurrent.
    let (folder, _tmp) = fresh_vault_with_clock(vec![entry(2, 5)]);

    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vt, &bundle, &password).unwrap();

    let golden_vault_uuid = extract_golden_vault_uuid();
    let state = SyncState::new(golden_vault_uuid, vec![entry(1, 7)]).unwrap();
    let outcome = sync_once(&folder, &identity, &state, 0u64).unwrap();
    assert!(matches!(outcome, SyncOutcome::ForkDetected { .. }));
}

/// Helper: extract the golden vault's vault_uuid from its vault.toml
/// so we don't hard-code the value here — it's pinned in the fixture
/// builder and any drift would surface as a vault.toml decode failure.
fn extract_golden_vault_uuid() -> [u8; 16] {
    let s = std::fs::read_to_string("tests/data/golden_vault_001/vault.toml").unwrap();
    let vt = secretary_core::unlock::vault_toml::decode(&s).unwrap();
    vt.vault_uuid
}

#[test]
fn sync_once_missing_vault_toml_yields_io_error() {
    let tmp = tempfile::tempdir().unwrap();
    // No vault.toml in tmp.path() — should fire Io.
    let password = fixtures::golden_vault_001_password();
    let identity = {
        let vt = std::fs::read("tests/data/golden_vault_001/vault.toml").unwrap();
        let bundle = std::fs::read("tests/data/golden_vault_001/identity.bundle.enc").unwrap();
        open_with_password(&vt, &bundle, &password).unwrap()
    };
    let state = SyncState::empty([0u8; 16]);
    let err = sync_once(tmp.path(), &identity, &state, 0u64).unwrap_err();
    assert!(matches!(err, SyncError::Io { .. }));
    if let SyncError::Io { context, .. } = err {
        assert_eq!(context, "failed to read vault.toml");
    }
}

#[test]
fn sync_once_corrupted_manifest_yields_vault_error() {
    use sync_helpers::fresh_vault_with_clock;
    let (folder, _tmp) = fresh_vault_with_clock(vec![entry(1, 5)]);

    // Flip a byte in the middle of the manifest to corrupt it.
    let manifest_path = folder.join("manifest.cbor.enc");
    let mut manifest_bytes = std::fs::read(&manifest_path).unwrap();
    let mid = manifest_bytes.len() / 2;
    manifest_bytes[mid] ^= 0xFF;
    std::fs::write(&manifest_path, &manifest_bytes).unwrap();

    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read("tests/data/golden_vault_001/vault.toml").unwrap();
    let bundle = std::fs::read("tests/data/golden_vault_001/identity.bundle.enc").unwrap();
    let identity = open_with_password(&vt, &bundle, &password).unwrap();

    let state = SyncState::empty(extract_golden_vault_uuid());
    let err = sync_once(&folder, &identity, &state, 0u64).unwrap_err();
    assert!(matches!(err, SyncError::Vault(_)));
}
