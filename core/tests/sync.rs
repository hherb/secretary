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
