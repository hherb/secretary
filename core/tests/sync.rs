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
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap().unwrap();
    assert_eq!(outcome, SyncOutcome::NothingToDo);
}

#[test]
fn dispatch_disk_strictly_ahead_yields_applied_automatically() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 5)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 7)], &state).unwrap().unwrap();
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
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap().unwrap();
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
fn dispatch_concurrent_clocks_signals_none() {
    // The clock-only dispatch helper returns None on Concurrent;
    // the integration test below (sync_once_concurrent_disk_yields_concurrent_detected)
    // exercises the bundle-carrying ConcurrentDetected variant
    // through the real sync_once + folder I/O path.
    let state = SyncState::new([0x42; 16], vec![entry(1, 5), entry(2, 3)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 3), entry(2, 5)], &state).unwrap();
    assert!(
        outcome.is_none(),
        "clock-only dispatch must return None on Concurrent, got {outcome:?}"
    );
}

#[test]
fn dispatch_empty_state_disk_present_yields_applied_automatically() {
    let state = SyncState::empty([0x42; 16]);
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap().unwrap();
    assert!(matches!(outcome, SyncOutcome::AppliedAutomatically { .. }));
}

#[test]
fn dispatch_both_empty_yields_nothing_to_do() {
    let state = SyncState::empty([0x42; 16]);
    let outcome = __test_dispatch(vec![], &state).unwrap().unwrap();
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
fn sync_once_concurrent_disk_yields_concurrent_detected() {
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
    match outcome {
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            disk_vector_clock,
            local_highest_seen,
            ..
        } => {
            // Golden vault has no sibling files; bundle.copies must be empty.
            assert!(
                bundle.copies.is_empty(),
                "no sibling manifests expected in golden_vault_001"
            );
            // No diverging blocks since no conflict-copy manifests exist
            // to disagree with the canonical on any block.
            assert!(
                plan.diverging_blocks.is_empty(),
                "no diverging blocks expected without conflict-copies"
            );
            assert_eq!(disk_vector_clock, vec![entry(2, 5)]);
            assert_eq!(local_highest_seen, vec![entry(1, 7)]);
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_manifest_hash_matches_bundle_envelope_bytes() {
    // Regression test for #80: the `manifest_hash` carried in
    // `ConcurrentDetected` must be the BLAKE3 of the SAME envelope
    // bytes carried in `bundle.canonical.raw_envelope_bytes`.
    //
    // Before the #80 fix, sync_once performed two reads of
    // `manifest.cbor.enc` — one inside `read_vault_manifest_full` for
    // verify+decrypt, and a second `std::fs::read` to feed the hash +
    // the bundle. A concurrent writer between the two reads would
    // leave the bundle carrying inconsistent data (body authenticated
    // from read 1; bytes-and-hash from read 2). After the fix, a
    // single read feeds verify+decrypt, hash, and bundle — so the
    // bundle bytes ALWAYS round-trip to the manifest_hash.
    //
    // The assertion below documents the invariant. In quiet test envs
    // it would pass even pre-fix (both reads return identical bytes),
    // so this test is a contract / regression guard rather than a
    // race demonstrator — the architectural fix (single read) is what
    // makes the invariant hold under concurrent writers.
    use secretary_core::sync::bundle::compute_manifest_hash;
    use sync_helpers::fresh_vault_with_clock;

    let (folder, _tmp) = fresh_vault_with_clock(vec![entry(2, 5)]);

    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle_bytes = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vt, &bundle_bytes, &password).unwrap();

    let golden_vault_uuid = extract_golden_vault_uuid();
    let state = SyncState::new(golden_vault_uuid, vec![entry(1, 7)]).unwrap();
    let outcome = sync_once(&folder, &identity, &state, 0u64).unwrap();

    match outcome {
        SyncOutcome::ConcurrentDetected {
            bundle,
            manifest_hash,
            ..
        } => {
            let recomputed = compute_manifest_hash(&bundle.canonical.raw_envelope_bytes);
            assert_eq!(
                recomputed, manifest_hash,
                "ConcurrentDetected.manifest_hash must equal BLAKE3 of bundle.canonical.raw_envelope_bytes — single-read invariant from #80 fix"
            );

            // Sanity: the bytes carried in the bundle ARE the on-disk
            // envelope bytes (i.e., they came from a real read of the
            // manifest file, not from re-encoding the decoded body).
            let on_disk = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
            assert_eq!(
                bundle.canonical.raw_envelope_bytes, on_disk,
                "bundle.canonical.raw_envelope_bytes must equal the on-disk manifest.cbor.enc bytes"
            );
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
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
    // No vault.toml in tmp.path() — should fire VaultError::Io (forwarded
    // through SyncError::Vault) since read_vault_manifest is the first I/O
    // path now that the redundant pre-read was removed.
    let password = fixtures::golden_vault_001_password();
    let identity = {
        let vt = std::fs::read("tests/data/golden_vault_001/vault.toml").unwrap();
        let bundle = std::fs::read("tests/data/golden_vault_001/identity.bundle.enc").unwrap();
        open_with_password(&vt, &bundle, &password).unwrap()
    };
    let state = SyncState::empty([0u8; 16]);
    let err = sync_once(tmp.path(), &identity, &state, 0u64).unwrap_err();
    match err {
        SyncError::Vault(secretary_core::vault::VaultError::Io { context, .. }) => {
            assert_eq!(context, "failed to read vault.toml");
        }
        other => panic!("expected SyncError::Vault(VaultError::Io), got {other:?}"),
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
