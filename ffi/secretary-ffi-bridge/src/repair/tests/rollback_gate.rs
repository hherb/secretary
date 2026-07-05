//! §10 pre-write rollback-gate posture (#384) on the mutating repair
//! arms: a dominated committed clock, and an existing-but-unreadable or
//! uuid-mismatched baseline store, must refuse before any manifest write.

use super::*;

/// Case 5 (#374 regression): the §10 rollback-resistance gate must run
/// BEFORE the repair write, on the COMMITTED manifest clock — not after the
/// adopt-and-tick, where the local tick would flip a strictly-dominated
/// (rollback) clock into an unflagged "concurrent" one and mask it
/// permanently. Stage genuine adoptable crash residue (a crashed save), seed a
/// §10 baseline (via a temp state dir injected through the `_in` seam) that
/// strictly dominates the committed clock — ahead on a FOREIGN device the
/// repair tick never touches — then assert repair REFUSES with `CorruptVault`
/// (core `VaultError::Rollback` folds to `CorruptVault`) and leaves the
/// on-disk manifest byte-for-byte unchanged (refuse-without-mutation — the
/// crux). Before the fix (baseline passed as `None`, §10 checked only on the
/// post-tick clock) this residue was silently adopted and the manifest
/// rewritten.
#[test]
fn repair_gates_rollback_before_write_and_leaves_manifest_untouched() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x96; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe5; 16], [0xf5; 16]);

    // v1 committed, v2 block on disk, manifest rolled back to v1; the
    // staging snapshots the committed clock + vault_uuid for the §10
    // baseline seed below.
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);
    let committed_clock = staged.committed_clock;
    let vault_uuid = staged.vault_uuid;

    // Sanity: this residue is GENUINELY adoptable — without a rollback
    // baseline the plain open flags the actionable VaultNeedsRepair (i.e. the
    // refusal below is caused by the §10 gate, not by unrelated corruption).
    assert!(
        matches!(
            open_vault_with_password(&folder, &pw),
            Err(FfiVaultError::VaultNeedsRepair { .. })
        ),
        "residue must be adoptable crash residue, not pre-existing corruption",
    );

    // Seed a §10 baseline that strictly DOMINATES the committed clock: every
    // committed entry verbatim (so the committed clock is never strictly
    // greater anywhere) plus a FOREIGN device ahead (so it is strictly less
    // there) → is_rollback(committed) == true. The foreign device is NOT the
    // one repair ticks — proving the gate fires on the pre-tick committed
    // clock, independent of the adopt-and-tick that would otherwise mask it.
    let foreign = [0x0f; 16];
    assert!(
        !committed_clock.iter().any(|e| e.device_uuid == foreign),
        "foreign device_uuid must be disjoint from the committed clock",
    );
    let mut baseline = committed_clock.clone();
    baseline.push(VectorClockEntry {
        device_uuid: foreign,
        counter: 1,
    });
    baseline.sort_by_key(|e| e.device_uuid);
    let synced = secretary_core::sync::SyncState::new(vault_uuid, baseline).unwrap();
    secretary_cli::state::save(state_dir.path(), &synced).unwrap();

    // Snapshot the on-disk manifest immediately before the repair attempt.
    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err = repair_vault_with_password_in(
        Some(state_dir.path()),
        &folder,
        &pw,
        &device_uuid,
        3_000,
        &[],
    )
    .expect_err("a strictly-dominated committed clock must refuse repair PRE-write");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "core VaultError::Rollback must fold to CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest (pre-write gate — the crux)",
    );
}

/// Case 6 (#374 follow-up): the same pre-write §10 rollback gate, proven
/// end-to-end for the DEVICE-SECRET arm. Mirrors
/// `repair_gates_rollback_before_write_and_leaves_manifest_untouched` (Case
/// 5, password arm) exactly, but enrolls a device slot and stages/repairs
/// through the device-secret unlock path — closing the coverage gap where
/// the pre-write gate was previously proven end-to-end only for password.
#[test]
fn repair_device_secret_gates_rollback_before_write_and_leaves_manifest_untouched() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0x97; 32]);

    // Enroll a fresh device slot via the bridge projection.
    let enrolled = add_device_slot(&folder, &pw).expect("add_device_slot must succeed");
    let device_uuid: [u8; 16] = enrolled
        .device_uuid
        .as_slice()
        .try_into()
        .expect("device_uuid must be 16 bytes");
    let device_secret_bytes = enrolled
        .device_secret
        .take_secret()
        .expect("first take_secret must return Some");
    let device_secret: [u8; 32] = device_secret_bytes
        .as_slice()
        .try_into()
        .expect("device secret must be 32 bytes");

    // Stage crash residue under this device's own unlock path.
    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf6; 16];

    // v1 committed, v2 block on disk, manifest rolled back to v1; the
    // staging snapshots the committed clock + vault_uuid for the §10
    // baseline seed below.
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);
    let committed_clock = staged.committed_clock;
    let vault_uuid = staged.vault_uuid;

    // Sanity: this residue is GENUINELY adoptable — without a rollback
    // baseline the plain device-secret open flags the actionable
    // VaultNeedsRepair (i.e. the refusal below is caused by the §10 gate,
    // not by unrelated corruption).
    assert!(
        matches!(
            open_with_device_secret(&folder, &device_uuid, &device_secret),
            Err(FfiVaultError::VaultNeedsRepair { .. })
        ),
        "residue must be adoptable crash residue, not pre-existing corruption",
    );

    // Seed a §10 baseline that strictly DOMINATES the committed clock: every
    // committed entry verbatim (so the committed clock is never strictly
    // greater anywhere) plus a FOREIGN device ahead (so it is strictly less
    // there) → is_rollback(committed) == true. The foreign device is NOT the
    // one repair ticks — proving the gate fires on the pre-tick committed
    // clock, independent of the adopt-and-tick that would otherwise mask it.
    let foreign = [0x1f; 16];
    assert!(
        !committed_clock.iter().any(|e| e.device_uuid == foreign),
        "foreign device_uuid must be disjoint from the committed clock",
    );
    let mut baseline = committed_clock.clone();
    baseline.push(VectorClockEntry {
        device_uuid: foreign,
        counter: 1,
    });
    baseline.sort_by_key(|e| e.device_uuid);
    let synced = secretary_core::sync::SyncState::new(vault_uuid, baseline).unwrap();
    secretary_cli::state::save(state_dir.path(), &synced).unwrap();

    // Snapshot the on-disk manifest immediately before the repair attempt.
    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err = repair_vault_with_device_secret_in(
        Some(state_dir.path()),
        &folder,
        &device_uuid,
        &device_secret,
        3_000,
        &[],
    )
    .expect_err("a strictly-dominated committed clock must refuse repair PRE-write");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "core VaultError::Rollback must fold to CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest (pre-write gate — the crux)",
    );
}

/// #384 posture (password arm): an EXISTING but unreadable/undecodable
/// §10 baseline state file must refuse the MUTATING repair fail-closed —
/// a skipped check here would let adoption tick + re-sign the manifest,
/// permanently laundering a rolled-back clock. The refusal surfaces as
/// `CorruptVault` whose detail names the state file and the documented
/// remedy (delete it = the crypto-design §10 reset); the manifest must be
/// byte-for-byte untouched. Missing-file/never-synced keeps adopting
/// (Cases 1/2 pin that branch).
#[test]
fn repair_refuses_unreadable_rollback_baseline_and_leaves_manifest_untouched() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x98; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe7; 16], [0xf7; 16]);

    // Stage genuine adoptable crash residue (crashed save, v2 on disk).
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // Sanity: adoptable residue, not pre-existing corruption.
    assert!(
        matches!(
            open_vault_with_password(&folder, &pw),
            Err(FfiVaultError::VaultNeedsRepair { .. })
        ),
        "residue must be adoptable crash residue",
    );

    // A PRESENT but garbage state file at the exact path load() reads.
    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let err = repair_vault_with_password_in(
        Some(state_dir.path()),
        &folder,
        &pw,
        &device_uuid,
        3_000,
        &[],
    )
    .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.contains("rollback baseline"),
                "detail must name the failing store: {detail}"
            );
            assert!(
                detail.contains("resets this device's rollback history"),
                "detail must carry the documented remedy: {detail}"
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture (device-secret arm): same contract as the password-arm
/// test above, proven end-to-end through the device-secret unlock path
/// (arm parity — mirrors how Case 5/6 pin the rollback gate on both arms).
#[test]
fn repair_device_secret_refuses_unreadable_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0x99; 32]);

    let enrolled = add_device_slot(&folder, &pw).expect("add_device_slot must succeed");
    let device_uuid: [u8; 16] = enrolled
        .device_uuid
        .as_slice()
        .try_into()
        .expect("device_uuid must be 16 bytes");
    let device_secret_bytes = enrolled
        .device_secret
        .take_secret()
        .expect("first take_secret must return Some");
    let device_secret: [u8; 32] = device_secret_bytes
        .as_slice()
        .try_into()
        .expect("device secret must be 32 bytes");

    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf8; 16];
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let err = repair_vault_with_device_secret_in(
        Some(state_dir.path()),
        &folder,
        &device_uuid,
        &device_secret,
        3_000,
        &[],
    )
    .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture (recovery arm): same fail-closed contract as the
/// password-arm test above, proven end-to-end through the mnemonic
/// unlock path — completing arm parity across all three repair arms so
/// a future edit cannot swap this arm's provider for a fail-open one
/// and ship green (the other two arms' tests would stay green).
#[test]
fn repair_recovery_refuses_unreadable_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9b; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xea; 16], [0xfa; 16]);
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // A PRESENT but garbage state file at the exact path load() reads.
    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let err = repair_vault_with_recovery_in(
        Some(state_dir.path()),
        &folder,
        VAULT_001_PHRASE,
        &device_uuid,
        3_000,
        &[],
    )
    .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture: a validly-encoded SyncState whose INTERNAL vault_uuid
/// differs from the file's path key (`StateError::VaultUuidMismatch`) is
/// "present but not usable" — same fail-closed refusal as garbage bytes,
/// NOT a silent skip (a skip would let a planted/mislabelled state file
/// neutralize §10 on the mutating path).
#[test]
fn repair_refuses_uuid_mismatched_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9a; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe9; 16], [0xf9; 16]);
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // A validly-encoded SyncState under a DIFFERENT internal uuid, planted
    // at the path keyed by the real vault uuid.
    let other_uuid = [0x5a; 16];
    assert_ne!(other_uuid, staged.vault_uuid);
    let clock = vec![VectorClockEntry {
        device_uuid: [0x0e; 16],
        counter: 1,
    }];
    let mismatched = secretary_core::sync::SyncState::new(other_uuid, clock).unwrap();
    secretary_cli::state::save(state_dir.path(), &mismatched).unwrap();
    std::fs::rename(
        secretary_cli::state::state_file_path(state_dir.path(), other_uuid),
        secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid),
    )
    .unwrap();

    let err = repair_vault_with_password_in(
        Some(state_dir.path()),
        &folder,
        &pw,
        &device_uuid,
        3_000,
        &[],
    )
    .expect_err("uuid-mismatched baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_v1,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}
