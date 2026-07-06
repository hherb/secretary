//! #374 part 3: approvals on the three repair arms — exact-bound
//! happy adoption per unlock arm, stale-approval refusal, and the §10
//! pre-write gate winning over a valid approval.

use super::*;

/// Happy-adopt (password arm): an exact approval — bound to the on-disk
/// block file's own BLAKE3 fingerprint and the exact added-recipient set —
/// must adopt the crashed-`share_block` widening residue, and the vault
/// must reopen clean afterwards. Mirrors core's
/// `crash_recovery.rs::repair_adopts_crashed_share_with_matching_approval`.
#[test]
fn repair_with_password_adopts_with_exact_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9c; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xeb; 16], [0xfb; 16]);
    let card_c = mint_external_card(0x9d, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[approval])
        .expect("exact approval must adopt the crashed-share superset");
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(entry.recipient_uuids.len(), 2, "widened set committed");
    assert!(entry.recipient_uuids.contains(&staged.added_contact_uuid));
    drop(repaired);

    // Vault opens clean afterwards (residue fully adopted).
    open_vault_with_password(&folder, &pw).expect("post-repair open must succeed");
}

/// Happy-adopt (recovery arm): same contract as the password-arm test
/// above, proven end-to-end through the 24-word mnemonic unlock path —
/// arm parity for the consent-adoption path.
#[test]
fn repair_with_recovery_adopts_with_exact_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9e; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xec; 16], [0xfc; 16]);
    let card_c = mint_external_card(0x9f, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let repaired =
        repair_vault_with_recovery(&folder, VAULT_001_PHRASE, &device_uuid, 3_000, &[approval])
            .expect("exact approval must adopt the crashed-share superset via the recovery arm");
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(entry.recipient_uuids.len(), 2, "widened set committed");
    assert!(entry.recipient_uuids.contains(&staged.added_contact_uuid));
    drop(repaired);

    open_vault_with_password(&folder, &pw).expect("post-repair open must succeed");
}

/// Happy-adopt (device-secret arm): same contract, proven end-to-end
/// through a freshly-enrolled device slot — arm parity across all three
/// repair entry points.
#[test]
fn repair_with_device_secret_adopts_with_exact_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0xa0; 32]);

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
    let block_uuid = [0xfd; 16];
    let card_c = mint_external_card(0xa1, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let repaired =
        repair_vault_with_device_secret(&folder, &device_uuid, &device_secret, 3_000, &[approval])
            .expect(
                "exact approval must adopt the crashed-share superset via the device-secret arm",
            );
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(entry.recipient_uuids.len(), 2, "widened set committed");
    assert!(entry.recipient_uuids.contains(&staged.added_contact_uuid));
    drop(repaired);

    // Vault opens clean afterwards (residue fully adopted). Password reopen
    // is fine here — the assertion is about the on-disk state, not the arm
    // used to unlock it (mirrors the password/recovery siblings above).
    open_vault_with_password(&folder, &pw).expect("post-repair open must succeed");
}

/// Stale consent: an approval whose `file_fingerprint` no longer matches
/// the on-disk block bytes (the residue changed, or the approval was built
/// against a different preview) must be refused as
/// `FfiVaultError::RepairRejected`, and the manifest must be untouched.
/// Mirrors core's
/// `crash_recovery.rs::repair_rejects_approval_with_stale_fingerprint`.
#[test]
fn repair_refuses_stale_approval_as_repair_rejected() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xa4; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xee; 16], [0xfe; 16]);
    let card_c = mint_external_card(0xa5, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let mut stale_fingerprint = staged.file_fingerprint;
    stale_fingerprint[0] ^= 0x01; // consent bound to different bytes than on disk
    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: stale_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };
    let err = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[approval])
        .expect_err("stale consent must refuse");
    match err {
        FfiVaultError::RepairRejected {
            block_uuid_hex,
            detail,
        } => {
            assert_eq!(block_uuid_hex, format_uuid_hyphenated(&block_uuid));
            assert!(
                detail.contains("does not match the on-disk residue"),
                "must be the stale-consent rejection arm specifically: {detail}"
            );
        }
        other => panic!("expected RepairRejected, got {other:?}"),
    }
    // All-or-nothing: the manifest must be untouched by the rejected repair.
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_pre_share,
        "rejected repair must not touch the manifest"
    );
}

/// #374 part 3 / §10 regression: even with a VALID (exact-matching)
/// approval present, an existing-but-unreadable §10 rollback baseline
/// state file must still refuse the repair as `CorruptVault` — the
/// rollback gate runs strictly BEFORE any per-block classification/consent
/// decision (module docs: "§10 rollback resistance is gated PRE-write"),
/// so a valid approval must never let a laundered rollback baseline slip
/// through. Mirrors
/// `repair_refuses_unreadable_rollback_baseline_and_leaves_manifest_untouched`
/// but adds a matching approval to prove fail-closed §10 still wins.
#[test]
fn repair_refuses_unreadable_rollback_baseline_even_with_valid_approval() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xa2; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xef; 16], [0xff; 16]);
    let card_c = mint_external_card(0xa3, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let approval = FfiApprovedWidening {
        block_uuid,
        file_fingerprint: staged.file_fingerprint,
        added_recipients: vec![staged.added_contact_uuid],
    };

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
        &[approval],
    )
    .expect_err("§10 fail-closed must win even with a valid approval present");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        staged.manifest_pre_share,
        "refused repair must not mutate the manifest (fail-closed pre-write wins over consent)",
    );
}
