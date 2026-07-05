//! preview_repair arms (#374 Task 6): read-only widening reports with
//! display names + fingerprints, empty preview for plainly-adoptable
//! residue, and the fail-closed §10 baseline posture at preview time.

use super::*;

/// `preview_repair_with_password` on a crashed-`share_block` (recipient-
/// widening) residue must report exactly one `FfiWideningReport`: the
/// affected block's name and hyphenated UUID, a `file_fingerprint_hex`
/// that round-trips the on-disk BLAKE3-256 fingerprint (and is 64
/// lowercase hex chars), and the one added recipient's hyphenated UUID +
/// verified display name + a 32-hex-char card fingerprint. Being
/// read-only, it must not touch the manifest at all.
#[test]
fn preview_with_password_reports_widening() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xb0; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xb1; 16], [0xb2; 16]);
    let card_c = mint_external_card(0xb3, "Cee");
    let staged = stage_crashed_share(&folder, open, block_uuid, device_uuid, &card_c, &mut rng);

    let manifest_before_preview = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let preview = preview_repair_with_password(&folder, &pw)
        .expect("preview must succeed on consent-eligible widening residue");

    assert_eq!(preview.widenings.len(), 1, "exactly one widened block");
    let report = &preview.widenings[0];
    assert_eq!(report.block_uuid_hex, format_uuid_hyphenated(&block_uuid));
    assert_eq!(report.block_name, "mine");
    assert_eq!(
        report.file_fingerprint_hex.len(),
        64,
        "file_fingerprint_hex must be 64 lowercase hex chars (BLAKE3-256)"
    );
    assert_eq!(
        report.file_fingerprint_hex,
        hex::encode(staged.file_fingerprint),
        "file_fingerprint_hex must round-trip the on-disk BLAKE3 fingerprint"
    );
    assert_eq!(report.added.len(), 1, "exactly one added recipient");
    let added = &report.added[0];
    assert_eq!(
        added.uuid_hex,
        format_uuid_hyphenated(&staged.added_contact_uuid)
    );
    assert_eq!(added.display_name, "Cee");
    assert_eq!(
        added.card_fingerprint_hex.len(),
        32,
        "card_fingerprint_hex must be 32 lowercase hex chars (16-byte identity fingerprint)"
    );

    // Read-only: preview must not write anything, including the manifest.
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_before_preview,
        "preview_repair must not mutate the manifest"
    );
}

/// A crashed `save_block` (interrupted content save, not a widening) is
/// exactly what `repair_vault` adopts unconditionally — there is nothing
/// to consent to. `preview_repair_with_password` must report zero
/// widenings for it.
#[test]
fn preview_with_password_empty_for_crashed_save() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xb4; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xb5; 16], [0xb6; 16]);
    stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    let preview = preview_repair_with_password(&folder, &pw)
        .expect("preview must succeed on adoptable (non-widening) residue");
    assert!(
        preview.widenings.is_empty(),
        "a crashed content save is not a widening; preview must report zero widenings, got {:?}",
        preview.widenings
    );
}

/// §10 fail-closed posture (#384) applies identically at preview time
/// (module docs on `super::preview`): an existing-but-unreadable
/// rollback-baseline state file must refuse `preview_repair_with_password`
/// as `CorruptVault` whose detail names the failing state file — before
/// any consent dialog would even be drawn. Mirrors
/// `repair_refuses_unreadable_rollback_baseline_and_leaves_manifest_untouched`
/// but through the read-only preview arm.
#[test]
fn preview_fails_closed_on_garbage_baseline_state() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0xb7; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xb8; 16], [0xb9; 16]);
    let staged = stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // A PRESENT but garbage state file at the exact path load() reads.
    let state_path = secretary_cli::state::state_file_path(state_dir.path(), staged.vault_uuid);
    std::fs::write(&state_path, b"not a canonical SyncState").unwrap();

    let err = preview_repair_with_password_in(Some(state_dir.path()), &folder, &pw)
        .expect_err("existing-but-unreadable baseline must refuse the preview fail-closed");
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.contains(&state_path.display().to_string()),
                "detail must name the failing state file: {detail}"
            );
            assert!(
                detail.contains("resets this device's rollback history"),
                "detail must carry the documented remedy: {detail}"
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
}
