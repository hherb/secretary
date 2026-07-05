//! Happy-adopt / fail-closed basics across the bridge repair arms:
//! interrupted-save adoption (password + device-secret), the default
//! recipient-widening refusal, and healthy-vault idempotence.

use super::*;

/// Case 1: happy-adopt via the password arm. Stage a crashed `save_block`
/// (v2 block on disk, v1 manifest committed) via the CORE `save_block`
/// directly (same sequence as
/// `crash_recovery.rs::repair_vault_adopts_interrupted_save`), then drive
/// the assertions entirely through the bridge surface: the plain open must
/// surface the typed `VaultNeedsRepair` signal, `repair_vault_with_password`
/// must adopt, and a subsequent bridge open must be green.
#[test]
fn repair_vault_with_password_adopts_interrupted_save_then_reopens() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    let open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe0; 16], [0xf0; 16]);
    // Crash simulation: v2 block hit disk, v2 manifest write was lost.
    stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    // The plain bridge open must surface the actionable typed signal.
    let err =
        open_vault_with_password(&folder, &pw).expect_err("crash residue must fail the plain open");
    match err {
        FfiVaultError::VaultNeedsRepair { block_uuid_hex } => {
            assert_eq!(block_uuid_hex, format_uuid_hyphenated(&block_uuid));
        }
        other => panic!("expected VaultNeedsRepair, got {other:?}"),
    }

    // repair_vault_with_password adopts the on-disk v2 generation. Empty
    // approvals is the documented safe zero-value (maps to FailClosed);
    // this residue shape (a crashed content save, not a widening) adopts
    // regardless.
    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[])
        .expect("gated adoption must succeed on genuine crash residue");
    drop(repaired);

    // A subsequent plain bridge open is green.
    open_vault_with_password(&folder, &pw).expect("vault must be healthy after repair");
}

/// Case 2: happy-adopt via the device-secret arm. Enroll a fresh device
/// slot through the bridge's own `add_device_slot` projection, stage the
/// same crashed-save residue, then adopt through
/// `repair_vault_with_device_secret`.
#[test]
fn repair_vault_with_device_secret_adopts_interrupted_save() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0x92; 32]);

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

    // Stage a crashed save under this device's own unlock path.
    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf1; 16];
    stage_crashed_save(&folder, open, block_uuid, device_uuid, &mut rng);

    let repaired =
        repair_vault_with_device_secret(&folder, &device_uuid, &device_secret, 3_000, &[])
            .expect("gated adoption via device secret must succeed");
    let entry = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("adopted entry present");
    assert_eq!(
        entry.block_name, "v2",
        "adopted entry carries on-disk content"
    );
}

/// Case 3: rejected — a crashed `share_block` (recipient-widening residue)
/// must NOT be auto-adopted. `repair_vault_with_password` must surface
/// `FfiVaultError::RepairRejected` whose `detail` names the would-be-added
/// recipient (mirrors `crash_recovery.rs::repair_rejects_crashed_share_superset`).
#[test]
fn repair_vault_with_password_rejects_recipient_widening_residue() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x93; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe2; 16], [0xf2; 16]);

    // Fresh external recipient — disjoint seed from the golden-vault mint
    // seeds so TOFU never collides.
    let card_c = mint_external_card(0x94, "Cee");

    let recipients = vec![open.owner_card.clone()];
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "mine"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_pre_share = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(
        &folder,
        &mut open,
        BlockUuid::new(block_uuid),
        &author_card,
        &author_sk_ed,
        &author_sk_pq,
        &recipients,
        &card_c,
        DeviceUuid::new(device_uuid),
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: the {owner, C} block hit disk, the manifest write
    // that would have committed the widened recipient set was lost.
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_pre_share).unwrap();

    // No approvals: this is the FailClosed baseline test — the widening
    // must be refused with no consent offered at all.
    let err = repair_vault_with_password(&folder, &pw, &device_uuid, 3_000, &[])
        .expect_err("crashed-share superset must be refused (documented limitation)");
    match err {
        FfiVaultError::RepairRejected {
            block_uuid_hex,
            detail,
        } => {
            assert_eq!(block_uuid_hex, format_uuid_hyphenated(&block_uuid));
            assert!(
                detail.contains("would ADD recipients"),
                "detail must name the widening reason: {detail}"
            );
            assert!(
                detail.contains(&format_uuid_hyphenated(&card_c.contact_uuid)),
                "detail must name the would-be-added recipient: {detail}"
            );
        }
        other => panic!("expected RepairRejected, got {other:?}"),
    }
    // All-or-nothing: the manifest must be untouched by the rejected repair.
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        manifest_pre_share,
        "rejected repair must not touch the manifest"
    );
}

/// Case 4: idempotent — `repair_vault_with_password` on a healthy vault
/// (no crash residue) succeeds and writes no new manifest bytes.
#[test]
fn repair_vault_with_password_is_idempotent_on_healthy_vault() {
    let (_tmp, folder) = tmp_golden_vault();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x95; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe3; 16], [0xf3; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "healthy"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let repaired = repair_vault_with_password(&folder, &pw, &device_uuid, 2_000, &[])
        .expect("healthy vault must open through repair");
    let has_block = repaired
        .manifest
        .block_summaries()
        .into_iter()
        .any(|b| b.block_uuid == block_uuid);
    assert!(has_block, "healthy repair must still see the live block");
    drop(repaired);

    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "healthy repair must not rewrite the manifest"
    );
}
