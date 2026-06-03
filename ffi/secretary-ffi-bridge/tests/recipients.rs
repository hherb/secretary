//! Integration tests for D.1.8 `block_recipients`. Reuse the share test
//! harness (writable golden copy + runtime-minted external cards).

#[allow(dead_code)]
mod share_block_helpers;

use secretary_core::identity::card::ContactCard;
use secretary_core::vault::format_uuid_hyphenated;
use secretary_ffi_bridge::{
    block_recipients, share_block_to, FfiVaultError, OpenVaultManifest, RecipientKind,
};
use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID,
    NEW_RECORD_UUID, NOW_MS_BASE,
};
use std::fs;
use std::path::Path;

/// Write raw card bytes into the vault's `contacts/` dir under the canonical
/// hyphenated filename. Returns the card's `contact_uuid`.
fn place_card(folder: &Path, card_bytes: &[u8]) -> [u8; 16] {
    let card = ContactCard::from_canonical_cbor(card_bytes).expect("valid card");
    let path = folder.join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&card.contact_uuid)
    ));
    fs::write(&path, card_bytes).expect("write card");
    card.contact_uuid
}

/// Resolve the owner's `contact_uuid` from the live manifest.
fn owner_uuid(manifest: &OpenVaultManifest) -> [u8; 16] {
    let bytes = manifest
        .owner_card_bytes()
        .expect("owner_card_bytes ok")
        .expect("vault has owner card");
    ContactCard::from_canonical_cbor(&bytes)
        .expect("owner card parses")
        .contact_uuid
}

#[test]
fn owner_only_block_has_single_owner_recipient() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    // Bridge save seeds recipients = [owner_card].
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );
    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].recipient_uuid, owner_uuid(&manifest));
    assert!(matches!(rs[0].kind, RecipientKind::Owner));
}

#[test]
fn shared_peer_resolves_to_contact_then_unknown_after_card_delete() {
    let (tmp, identity, manifest) = fresh_writable_vault();
    let folder = tmp.path().to_path_buf();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );

    // Share to a minted Alice → recipients = [owner, alice]; Alice resolves.
    let (_bundle, alice_bytes) = mint_external_card(0x51, "Alice");
    let alice = place_card(&folder, &alice_bytes);
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share");

    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    assert_eq!(rs.len(), 2);
    assert!(matches!(rs[0].kind, RecipientKind::Owner));
    let alice_row = rs
        .iter()
        .find(|r| r.recipient_uuid == alice)
        .expect("alice row");
    match &alice_row.kind {
        RecipientKind::Contact { display_name } => assert_eq!(display_name, "Alice"),
        other => panic!("expected Contact, got {other:?}"),
    }

    // Delete Alice's card (D.1.7 delete != revoke): she stays in recipients[]
    // (residual keyholder) but no longer resolves to a name.
    fs::remove_file(
        folder
            .join("contacts")
            .join(format!("{}.card", format_uuid_hyphenated(&alice))),
    )
    .expect("rm card");
    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    assert_eq!(rs.len(), 2);
    let alice_row = rs
        .iter()
        .find(|r| r.recipient_uuid == alice)
        .expect("alice row");
    assert!(matches!(alice_row.kind, RecipientKind::Unknown));
}

#[test]
fn tampered_card_is_unknown_not_forged_name() {
    let (tmp, identity, manifest) = fresh_writable_vault();
    let folder = tmp.path().to_path_buf();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );
    let (_bundle, alice_bytes) = mint_external_card(0x51, "Alice");
    let alice = place_card(&folder, &alice_bytes);
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share");

    // Corrupt Alice's card on disk so parse / verify_self() fails.
    let path = folder
        .join("contacts")
        .join(format!("{}.card", format_uuid_hyphenated(&alice)));
    let mut bytes = fs::read(&path).expect("read card");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&path, &bytes).expect("write tampered card");

    let rs = block_recipients(&manifest, NEW_BLOCK_UUID).expect("recipients");
    let alice_row = rs
        .iter()
        .find(|r| r.recipient_uuid == alice)
        .expect("alice row");
    assert!(
        matches!(alice_row.kind, RecipientKind::Unknown),
        "a tampered card must classify Unknown, never a trusted name"
    );
}

#[test]
fn unknown_block_is_block_not_found() {
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let err = block_recipients(&manifest, [0xEE; 16]).expect_err("missing block");
    assert!(matches!(err, FfiVaultError::BlockNotFound { .. }));
}
