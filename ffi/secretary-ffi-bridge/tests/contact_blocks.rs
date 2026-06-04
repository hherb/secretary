//! Integration tests for D.1.9 `contact_blocks` — the per-contact inverse of
//! `block_recipients`. Reuse the share test harness (writable golden copy +
//! runtime-minted external cards). Read-only: no writes beyond the harness's
//! own save/share/trash setup.

#[allow(dead_code)]
mod share_block_helpers;

use secretary_core::identity::card::ContactCard;
use secretary_core::vault::format_uuid_hyphenated;
use secretary_ffi_bridge::{
    contact_blocks, enumerate_contact_cards, share_block_to, trash_block, OpenVaultManifest,
};
use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID,
    NEW_RECORD_UUID, NOW_MS_BASE,
};
use std::fs;
use std::path::Path;

/// Write raw card bytes into the vault's `contacts/` dir under the canonical
/// hyphenated filename. Returns the card's `contact_uuid`. (Local copy of the
/// `recipients.rs` helper — the shared harness mod doesn't expose it.)
fn place_card(folder: &Path, card_bytes: &[u8]) -> [u8; 16] {
    let card = ContactCard::from_canonical_cbor(card_bytes).expect("valid card");
    let path = folder.join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&card.contact_uuid)
    ));
    fs::write(&path, card_bytes).expect("write card");
    card.contact_uuid
}

/// Shared setup: a writable golden copy with one owner-authored block saved
/// and a minted "Alice" peer card placed in contacts/ (NOT yet a recipient).
/// Returns (tempdir guard, identity, manifest, alice_uuid).
fn vault_with_block_and_alice() -> (
    tempfile::TempDir,
    secretary_ffi_bridge::UnlockedIdentity,
    OpenVaultManifest,
    [u8; 16],
) {
    let (tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "user",
        "alice",
        NOW_MS_BASE,
    );
    let (_alice_bundle, alice_card) = mint_external_card(0x42, "Alice");
    let alice_uuid = place_card(tmp.path(), &alice_card);
    (tmp, identity, manifest, alice_uuid)
}

#[test]
fn contact_with_no_shares_has_empty_block_list() {
    let (_tmp, _identity, manifest, alice_uuid) = vault_with_block_and_alice();
    // Alice has a card on disk but was never made a recipient of any block.
    let blocks = contact_blocks(&manifest, alice_uuid).expect("contact_blocks ok");
    assert!(blocks.is_empty(), "an un-shared contact receives no blocks");
}

#[test]
fn contact_blocks_lists_the_shared_block() {
    let (_tmp, identity, manifest, alice_uuid) = vault_with_block_and_alice();
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share to alice");

    let blocks = contact_blocks(&manifest, alice_uuid).expect("contact_blocks ok");
    assert_eq!(blocks.len(), 1, "alice now receives exactly one block");
    assert_eq!(blocks[0].block_uuid, NEW_BLOCK_UUID);
    assert_eq!(blocks[0].block_name, "shared");
}

#[test]
fn block_count_matches_shared_block_count_invariant() {
    let (_tmp, identity, manifest, alice_uuid) = vault_with_block_and_alice();
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share to alice");

    let list_len = contact_blocks(&manifest, alice_uuid)
        .expect("contact_blocks ok")
        .len();
    let (summaries, _unreadable) = enumerate_contact_cards(&manifest).expect("enumerate ok");
    let alice = summaries
        .iter()
        .find(|c| c.contact_uuid == alice_uuid)
        .expect("alice is an enumerated contact");
    assert_eq!(
        list_len, alice.shared_block_count as usize,
        "contact_blocks length must equal shared_block_count"
    );
}

#[test]
fn trashing_a_shared_block_drops_it_from_the_list() {
    let (_tmp, identity, manifest, alice_uuid) = vault_with_block_and_alice();
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        alice_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("share to alice");
    assert_eq!(
        contact_blocks(&manifest, alice_uuid).expect("ok").len(),
        1,
        "precondition: alice receives the block before trash"
    );

    trash_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2,
    )
    .expect("trash the block");

    let blocks = contact_blocks(&manifest, alice_uuid).expect("contact_blocks ok");
    assert!(
        blocks.is_empty(),
        "a trashed block (moved to manifest.trash) must not appear in the reverse map"
    );
}

#[test]
fn unknown_uuid_matches_nothing_without_error() {
    let (_tmp, _identity, manifest, _alice_uuid) = vault_with_block_and_alice();
    let stranger = [0x99u8; 16]; // valid 16 bytes, no card, no recipiency
    let blocks = contact_blocks(&manifest, stranger).expect("contact_blocks ok");
    assert!(
        blocks.is_empty(),
        "a uuid matching nothing yields an empty list"
    );
}
