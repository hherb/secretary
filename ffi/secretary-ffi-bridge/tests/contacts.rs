//! Integration tests for the D.1.6 contacts subsystem. Reuse the share
//! test harness (writable golden copy + runtime-minted external cards).

// The shared harness exposes more helpers (block-save constants, etc.) than
// this bin consumes; the share_block bins use the full surface, so the unused
// items only show up here. Suppress dead_code for the shared module only.
#[allow(dead_code)]
mod share_block_helpers;

use secretary_core::identity::card::ContactCard;
use secretary_core::vault::format_uuid_hyphenated;
use secretary_ffi_bridge::{
    enumerate_contact_cards, import_contact_card, share_block_to, FfiVaultError,
};
use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID,
    NEW_RECORD_UUID, NOW_MS_BASE,
};
use std::fs;

fn uuid_of(card_bytes: &[u8]) -> [u8; 16] {
    ContactCard::from_canonical_cbor(card_bytes)
        .unwrap()
        .contact_uuid
}

/// Write raw card bytes into the vault's contacts/ dir under the canonical
/// hyphenated filename. Returns the card's contact_uuid.
fn place_card(folder: &std::path::Path, card_bytes: &[u8]) -> [u8; 16] {
    let card = ContactCard::from_canonical_cbor(card_bytes).expect("valid card");
    let path = folder.join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&card.contact_uuid)
    ));
    fs::write(&path, card_bytes).expect("write card");
    card.contact_uuid
}

/// Resolve the owner's `contact_uuid` so tests can assert it is never
/// returned, independent of how many cards the fixture ships with.
fn owner_uuid(manifest: &secretary_ffi_bridge::OpenVaultManifest) -> [u8; 16] {
    let bytes = manifest
        .owner_card_bytes()
        .expect("owner_card_bytes ok")
        .expect("vault has owner card");
    ContactCard::from_canonical_cbor(&bytes)
        .expect("owner card parses")
        .contact_uuid
}

#[test]
fn enumerate_returns_placed_cards_excluding_owner() {
    // NOTE (adapted from plan): the golden_vault_001 fixture's contacts/ dir
    // ships with THREE valid cards — the owner plus two pre-existing peer
    // cards ("Alice"/"Bob") used by the share tests — not just the owner's
    // self-card. So we baseline the enumeration BEFORE placing new cards and
    // assert the DELTA, keeping the test independent of fixture card count.
    let (tmp, _identity, manifest) = fresh_writable_vault();
    let folder = tmp.path();

    let (baseline, baseline_unreadable) =
        enumerate_contact_cards(&manifest).expect("baseline enumerate ok");
    assert_eq!(baseline_unreadable, 0, "fixture cards are all valid");
    let owner = owner_uuid(&manifest);
    assert!(
        baseline.iter().all(|s| s.contact_uuid != owner),
        "owner self-card is never enumerated"
    );

    // Mint two peers under seeds that do NOT collide with the fixture's
    // pre-existing peer cards (the fixture's "Alice" was minted under seed
    // 0xA1 by this same helper, so its UUID matches deterministically; using
    // it would silently overwrite that file and add zero net entries).
    let (_b1, peer1) = mint_external_card(0xC3, "Peer-One");
    let (_b2, peer2) = mint_external_card(0xD4, "Peer-Two");
    let peer1_uuid = place_card(folder, &peer1);
    let peer2_uuid = place_card(folder, &peer2);
    // Sanity: the two minted peers are genuinely new (not already present in
    // the fixture baseline) and distinct from each other.
    assert_ne!(peer1_uuid, peer2_uuid, "minted peers are distinct");
    assert!(
        baseline.iter().all(|s| s.contact_uuid != peer1_uuid)
            && baseline.iter().all(|s| s.contact_uuid != peer2_uuid),
        "chosen seeds do not collide with fixture peers"
    );

    let (summaries, unreadable) = enumerate_contact_cards(&manifest).expect("enumerate ok");

    assert_eq!(unreadable, 0, "all placed cards are valid");
    assert!(
        summaries.iter().all(|s| s.contact_uuid != owner),
        "owner self-card still excluded after placing peers"
    );
    assert!(
        summaries.iter().any(|s| s.contact_uuid == peer1_uuid),
        "minted Peer-One present"
    );
    assert!(
        summaries.iter().any(|s| s.contact_uuid == peer2_uuid),
        "minted Peer-Two present"
    );
    assert_eq!(
        summaries.len(),
        baseline.len() + 2,
        "exactly the two newly-placed peers are added"
    );
}

#[test]
fn enumerate_counts_unreadable_and_unverified() {
    let (tmp, _identity, manifest) = fresh_writable_vault();
    let folder = tmp.path();

    let (baseline, _) = enumerate_contact_cards(&manifest).expect("baseline enumerate ok");

    // Seed 0xC3 does not collide with the fixture peers (see sibling test).
    let (_b1, peer) = mint_external_card(0xC3, "Peer-One");
    let peer_uuid = place_card(folder, &peer);
    assert!(
        baseline.iter().all(|s| s.contact_uuid != peer_uuid),
        "minted peer is genuinely new"
    );
    // Garbage .card → parse failure.
    fs::write(folder.join("contacts").join("garbage.card"), b"not cbor").unwrap();
    // Tampered card → parse OK (or parse fail) but never verifies (flip a
    // signature byte). Either failure mode increments `unreadable`.
    let mut tampered = peer.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    fs::write(
        folder
            .join("contacts")
            .join("11111111-1111-1111-1111-111111111111.card"),
        &tampered,
    )
    .unwrap();

    let (summaries, unreadable) = enumerate_contact_cards(&manifest).expect("enumerate ok");
    assert_eq!(
        summaries.len(),
        baseline.len() + 1,
        "only the intact minted peer card is added"
    );
    assert_eq!(unreadable, 2, "garbage + tampered both counted");
}

#[test]
fn import_writes_card_and_returns_summary() {
    let (tmp, _identity, manifest) = fresh_writable_vault();
    let (_b, peer) = mint_external_card(0xC3, "Carol");

    let summary = import_contact_card(&manifest, &peer).expect("import ok");
    assert_eq!(summary.display_name, "Carol");

    // File landed under the canonical hyphenated name.
    let path = tmp.path().join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&summary.contact_uuid)
    ));
    assert!(path.exists(), "imported card written to contacts/");
}

#[test]
fn import_rejects_duplicate_uuid() {
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let (_b, peer) = mint_external_card(0xC3, "Carol");
    import_contact_card(&manifest, &peer).expect("first import ok");
    let err = import_contact_card(&manifest, &peer).expect_err("dup must reject");
    assert!(matches!(err, FfiVaultError::ContactAlreadyExists { .. }));
}

#[test]
fn import_rejects_tampered_card() {
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let (_b, peer) = mint_external_card(0xC3, "Carol");
    let mut tampered = peer.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    let err = import_contact_card(&manifest, &tampered).expect_err("tampered must reject");
    assert!(matches!(err, FfiVaultError::CardDecodeFailure { .. }));
}

#[test]
fn share_block_to_appends_recipient() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "password",
        "hunter2",
        NOW_MS_BASE,
    );
    let (_b, peer) = mint_external_card(0xC3, "Carol");
    let peer_uuid = uuid_of(&peer);
    import_contact_card(&manifest, &peer).expect("import peer");

    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        peer_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("share_block_to ok");

    let entry = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable");
    assert_eq!(entry.recipient_uuids.len(), 2, "owner + peer");
    assert!(entry.recipient_uuids.contains(&peer_uuid));
}

#[test]
fn share_block_to_unknown_recipient_card_is_contact_not_found() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "p",
        "v",
        NOW_MS_BASE,
    );
    let err = share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        [0x99; 16],
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect_err("no card on disk");
    assert!(matches!(err, FfiVaultError::ContactNotFound { .. }));
}

#[test]
fn share_block_to_unknown_block_is_block_not_found() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let (_b, peer) = mint_external_card(0xC3, "Carol");
    let peer_uuid = uuid_of(&peer);
    import_contact_card(&manifest, &peer).unwrap();
    let err = share_block_to(
        &identity,
        &manifest,
        [0x77; 16],
        peer_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect_err("unknown block");
    assert!(matches!(err, FfiVaultError::BlockNotFound { .. }));
}

#[test]
fn share_block_to_twice_is_recipient_already_present() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "p",
        "v",
        NOW_MS_BASE,
    );
    let (_b, peer) = mint_external_card(0xC3, "Carol");
    let peer_uuid = uuid_of(&peer);
    import_contact_card(&manifest, &peer).unwrap();
    share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        peer_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .unwrap();
    let err = share_block_to(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        peer_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 2,
    )
    .expect_err("already a recipient");
    assert!(matches!(err, FfiVaultError::RecipientAlreadyPresent));
}
