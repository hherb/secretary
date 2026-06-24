//! Integration tests for `share_block` against a writable copy of
//! `golden_vault_001`. Each test gets its own tempdir so share mutations
//! never reach the on-disk fixture.
//!
//! Alice (the recipient) is minted directly via
//! `secretary_core::unlock::bundle::generate` + a self-signing helper —
//! NOT by spinning up a second full vault. This keeps the test fast
//! (no extra Argon2id KDF) and isolates the share path from create_vault.
//!
//! Cross-vault read (Alice opens a vault staged by share_block) is
//! covered by `core/tests/share_block.rs::share_block_round_trip` at the
//! crypto core level; the bridge tests here verify the FFI surface +
//! manifest-state mutations end-to-end.
//!
//! The N-recipient sequential-share property test lives in the sibling
//! `share_block_proptest.rs` integration-test bin so its case-budget is
//! independent of these failure-mode tests.

mod share_block_helpers;

use secretary_core::vault::format_uuid_hyphenated;
use secretary_ffi_bridge::{share_block, FfiVaultError};
use std::fs;

use share_block_helpers::{
    fresh_writable_vault, mint_external_card, mint_forged_card, save_one_record_block, DEVICE_UUID,
    NEW_BLOCK_UUID, NEW_RECORD_UUID, NOW_MS_BASE,
};

// ---------------------------------------------------------------------------
// Happy path: owner saves a block, owner shares with Alice, manifest's
// recipient list now includes Alice's contact UUID.
// ---------------------------------------------------------------------------

#[test]
fn share_block_owner_to_alice_appends_recipient_to_manifest() {
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
    let pre = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable after save");
    assert_eq!(
        pre.recipient_uuids.len(),
        1,
        "v1 single-author save_block: only the owner is on the recipient list",
    );

    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card bytes from live handle");
    let (alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");

    share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("share_block must succeed for owner sharing their own block");

    let post = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block still findable after share");
    assert_eq!(
        post.recipient_uuids.len(),
        2,
        "share_block must append the new recipient to the manifest entry",
    );
    assert!(
        post.recipient_uuids.contains(&alice_bundle.user_uuid),
        "Alice's user_uuid must appear in the post-share recipient list",
    );
    assert!(
        post.last_modified_ms > pre.last_modified_ms,
        "last_modified_ms must advance across share",
    );
    assert_eq!(
        post.created_at_ms, pre.created_at_ms,
        "created_at_ms must be preserved across share",
    );
}

// ---------------------------------------------------------------------------
// Failure: duplicate recipient → RecipientAlreadyPresent
// ---------------------------------------------------------------------------

#[test]
fn share_block_with_duplicate_recipient_returns_already_present() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "k",
        "v",
        NOW_MS_BASE,
    );
    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card present");
    let (_alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");

    // First share: ok.
    share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("first share to alice succeeds");

    // Second share with the same alice card: existing list now has both
    // owner + alice; adding alice a second time must fail.
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        &[owner_card_bytes, alice_card_bytes.clone()],
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    )
    .expect_err("duplicate share must fail");
    assert!(
        matches!(err, FfiVaultError::RecipientAlreadyPresent),
        "expected RecipientAlreadyPresent, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Failure: caller's existing_recipient_cards omits a recipient on disk
// → MissingRecipientCard with the omitted fingerprint hex
// ---------------------------------------------------------------------------

#[test]
fn share_block_with_missing_existing_recipient_card_returns_missing_recipient_card() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "k",
        "v",
        NOW_MS_BASE,
    );
    // Block's wire-level recipient table currently contains the owner.
    // Pass an EMPTY existing_recipient_cards list — core's MissingRecipientCard
    // check fires for the owner's fingerprint, the bridge's From impl
    // maps it to FfiVaultError::MissingRecipientCard with hex.
    let (_alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        &[],
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect_err("share with empty existing list must fail");
    match err {
        FfiVaultError::MissingRecipientCard {
            recipient_fingerprint_hex,
        } => {
            assert_eq!(
                recipient_fingerprint_hex.len(),
                32,
                "fingerprint hex must be 32 chars (16-byte BLAKE3)",
            );
        }
        other => panic!("expected MissingRecipientCard, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Failure: malformed ContactCard bytes → CardDecodeFailure (bridge-internal)
// ---------------------------------------------------------------------------

#[test]
fn share_block_with_malformed_existing_card_bytes_returns_card_decode_failure() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "k",
        "v",
        NOW_MS_BASE,
    );
    let (_alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");
    let garbage = vec![0xFFu8; 8];
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&garbage),
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect_err("garbage existing card bytes must fail");
    match err {
        FfiVaultError::CardDecodeFailure { detail } => {
            assert!(!detail.is_empty(), "detail must be populated");
        }
        other => panic!("expected CardDecodeFailure (existing), got {other:?}"),
    }
}

#[test]
fn share_block_with_malformed_new_recipient_bytes_returns_card_decode_failure() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "k",
        "v",
        NOW_MS_BASE,
    );
    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card present");
    let garbage_new = vec![0xFFu8; 8];
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &garbage_new,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect_err("garbage new_recipient bytes must fail");
    assert!(
        matches!(err, FfiVaultError::CardDecodeFailure { .. }),
        "expected CardDecodeFailure (new_recipient), got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Failure: wiped handle → CorruptVault
// ---------------------------------------------------------------------------

#[test]
fn share_block_on_wiped_manifest_returns_corrupt_vault() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "k",
        "v",
        NOW_MS_BASE,
    );
    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card present");
    let (_alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");
    manifest.wipe();
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect_err("wiped manifest must fail");
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.to_lowercase().contains("manifest"),
                "detail should name the wiped handle: {detail}",
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
}

#[test]
fn share_block_on_wiped_identity_returns_corrupt_vault() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "k",
        "v",
        NOW_MS_BASE,
    );
    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card present");
    let (_alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");
    identity.wipe();
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect_err("wiped identity must fail");
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.to_lowercase().contains("identity"),
                "detail should name the wiped handle: {detail}",
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// NotAuthor — NOT pinned at this layer
//
// Reaching FfiVaultError::NotAuthor from the bridge integration layer
// requires staging two distinct vaults (one's manifest must list the
// other's block) and then sharing as the non-author. The bridge crate's
// integration tests can't cleanly construct this — open_vault_with_password
// validates vault.toml ↔ manifest consistency, so a cross-vault stage is
// rejected before share_block is called.
//
// The variant is pinned at:
// 1. Bridge unit level: src/error/vault.rs's
//    `vault_error_not_author_from_core_preserves_fingerprints_as_hex`
//    (covers the From<core::VaultError> mapping).
// 2. Core integration level:
//    core/tests/share_block.rs::share_block_non_author_rejected.
// 3. Foreign integration: pytest will exercise NotAuthor end-to-end via
//    create_vault (which is available at the foreign layer).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// #206: TOFU substitution guard
// ---------------------------------------------------------------------------

#[test]
fn share_block_raw_rejects_substituting_a_trusted_card() {
    // #206: a forged card carrying a TRUSTED contact's uuid but attacker
    // keys must not (a) overwrite the on-disk trusted card nor (b) re-key
    // the block. The hardened raw share_block rejects it as
    // ContactAlreadyExists before core runs.
    let (tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "p",
        "v",
        NOW_MS_BASE,
    );
    // Genuine Alice on disk (TOFU import via raw share to a fresh block path
    // would also write her, but place the card directly for clarity).
    let (alice_bundle, alice_genuine) = mint_external_card(0xB1, "Alice");
    let alice_uuid = alice_bundle.user_uuid;
    let card_path = tmp
        .path()
        .join("contacts")
        .join(format!("{}.card", format_uuid_hyphenated(&alice_uuid)));
    fs::write(&card_path, &alice_genuine).expect("place genuine alice card");

    // Forged card: Alice's uuid, attacker keys, self-consistent.
    let (_eve, forged) = mint_forged_card(0xE5, "Eve-as-Alice", alice_uuid);
    assert_ne!(forged, alice_genuine, "forged bytes differ from genuine");

    let owner_card_bytes = manifest.owner_card_bytes().unwrap().unwrap();
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &forged,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect_err("substituting a trusted card must be rejected");
    assert!(
        matches!(err, FfiVaultError::ContactAlreadyExists { .. }),
        "got {err:?}"
    );

    // On-disk card unchanged.
    let on_disk = fs::read(&card_path).unwrap();
    assert_eq!(
        on_disk, alice_genuine,
        "trusted card must not be overwritten"
    );

    // Block not re-keyed: still owner-only.
    let entry = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable");
    assert_eq!(entry.recipient_uuids.len(), 1, "owner only; no re-key");
    assert!(!entry.recipient_uuids.contains(&alice_uuid));
}

#[test]
fn share_block_raw_rejects_unsigned_new_card() {
    // New card parses but fails verify_self → CardDecodeFailure (gate 1).
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
    let owner = manifest.owner_card_bytes().unwrap().unwrap();
    let (_b, mut alice) = mint_external_card(0xB1, "Alice");
    let n = alice.len();
    alice[n - 1] ^= 0xFF; // still parses; self-sig now invalid
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner),
        &alice,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect_err("unsigned new card must reject");
    assert!(
        matches!(err, FfiVaultError::CardDecodeFailure { .. }),
        "got {err:?}"
    );
}

#[test]
fn share_block_raw_rejects_unsigned_existing_card() {
    // An existing card that parses but fails verify_self → CardDecodeFailure
    // (gate 3), surfaced earlier than core's MissingRecipientCard.
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
    let mut owner = manifest.owner_card_bytes().unwrap().unwrap();
    let n = owner.len();
    owner[n - 1] ^= 0xFF; // tampered owner card in the existing list
    let (_b, alice) = mint_external_card(0xB1, "Alice");
    let err = share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner),
        &alice,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect_err("unsigned existing card must reject");
    assert!(
        matches!(err, FfiVaultError::CardDecodeFailure { .. }),
        "got {err:?}"
    );
}

#[test]
fn share_block_raw_allows_byte_identical_existing_card_on_disk() {
    // Sharing a brand-new recipient whose genuine card is already on disk
    // with IDENTICAL bytes must succeed (guard allows identical).
    let (tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "p",
        "v",
        NOW_MS_BASE,
    );
    let (alice_bundle, alice) = mint_external_card(0xB1, "Alice");
    let path = tmp.path().join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&alice_bundle.user_uuid)
    ));
    fs::write(&path, &alice).unwrap();
    let owner = manifest.owner_card_bytes().unwrap().unwrap();
    share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner),
        &alice,
        DEVICE_UUID,
        NOW_MS_BASE + 1,
    )
    .expect("identical on-disk card → allowed");
    let entry = manifest.find_block(&NEW_BLOCK_UUID).unwrap();
    assert_eq!(entry.recipient_uuids.len(), 2);
    assert!(entry.recipient_uuids.contains(&alice_bundle.user_uuid));
}
