//! Integration tests for `revoke_block` against a writable copy of
//! `golden_vault_001`. Mirrors `share_block.rs`: each test gets its own
//! tempdir so revoke mutations never reach the on-disk fixture.
//!
//! `revoke_block` is the near-exact inverse of `share_block` — it removes a
//! recipient from a block's wire-level recipient table, re-keys for the
//! remaining recipients, and drops the revoked UUID from the manifest entry.
//!
//! Reuses `share_block_helpers` verbatim (the share + revoke bridge tests
//! share the same vault/handle/card-assembly fixtures).

mod share_block_helpers;

use secretary_ffi_bridge::{revoke_block, share_block, FfiVaultError};

use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID,
    NEW_RECORD_UUID, NOW_MS_BASE,
};

// ---------------------------------------------------------------------------
// Happy path: owner shares with Alice, then revokes Alice. The manifest's
// recipient list no longer contains Alice's contact UUID.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_removes_recipient_and_typed_errors() {
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

    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card bytes from live handle");
    let (alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");

    // Share with Alice first so there is a recipient to revoke.
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

    let pre = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable after share");
    assert_eq!(
        pre.recipient_uuids.len(),
        2,
        "after share: owner + alice are recipients",
    );
    assert!(
        pre.recipient_uuids.contains(&alice_bundle.user_uuid),
        "Alice must be a recipient before revoke",
    );

    // Act: revoke Alice. existing_recipient_cards = every CURRENT recipient
    // card (owner + alice), including the revoke target.
    revoke_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        &[owner_card_bytes.clone(), alice_card_bytes.clone()],
        alice_bundle.user_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    )
    .expect("revoke_block must succeed for owner revoking a recipient");

    let post = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block still findable after revoke");
    assert_eq!(
        post.recipient_uuids.len(),
        1,
        "revoke_block must drop the revoked recipient from the manifest entry",
    );
    assert!(
        !post.recipient_uuids.contains(&alice_bundle.user_uuid),
        "Alice's user_uuid must NOT appear in the post-revoke recipient list",
    );
    assert!(
        post.last_modified_ms > pre.last_modified_ms,
        "last_modified_ms must advance across revoke",
    );
    assert_eq!(
        post.created_at_ms, pre.created_at_ms,
        "created_at_ms must be preserved across revoke",
    );

    // Act 2: revoke a UUID that is NOT a recipient → RecipientNotPresent.
    let (bob_bundle, _bob_card_bytes) = mint_external_card(0xB2, "Bob");
    let err = revoke_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        bob_bundle.user_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 3_000,
    )
    .expect_err("revoking a non-recipient must fail");
    assert!(
        matches!(err, FfiVaultError::RecipientNotPresent),
        "expected RecipientNotPresent, got {err:?}",
    );

    // Act 3: revoke the OWNER UUID → CannotRevokeOwner (rejected up-front).
    let owner_uuid: [u8; 16] = identity
        .user_uuid()
        .try_into()
        .expect("user_uuid is 16 bytes");
    let err = revoke_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        owner_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 4_000,
    )
    .expect_err("revoking the owner must fail");
    assert!(
        matches!(err, FfiVaultError::CannotRevokeOwner),
        "expected CannotRevokeOwner, got {err:?}",
    );
}
