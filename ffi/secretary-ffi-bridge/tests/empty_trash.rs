//! Integration tests for the bridge `empty_trash` against a writable
//! copy of `golden_vault_001`. Each test gets its own tempdir so trash
//! / purge mutations never reach the on-disk fixture.

// Shared helpers pulled in for the fixture; some items are only used by
// share_block.rs, so allow dead code at this test bin.
#[allow(dead_code)]
mod share_block_helpers;

use secretary_ffi_bridge::{empty_trash, purge_block, share_block, trash_block};

use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_RECORD_UUID,
    NOW_MS_BASE,
};

const OWNER_ONLY_BLOCK_UUID: [u8; 16] = [0xE1; 16];
const SHARED_BLOCK_UUID: [u8; 16] = [0xE2; 16];
const ALREADY_PURGED_BLOCK_UUID: [u8; 16] = [0xE3; 16];

/// Mixed trash: one owner-only block, one shared block, one block that
/// is already purged before `empty_trash` runs (must not be double
/// counted). `empty_trash` must aggregate the first two only.
#[test]
fn empty_trash_aggregates_mixed_trash() {
    let (tmp, identity, manifest) = fresh_writable_vault();

    // Owner-only block: save + trash.
    save_one_record_block(
        &identity,
        &manifest,
        OWNER_ONLY_BLOCK_UUID,
        NEW_RECORD_UUID,
        "password",
        "hunter2",
        NOW_MS_BASE,
    );
    trash_block(
        &identity,
        &manifest,
        OWNER_ONLY_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("trash owner-only block");

    // Shared block: save, share to Alice, then trash.
    save_one_record_block(
        &identity,
        &manifest,
        SHARED_BLOCK_UUID,
        [0xCC; 16],
        "password",
        "hunter3",
        NOW_MS_BASE,
    );
    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card bytes from live handle");
    let (_alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");
    share_block(
        &identity,
        &manifest,
        SHARED_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_500,
    )
    .expect("share block to alice");
    trash_block(
        &identity,
        &manifest,
        SHARED_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    )
    .expect("trash shared block");

    // Already-purged block: save, trash, purge — before empty_trash runs.
    save_one_record_block(
        &identity,
        &manifest,
        ALREADY_PURGED_BLOCK_UUID,
        [0xDD; 16],
        "password",
        "hunter4",
        NOW_MS_BASE,
    );
    trash_block(
        &identity,
        &manifest,
        ALREADY_PURGED_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2_500,
    )
    .expect("trash already-purged block");
    purge_block(
        &identity,
        &manifest,
        ALREADY_PURGED_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 3_000,
    )
    .expect("pre-purge the already-purged block");

    // Now empty the rest of the trash.
    let report = empty_trash(&identity, &manifest, DEVICE_UUID, NOW_MS_BASE + 4_000)
        .expect("empty_trash must succeed");

    assert_eq!(
        report.purged_count, 2,
        "only the 2 not-yet-purged entries are targeted; the pre-purged one is excluded"
    );
    assert_eq!(
        report.shared_count, 1,
        "the shared block classifies as shared"
    );
    assert_eq!(
        report.owner_only_count, 1,
        "the owner-only block classifies as owner-only"
    );
    assert_eq!(report.unknown_count, 0);
    assert!(
        report.files_removed >= 2,
        "at least the 2 newly-purged trash files must have been removed, got {}",
        report.files_removed
    );
    assert_eq!(report.files_failed, 0);

    // The trash/ directory no longer holds files for either newly-purged UUID.
    let trash_dir = tmp.path().join("trash");
    for uuid in [OWNER_ONLY_BLOCK_UUID, SHARED_BLOCK_UUID] {
        let uuid_hex = uuid_hex_hyphenated(&uuid);
        if let Ok(rd) = std::fs::read_dir(&trash_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                assert!(
                    !name.starts_with(&uuid_hex),
                    "purged block's trash file must be gone, found {name}"
                );
            }
        }
    }
}

/// Nothing to purge: an empty (or already-fully-purged) trash returns
/// the all-zero default report, no manifest write occurs.
#[test]
fn empty_trash_on_empty_trash_returns_zero_report() {
    let (_tmp, identity, manifest) = fresh_writable_vault();

    let report = empty_trash(&identity, &manifest, DEVICE_UUID, NOW_MS_BASE)
        .expect("empty_trash on a fresh vault with nothing trashed must succeed");

    assert_eq!(report.purged_count, 0);
    assert_eq!(report.shared_count, 0);
    assert_eq!(report.owner_only_count, 0);
    assert_eq!(report.unknown_count, 0);
    assert_eq!(report.files_removed, 0);
    assert_eq!(report.files_failed, 0);
}

fn uuid_hex_hyphenated(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
