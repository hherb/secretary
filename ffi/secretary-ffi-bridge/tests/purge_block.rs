//! Integration tests for the bridge `purge_block` against a writable
//! copy of `golden_vault_001`. Each test gets its own tempdir so trash
//! / purge mutations never reach the on-disk fixture.

// Shared helpers pulled in for the fixture; some items are only used by
// share_block.rs, so allow dead code at this test bin.
#[allow(dead_code)]
mod share_block_helpers;

use secretary_ffi_bridge::{purge_block, restore_block, trash_block, FfiVaultError};

use share_block_helpers::{
    fresh_writable_vault, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID, NEW_RECORD_UUID,
    NOW_MS_BASE,
};

// ---------------------------------------------------------------------------
// Happy path: save → trash → purge, then restore rejects with BlockPurged
// ---------------------------------------------------------------------------

#[test]
fn purge_block_owner_only_then_restore_returns_block_purged() {
    let (tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "password",
        "hunter2",
        NOW_MS_BASE,
    );
    trash_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("trash_block");

    let report = purge_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    )
    .expect("purge_block must succeed for a freshly-trashed, owner-only block");

    assert_eq!(report.block_uuid, NEW_BLOCK_UUID);
    assert_eq!(
        report.was_shared,
        Some(false),
        "owner-only block must classify as not-shared"
    );
    assert_eq!(report.recipient_count, Some(1));
    assert!(
        report.files_removed >= 1,
        "at least one trash file must have been removed, got {}",
        report.files_removed
    );

    // The trash/ directory no longer holds any file for this UUID.
    let trash_dir = tmp.path().join("trash");
    let uuid_hex = uuid_hex_hyphenated(&NEW_BLOCK_UUID);
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

    // Follow-up restore must be rejected as permanently purged.
    let result = restore_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 3_000,
    );
    match result {
        Err(FfiVaultError::BlockPurged { detail }) => {
            assert!(
                detail.contains("ab") || detail.contains("AB"),
                "detail must carry the UUID hex: {detail}"
            );
        }
        other => panic!("expected BlockPurged, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Idempotent re-purge: a second purge_block call on an already-purged
// TrashEntry succeeds with an honest "unknown" classification.
// ---------------------------------------------------------------------------

#[test]
fn purge_block_is_idempotent_on_second_call() {
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
    trash_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("trash_block");
    purge_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    )
    .expect("first purge_block must succeed");

    let second = purge_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 3_000,
    )
    .expect("re-purge of an already-purged TrashEntry must succeed idempotently");

    assert_eq!(second.was_shared, None);
    assert_eq!(second.recipient_count, None);
    assert_eq!(second.files_removed, 0);
}

// ---------------------------------------------------------------------------
// Failure: purging a UUID with no TrashEntry at all → BlockNotInTrash
// ---------------------------------------------------------------------------

#[test]
fn purge_block_unknown_uuid_returns_block_not_in_trash() {
    let (_tmp, identity, manifest) = fresh_writable_vault();

    let result = purge_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE,
    );
    match result {
        Err(FfiVaultError::BlockNotInTrash { detail }) => {
            assert!(
                detail.contains("ab") || detail.contains("AB"),
                "detail must carry the UUID hex: {detail}"
            );
        }
        other => panic!("expected BlockNotInTrash, got {other:?}"),
    }
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
