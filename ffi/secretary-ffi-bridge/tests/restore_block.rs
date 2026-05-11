//! Integration tests for the bridge `restore_block` against a writable
//! copy of `golden_vault_001`. Each test gets its own tempdir so trash
//! / restore mutations never reach the on-disk fixture.

// Shared helpers pulled in for the fixture; some items are only used by
// share_block.rs, so allow dead code at this test bin.
#[allow(dead_code)]
mod share_block_helpers;

use std::fs;

use secretary_ffi_bridge::{restore_block, trash_block, FfiVaultError};

use share_block_helpers::{
    fresh_writable_vault, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID, NEW_RECORD_UUID,
    NOW_MS_BASE,
};

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

// ---------------------------------------------------------------------------
// Happy path: save → trash → restore round-trip via bridge entry points
// ---------------------------------------------------------------------------

#[test]
fn restore_block_end_to_end_round_trip() {
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

    restore_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    )
    .expect("restore_block must succeed for a freshly-trashed block");

    let uuid_hex = uuid_hex_hyphenated(&NEW_BLOCK_UUID);
    assert!(
        tmp.path()
            .join("blocks")
            .join(format!("{uuid_hex}.cbor.enc"))
            .exists(),
        "block file must be back in blocks/ after restore"
    );
    assert!(
        manifest.find_block(&NEW_BLOCK_UUID).is_some(),
        "BlockEntry must be back in the manifest after restore"
    );
}

// ---------------------------------------------------------------------------
// Failure: live-collision → BlockUuidAlreadyLive
// ---------------------------------------------------------------------------

#[test]
fn restore_block_live_collision_returns_block_uuid_already_live() {
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
    // Re-save under the same UUID — block becomes live again WITHOUT
    // touching the trash file from the previous trash_block call.
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "password",
        "newer",
        NOW_MS_BASE + 1_500,
    );

    let result = restore_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    );
    match result {
        Err(FfiVaultError::BlockUuidAlreadyLive { detail }) => {
            assert!(
                detail.contains("ab") || detail.contains("AB"),
                "detail must carry the UUID hex: {detail}"
            );
        }
        other => panic!("expected BlockUuidAlreadyLive, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Failure: tampered trash file → CorruptVault (folded from
// RestoreVerificationFailed)
// ---------------------------------------------------------------------------

#[test]
fn restore_block_tampered_file_returns_corrupt_vault() {
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
    let trash_ms = NOW_MS_BASE + 1_000;
    trash_block(&identity, &manifest, NEW_BLOCK_UUID, DEVICE_UUID, trash_ms).expect("trash_block");

    // Tamper: flip a byte mid-file. The §6.1 hybrid signature rejects
    // regardless of where the bit lands (all sections are signed).
    let uuid_hex = uuid_hex_hyphenated(&NEW_BLOCK_UUID);
    let trash_path = tmp
        .path()
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.{trash_ms}"));
    let mut bytes = fs::read(&trash_path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    fs::write(&trash_path, &bytes).unwrap();

    let result = restore_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
    );
    match result {
        Err(FfiVaultError::CorruptVault { detail }) => {
            assert!(
                detail.contains("verification"),
                "detail must mention verification: {detail}"
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
    // Trash file still present (caller decides forensic vs purge).
    assert!(trash_path.exists());
    // Manifest.blocks still has no entry for the UUID (block was trashed
    // and restore was rejected before any manifest mutation).
    assert!(manifest.find_block(&NEW_BLOCK_UUID).is_none());
}
