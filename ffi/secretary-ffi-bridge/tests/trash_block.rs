//! Integration tests for the bridge `trash_block` against a writable
//! copy of `golden_vault_001`. Each test gets its own tempdir so trash
//! mutations never reach the on-disk fixture.

// Shared helpers are pulled in for the fixture; mint_external_card is
// only used by share_block.rs, so allow dead code at this test bin.
#[allow(dead_code)]
mod share_block_helpers;

use std::fs;

use secretary_ffi_bridge::{trash_block, FfiVaultError};

use share_block_helpers::{
    fresh_writable_vault, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID, NEW_RECORD_UUID,
    NOW_MS_BASE,
};

/// Pretty-print 16-byte UUID as the same hyphenated hex used by the
/// vault folder layout (matches `core::vault::orchestrators::format_uuid_hyphenated`).
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
// Happy path: save → trash → block file moved + manifest reflects change
// ---------------------------------------------------------------------------

#[test]
fn trash_block_round_trip_moves_file_and_updates_manifest() {
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

    // Sanity: block is live before trash.
    let pre = manifest.find_block(&NEW_BLOCK_UUID);
    assert!(pre.is_some(), "block must be live before trash");

    let trash_now_ms = NOW_MS_BASE + 1_000;
    trash_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        trash_now_ms,
    )
    .expect("trash_block must succeed for a live block");

    // Block file moved blocks/ → trash/.
    let uuid_hex = uuid_hex_hyphenated(&NEW_BLOCK_UUID);
    assert!(
        !tmp.path()
            .join("blocks")
            .join(format!("{uuid_hex}.cbor.enc"))
            .exists(),
        "block file must be moved out of blocks/"
    );
    assert!(
        tmp.path()
            .join("trash")
            .join(format!("{uuid_hex}.cbor.enc.{trash_now_ms}"))
            .exists(),
        "block file must appear in trash/ with the tombstone timestamp"
    );

    // Manifest snapshot reflects the change.
    assert!(
        manifest.find_block(&NEW_BLOCK_UUID).is_none(),
        "BlockEntry must be gone after trash_block",
    );
}

// ---------------------------------------------------------------------------
// Failure: unknown UUID → BlockNotFound, no state change
// ---------------------------------------------------------------------------

#[test]
fn trash_block_unknown_uuid_returns_block_not_found() {
    let (tmp, identity, manifest) = fresh_writable_vault();
    let unknown_uuid: [u8; 16] = [0xff; 16];

    let result = trash_block(
        &identity,
        &manifest,
        unknown_uuid,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    );
    match result {
        Err(FfiVaultError::BlockNotFound { uuid_hex }) => {
            assert!(uuid_hex.contains("ff"));
        }
        other => panic!("expected BlockNotFound, got {other:?}"),
    }
    // No trash/ folder should have been created on the no-op failure.
    assert!(
        !tmp.path().join("trash").exists()
            || tmp
                .path()
                .join("trash")
                .read_dir()
                .map(|mut it| it.next().is_none())
                .unwrap_or(true),
        "trash/ must remain absent or empty after a BlockNotFound failure"
    );
}

// ---------------------------------------------------------------------------
// Failure: wiped identity → CorruptVault
// ---------------------------------------------------------------------------

#[test]
fn trash_block_wiped_identity_returns_corrupt_vault() {
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
    // Wipe the identity handle. After wipe, subsequent reads should
    // surface CorruptVault from the bridge.
    identity.wipe();

    let result = trash_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    );
    assert!(matches!(result, Err(FfiVaultError::CorruptVault { .. })));

    // On-disk: the block file is still in blocks/, untouched. The wipe
    // came after save_one_record_block, so the file exists.
    let uuid_hex = uuid_hex_hyphenated(&NEW_BLOCK_UUID);
    assert!(
        tmp.path()
            .join("blocks")
            .join(format!("{uuid_hex}.cbor.enc"))
            .exists(),
        "block file must remain in blocks/ after a CorruptVault failure"
    );
    // Suppress unused-variable warning on fs (kept for symmetry with
    // peer tests that read trash/).
    let _ = fs::metadata(tmp.path());
}
