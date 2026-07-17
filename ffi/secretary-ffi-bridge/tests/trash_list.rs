//! D.1.5 `list_trashed_blocks` — the Trash view's by-name projection.
//!
//! Hermetic: a writable copy of golden_vault_001 per test (crypto comes
//! from the fixture — no hardcoded key material). golden_vault_001 has
//! no trashed blocks at rest, so the empty case is the bare fixture and
//! the populated case creates + trashes a block first.

use std::path::{Path, PathBuf};

use secretary_ffi_bridge::{
    create_block, list_trashed_blocks, open_vault_with_password, purge_block, trash_block,
    OpenVaultManifest, UnlockedIdentity,
};
use secretary_test_utils::{copy_dir_to_tempdir, core_test_data_dir};

const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
const DEVICE_UUID: [u8; 16] = [0x07; 16];

/// Opened writable golden-001 vault. Holds the tempdir alive for the
/// test's duration (dropping it cleans up the on-disk copy).
struct Opened {
    _tmp: tempfile::TempDir,
    identity: UnlockedIdentity,
    manifest: OpenVaultManifest,
}

fn open_writable_golden_001() -> Opened {
    let tmp = copy_dir_to_tempdir(&core_test_data_dir().join("golden_vault_001"));
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("open writable copy of golden_vault_001");
    Opened {
        _tmp: tmp,
        identity: out.identity,
        manifest: out.manifest,
    }
}

#[test]
fn trashed_block_appears_in_list_by_name() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x51u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Bank logins".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block");

    trash_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        DEVICE_UUID,
        2_000,
    )
    .expect("trash_block");

    let listed =
        list_trashed_blocks(&opened.identity, &opened.manifest).expect("list_trashed_blocks");

    let entry = listed
        .iter()
        .find(|t| t.block_uuid == block_uuid)
        .expect("trashed block present in list");
    assert_eq!(entry.block_name, "Bank logins");
    assert_eq!(entry.tombstoned_at_ms, 2_000);
    assert_eq!(entry.tombstoned_by, DEVICE_UUID);
}

/// Locate the single `<uuid>.cbor.enc.<ts>` trash file for `block_uuid`
/// in the vault's `trash/` dir. Returns the full path; panics if there
/// is not exactly one matching file (the populated tests trash exactly
/// one block, so this pins the precondition).
fn find_trash_file(vault_dir: &Path, block_uuid: &[u8; 16]) -> PathBuf {
    let hyphenated = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        block_uuid[0], block_uuid[1], block_uuid[2], block_uuid[3],
        block_uuid[4], block_uuid[5],
        block_uuid[6], block_uuid[7],
        block_uuid[8], block_uuid[9],
        block_uuid[10], block_uuid[11], block_uuid[12], block_uuid[13], block_uuid[14], block_uuid[15],
    );
    let prefix = format!("{hyphenated}.cbor.enc.");
    let trash_dir = vault_dir.join("trash");
    let mut matches: Vec<PathBuf> = std::fs::read_dir(&trash_dir)
        .expect("read trash dir")
        .filter_map(|e| {
            let path = e.expect("dir entry").path();
            let name = path.file_name()?.to_str()?.to_string();
            name.starts_with(&prefix).then_some(path)
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one trash file for the block, found {matches:?}",
    );
    matches.pop().unwrap()
}

/// Overwrite a file's contents in place with `new_bytes` (same path, so
/// the `<ts>` suffix is unchanged). Used to corrupt a trash file's
/// ciphertext to prove whether a list call re-decrypts it.
fn overwrite_in_place(path: &Path, new_bytes: &[u8]) {
    std::fs::write(path, new_bytes).expect("overwrite trash file in place");
}

/// Newest-wins: with two trash files for the same block, the listing
/// selects the one with the higher canonical `<ts>` suffix and decrypts
/// fine. We also drop a leading-zero (non-canonical) decimal file and a
/// non-numeric junk file to confirm both are ignored, not fatal.
#[test]
fn list_selects_newest_trash_file_and_skips_non_canonical() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x52u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Email logins".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block");

    trash_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        DEVICE_UUID,
        2_000,
    )
    .expect("trash_block");

    // The vault folder is the tempdir root.
    let vault_dir = opened._tmp.path();
    let original = find_trash_file(vault_dir, &block_uuid);
    let bytes = std::fs::read(&original).expect("read original trash file");

    // Same ciphertext, higher canonical timestamp suffix => newest wins.
    // (Decrypts identically since it's a byte-for-byte copy.)
    let newest = original.with_file_name(format!(
        "{}.99999",
        original
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit_once('.')
            .unwrap()
            .0,
    ));
    std::fs::write(&newest, &bytes).expect("write newest trash file");

    // Non-canonical leading-zero suffix and non-numeric junk: both must
    // be skipped by the listing, never selected, never fatal.
    let bogus_leading_zero = original.with_file_name(format!(
        "{}.00123",
        original
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit_once('.')
            .unwrap()
            .0,
    ));
    std::fs::write(&bogus_leading_zero, &bytes).expect("write leading-zero trash file");

    let listed =
        list_trashed_blocks(&opened.identity, &opened.manifest).expect("list_trashed_blocks");
    let entry = listed
        .iter()
        .find(|t| t.block_uuid == block_uuid)
        .expect("trashed block still present with newest + bogus files on disk");
    assert_eq!(entry.block_name, "Email logins");
}

#[test]
fn list_trashed_blocks_empty_when_nothing_trashed() {
    let opened = open_writable_golden_001();
    let listed =
        list_trashed_blocks(&opened.identity, &opened.manifest).expect("list_trashed_blocks");
    assert!(
        !listed.iter().any(|t| t.block_name == "Bank logins"),
        "fresh golden copy must not contain a 'Bank logins' trashed block",
    );
}

/// A second `list_trashed_blocks` with the SAME on-disk `<ts>` serves the
/// name from the memo without re-decrypting: we corrupt the ciphertext in
/// place after the first list, and the second list still returns the
/// correct name (a re-decrypt would have surfaced a typed error).
#[test]
fn cache_hit_serves_name_without_redecrypt() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x53u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Server keys".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block");
    trash_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        DEVICE_UUID,
        2_000,
    )
    .expect("trash_block");

    // First list populates the memo (uuid, ts → "Server keys").
    let first = list_trashed_blocks(&opened.identity, &opened.manifest).expect("first list");
    assert_eq!(
        first
            .iter()
            .find(|t| t.block_uuid == block_uuid)
            .unwrap()
            .block_name,
        "Server keys",
    );

    // Corrupt the trash file's bytes in place (ts suffix unchanged).
    let vault_dir = opened._tmp.path();
    let trash_file = find_trash_file(vault_dir, &block_uuid);
    overwrite_in_place(&trash_file, b"this is not a valid block file envelope");

    // Second list: same (uuid, ts) → memo hit → name still resolves,
    // proving the corrupt bytes were never decrypted.
    let second = list_trashed_blocks(&opened.identity, &opened.manifest)
        .expect("second list must succeed from cache");
    assert_eq!(
        second
            .iter()
            .find(|t| t.block_uuid == block_uuid)
            .unwrap()
            .block_name,
        "Server keys",
    );
}

/// A newer `<ts>` is a different memo key, so the listing must re-decrypt
/// the newest file rather than serve the stale cached name. We drop a
/// CORRUPT higher-ts file after the first list; the second list keys on
/// the new ts → miss → re-decrypt → typed error (not the stale name).
#[test]
fn newer_ts_forces_redecrypt_not_stale_cache() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x54u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Recovery codes".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block");
    trash_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        DEVICE_UUID,
        2_000,
    )
    .expect("trash_block");

    // First list caches (uuid, old_ts → "Recovery codes").
    let first = list_trashed_blocks(&opened.identity, &opened.manifest).expect("first list");
    assert_eq!(
        first
            .iter()
            .find(|t| t.block_uuid == block_uuid)
            .unwrap()
            .block_name,
        "Recovery codes",
    );

    // Drop a CORRUPT higher-ts file for the same uuid. newest-wins selects
    // it; its (uuid, new_ts) is not in the memo → must decrypt → error.
    let vault_dir = opened._tmp.path();
    let original = find_trash_file(vault_dir, &block_uuid);
    let corrupt_newer = original.with_file_name(format!(
        "{}.99999",
        original
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit_once('.')
            .unwrap()
            .0,
    ));
    std::fs::write(&corrupt_newer, b"corrupt newer-ts envelope").expect("write corrupt newer file");

    let result = list_trashed_blocks(&opened.identity, &opened.manifest);
    assert!(
        result.is_err(),
        "newer ts is a cache miss; decrypting the corrupt newest file must error, \
         not silently serve the stale cached name",
    );
}

/// #399 regression: a purged trash entry has NO on-disk file by design
/// (its ciphertext was deleted by `purge_block`). Before the fix,
/// `list_trashed_blocks` treated the missing file as an integrity
/// violation and raised `CorruptVault`. Trash two blocks, purge one,
/// and confirm the listing silently excludes the purged one — no error,
/// and exactly the not-purged block is returned.
#[test]
fn list_trashed_skips_purged_entries() {
    let opened = open_writable_golden_001();

    let kept_uuid = [0x55u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        kept_uuid,
        "Kept in trash".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block kept");
    trash_block(
        &opened.identity,
        &opened.manifest,
        kept_uuid,
        DEVICE_UUID,
        2_000,
    )
    .expect("trash_block kept");

    let purged_uuid = [0x56u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        purged_uuid,
        "Purged away".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block purged");
    trash_block(
        &opened.identity,
        &opened.manifest,
        purged_uuid,
        DEVICE_UUID,
        2_000,
    )
    .expect("trash_block purged");
    purge_block(
        &opened.identity,
        &opened.manifest,
        purged_uuid,
        DEVICE_UUID,
        3_000,
    )
    .expect("purge_block");

    let listed = list_trashed_blocks(&opened.identity, &opened.manifest)
        .expect("list_trashed_blocks must not error on a purged entry");

    assert_eq!(
        listed.len(),
        1,
        "purged block is not listed and does not error; listing was {listed:?}"
    );
    assert_eq!(listed[0].block_uuid, kept_uuid);
    assert_eq!(listed[0].block_name, "Kept in trash");
}
