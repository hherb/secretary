//! D.1.5 `list_trashed_blocks` — the Trash view's by-name projection.
//!
//! Hermetic: a writable copy of golden_vault_001 per test (crypto comes
//! from the fixture — no hardcoded key material). golden_vault_001 has
//! no trashed blocks at rest, so the empty case is the bare fixture and
//! the populated case creates + trashes a block first.

use std::path::{Path, PathBuf};

use secretary_ffi_bridge::{
    create_block, list_trashed_blocks, open_vault_with_password, trash_block, OpenVaultManifest,
    UnlockedIdentity,
};

const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
const DEVICE_UUID: [u8; 16] = [0x07; 16];

fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

/// Opened writable golden-001 vault. Holds the tempdir alive for the
/// test's duration (dropping it cleans up the on-disk copy).
struct Opened {
    _tmp: tempfile::TempDir,
    identity: UnlockedIdentity,
    manifest: OpenVaultManifest,
}

fn open_writable_golden_001() -> Opened {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&src, tmp.path());
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
