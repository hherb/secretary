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
