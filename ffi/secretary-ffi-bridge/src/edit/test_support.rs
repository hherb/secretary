//! Shared `#[cfg(test)]` fixtures for the block-CRUD edit primitives
//! (`rename.rs`, `move_record.rs`). Mirrors the per-file helper used by
//! `mod.rs` / `tombstone.rs`; factored out here because two new files need it.
#![cfg(test)]

use std::path::{Path, PathBuf};

use crate::{open_vault_with_password, OpenVaultOutput};

pub(super) const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

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

/// Open a writable copy of golden_vault_001 in a fresh tempdir. The tempdir
/// is returned so the caller keeps it alive for the test.
pub(super) fn open_writable_golden_001() -> (tempfile::TempDir, OpenVaultOutput) {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&src, tmp.path());
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("open writable copy of golden_vault_001");
    (tmp, out)
}
