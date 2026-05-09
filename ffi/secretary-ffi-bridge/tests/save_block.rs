//! Integration tests for `save_block` against a writable copy of
//! `golden_vault_001`. Each test gets its own tempdir so save mutations
//! never reach the on-disk fixture.
//!
//! KAT source of truth: `core/tests/data/golden_vault_001_inputs.json`.

use std::fs;
use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_ffi_bridge::{
    open_vault_with_password, read_block, save_block, BlockInput, FieldInput, FieldInputValue,
    OpenVaultManifest, RecordInput, UnlockedIdentity,
};

// ---------------------------------------------------------------------------
// Test fixture: writable golden_vault_001 copy
// ---------------------------------------------------------------------------

/// Path to the golden_vault_NNN folder. CARGO_MANIFEST_DIR is
/// ffi/secretary-ffi-bridge/, so we walk up to core/tests/data/.
fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

/// Recursively copy `src` into `dst` (which may not exist yet). Mirrors the
/// minimal pattern used by core's tests; intentionally not pulled in as a
/// dependency to keep the test fixture self-contained.
fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

/// Open a writable copy of golden_vault_001 in a fresh tempdir. The
/// tempdir is returned alongside the handles so the caller holds it
/// alive for the test's duration; dropping it cleans up the directory.
fn fresh_writable_vault() -> (tempfile::TempDir, UnlockedIdentity, OpenVaultManifest) {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&src, tmp.path());
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("open writable copy of golden_vault_001");
    (tmp, out.identity, out.manifest)
}

// Pinned UUIDs / timestamps for deterministic test inputs. These are
// distinct from golden_vault_001's existing block (whose UUID is
// 11223344-5566-7788-99aa-bbccddeeff00 per tests/read_block.rs).
const NEW_BLOCK_UUID: [u8; 16] = [0xAB; 16];
const NEW_RECORD_UUID: [u8; 16] = [0xCD; 16];
const DEVICE_UUID: [u8; 16] = [0x07; 16];
const NOW_MS_BASE: u64 = 1_715_000_000_000;

// ---------------------------------------------------------------------------
// Round-trip: insert + read back
// ---------------------------------------------------------------------------

#[test]
fn save_block_insert_round_trips_through_read_block() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let pre_count = manifest.block_count();

    let input = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "Notes".to_string(),
        records: vec![RecordInput {
            record_uuid: NEW_RECORD_UUID,
            fields: vec![
                FieldInput {
                    name: "title".to_string(),
                    value: FieldInputValue::Text(SecretString::from("wifi password")),
                },
                FieldInput {
                    name: "key".to_string(),
                    value: FieldInputValue::Bytes(SecretBytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF])),
                },
            ],
        }],
    };

    save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE).expect("save_block");
    assert_eq!(manifest.block_count(), pre_count + 1);
    let summary = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable in manifest");
    assert_eq!(summary.block_name, "Notes");

    let output = read_block(&identity, &manifest, &NEW_BLOCK_UUID).expect("read_block");
    assert_eq!(output.record_count(), 1);
    let record = output.record_at(0).expect("record present");
    assert_eq!(record.field_count(), 2);
    let title = record.field_by_name("title").expect("title field present");
    assert_eq!(title.expose_text().as_deref(), Some("wifi password"));
    let key = record.field_by_name("key").expect("key field present");
    assert_eq!(key.expose_bytes(), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}
