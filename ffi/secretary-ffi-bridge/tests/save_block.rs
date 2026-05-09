//! Integration tests for `save_block` against a writable copy of
//! `golden_vault_001`. Each test gets its own tempdir so save mutations
//! never reach the on-disk fixture.
//!
//! KAT source of truth: `core/tests/data/golden_vault_001_inputs.json`.

use std::fs;
use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_ffi_bridge::{
    open_vault_with_password, read_block, save_block, BlockInput, FfiVaultError, FieldInput,
    FieldInputValue, OpenVaultManifest, RecordInput, UnlockedIdentity,
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

// ---------------------------------------------------------------------------
// Update path: same block_uuid replaces the existing entry
// ---------------------------------------------------------------------------

#[test]
fn save_block_update_replaces_existing_entry_and_advances_clock() {
    let (_tmp, identity, manifest) = fresh_writable_vault();

    let v1 = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "v1".to_string(),
        records: vec![],
    };
    save_block(&identity, &manifest, v1, DEVICE_UUID, NOW_MS_BASE).expect("first save");
    let after_v1 = manifest.find_block(&NEW_BLOCK_UUID).expect("v1 present");
    let created_at_v1 = after_v1.created_at_ms;

    let v2 = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "v2".to_string(),
        records: vec![],
    };
    save_block(&identity, &manifest, v2, DEVICE_UUID, NOW_MS_BASE + 1_000).expect("second save");
    let after_v2 = manifest.find_block(&NEW_BLOCK_UUID).expect("v2 present");
    assert_eq!(
        after_v2.block_name, "v2",
        "block_name should reflect the second save",
    );
    assert_eq!(
        after_v2.created_at_ms, created_at_v1,
        "created_at_ms must be preserved across updates",
    );
    assert!(
        after_v2.last_modified_ms > after_v1.last_modified_ms,
        "last_modified_ms must advance",
    );
}

// ---------------------------------------------------------------------------
// Empty records vec is allowed
// ---------------------------------------------------------------------------

#[test]
fn save_block_with_empty_records_succeeds() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let pre_count = manifest.block_count();
    let input = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "empty".to_string(),
        records: vec![],
    };
    save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE).expect("empty save");
    assert_eq!(manifest.block_count(), pre_count + 1);
    let summary = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable");
    assert_eq!(summary.block_name, "empty");
}

// ---------------------------------------------------------------------------
// Persists across re-open
// ---------------------------------------------------------------------------

#[test]
fn save_block_persists_to_disk_visible_to_fresh_open() {
    let tmp;
    {
        let (held_tmp, identity, manifest) = fresh_writable_vault();
        let input = BlockInput {
            block_uuid: NEW_BLOCK_UUID,
            block_name: "persisted".to_string(),
            records: vec![RecordInput {
                record_uuid: NEW_RECORD_UUID,
                fields: vec![FieldInput {
                    name: "k".to_string(),
                    value: FieldInputValue::Text(SecretString::from("v")),
                }],
            }],
        };
        save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE).expect("save");
        // Drop the original handles by ending the inner scope; tmp lives on.
        identity.wipe();
        manifest.wipe();
        tmp = held_tmp;
    }

    // Re-open the same on-disk vault.
    let out2 = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).expect("re-open");
    let summary = out2
        .manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block visible on re-open");
    assert_eq!(summary.block_name, "persisted");
    let output = read_block(&out2.identity, &out2.manifest, &NEW_BLOCK_UUID).expect("read");
    let r = output.record_at(0).expect("record present");
    assert_eq!(
        r.field_by_name("k").unwrap().expose_text().as_deref(),
        Some("v")
    );
}

// ---------------------------------------------------------------------------
// Wiped-handle short-circuits (CorruptVault)
// ---------------------------------------------------------------------------

#[test]
fn save_block_on_wiped_manifest_returns_corrupt_vault() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    manifest.wipe();
    let input = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "x".to_string(),
        records: vec![],
    };
    let err = save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE).unwrap_err();
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.contains("manifest"),
                "detail should name the manifest handle: {detail}",
            );
        }
        other => panic!("expected CorruptVault, got: {other:?}"),
    }
}

#[test]
fn save_block_on_wiped_identity_returns_corrupt_vault() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    identity.wipe();
    let input = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "x".to_string(),
        records: vec![],
    };
    let err = save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE).unwrap_err();
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.contains("identity"),
                "detail should name the identity handle: {detail}",
            );
        }
        other => panic!("expected CorruptVault, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Failure invariant: chmod the vault folder read-only; assert in-memory unchanged
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn save_block_failure_leaves_in_memory_manifest_unchanged() {
    use std::os::unix::fs::PermissionsExt;

    let (tmp, identity, manifest) = fresh_writable_vault();
    let pre_count = manifest.block_count();

    // chmod the vault folder read-only so write_atomic / create_dir_all
    // for blocks/ fails. Any path that reaches an I/O failure inside
    // core::save_block surfaces as FolderInvalid via map_core_vault_error.
    let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
    perms.set_mode(0o555);
    fs::set_permissions(tmp.path(), perms).unwrap();

    let input = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "doomed".to_string(),
        records: vec![],
    };
    let result = save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE);

    // Restore writable perms so TempDir's Drop can clean up.
    let mut restored = fs::metadata(tmp.path()).unwrap().permissions();
    restored.set_mode(0o755);
    fs::set_permissions(tmp.path(), restored).unwrap();

    // The save must have failed with a typed error — either FolderInvalid
    // (the create_dir_all / write_atomic path) or SaveCryptoFailure (if
    // the failure manifested upstream of IO). Both are acceptable for
    // the failure-invariant property.
    let err = result.expect_err("save_block must fail on a read-only vault folder");
    assert!(
        matches!(
            err,
            FfiVaultError::FolderInvalid { .. } | FfiVaultError::SaveCryptoFailure { .. },
        ),
        "expected FolderInvalid or SaveCryptoFailure, got: {err:?}",
    );

    // CRITICAL: in-memory state must equal pre-call state.
    assert_eq!(
        manifest.block_count(),
        pre_count,
        "block_count() must be unchanged after a failed save",
    );
    assert!(
        manifest.find_block(&NEW_BLOCK_UUID).is_none(),
        "the new block_uuid must not appear in the manifest after a failed save",
    );
}
