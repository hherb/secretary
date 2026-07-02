//! Integration tests for `read_block` pinned against the
//! `golden_vault_001` KAT. Lives in `tests/` (not inline `#[cfg(test)]`)
//! so the production sub-files in `src/record/` stay focused; the
//! tests here exercise the full open + read flow against on-disk
//! fixtures.
//!
//! KAT source of truth: `core/tests/data/golden_vault_001_inputs.json`.

use std::fs;
use std::path::PathBuf;

use secretary_ffi_bridge::{
    open_vault_with_password, open_vault_with_recovery, read_block, FfiVaultError,
};

/// Path to the golden_vault_NNN folder. CARGO_MANIFEST_DIR is
/// ffi/secretary-ffi-bridge/, so we walk up to core/tests/data/.
fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

/// Pinned block UUID for golden_vault_001's single block (matches the
/// hyphenated on-disk filename `11223344-5566-7788-99aa-bbccddeeff00`).
const VAULT_001_BLOCK_UUID: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const VAULT_001_BLOCK_NAME: &str = "Personal logins";
const VAULT_001_RECORD_UUID: [u8; 16] = [
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
];
const VAULT_001_DEVICE_UUID: [u8; 16] = [
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
];
const VAULT_001_TIMESTAMP_MS: u64 = 2_000_000_000_000;
const VAULT_001_RECORD_TYPE: &str = "login";
const VAULT_001_TAG: &str = "work";
const VAULT_001_USERNAME_VALUE: &str = "owner@example.com";
const VAULT_001_PASSWORD_VALUE: &str = "hunter2";

/// Hyphenated form of VAULT_001_BLOCK_UUID — matches the on-disk
/// filename convention. Hard-coded here so the integration tests don't
/// depend on a private bridge helper.
const VAULT_001_BLOCK_FILENAME: &str = "11223344-5566-7788-99aa-bbccddeeff00.cbor.enc";

#[test]
fn read_block_returns_one_record_two_fields_for_golden_vault_001() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).expect("open should succeed");
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false)
        .expect("read_block should succeed");
    assert_eq!(block.record_count(), 1);
    assert_eq!(block.block_name(), VAULT_001_BLOCK_NAME);
    assert_eq!(block.block_uuid(), VAULT_001_BLOCK_UUID);
    let record = block.record_at(0).expect("record at index 0");
    assert_eq!(record.field_count(), 2);
}

#[test]
fn read_block_record_metadata_matches_pinned_kat() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record = block.record_at(0).unwrap();
    assert_eq!(record.record_uuid(), VAULT_001_RECORD_UUID);
    assert_eq!(record.record_type(), VAULT_001_RECORD_TYPE);
    assert_eq!(record.tags(), vec![VAULT_001_TAG.to_string()]);
    assert!(!record.tombstone());
    assert_eq!(record.created_at_ms(), VAULT_001_TIMESTAMP_MS);
    assert_eq!(record.last_mod_ms(), VAULT_001_TIMESTAMP_MS);
}

#[test]
fn read_block_field_names_in_btreemap_order() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record = block.record_at(0).unwrap();
    assert_eq!(
        record.field_names(),
        vec!["password".to_string(), "username".to_string()],
    );
}

#[test]
fn read_block_field_text_payload_matches_pinned_kat() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record = block.record_at(0).unwrap();
    let pw_field = record
        .field_by_name("password")
        .expect("password field must exist");
    let user_field = record
        .field_by_name("username")
        .expect("username field must exist");
    assert_eq!(
        pw_field.expose_text(),
        Some(VAULT_001_PASSWORD_VALUE.to_string()),
    );
    assert_eq!(
        user_field.expose_text(),
        Some(VAULT_001_USERNAME_VALUE.to_string()),
    );
}

#[test]
fn read_block_field_metadata_matches_pinned_kat() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record = block.record_at(0).unwrap();
    let pw_field = record.field_by_name("password").unwrap();
    let user_field = record.field_by_name("username").unwrap();
    assert_eq!(pw_field.last_mod_ms(), VAULT_001_TIMESTAMP_MS);
    assert_eq!(user_field.last_mod_ms(), VAULT_001_TIMESTAMP_MS);
    assert_eq!(pw_field.device_uuid(), VAULT_001_DEVICE_UUID);
    assert_eq!(user_field.device_uuid(), VAULT_001_DEVICE_UUID);
}

#[test]
fn read_block_field_is_text_not_bytes() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record = block.record_at(0).unwrap();
    let pw_field = record.field_by_name("password").unwrap();
    assert!(pw_field.is_text());
    assert!(!pw_field.is_bytes());
    assert_eq!(pw_field.expose_bytes(), None);
}

#[test]
fn read_block_unknown_uuid_returns_block_not_found() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let unknown = [0u8; 16];
    let err = read_block(&out.identity, &out.manifest, &unknown, false).unwrap_err();
    let FfiVaultError::BlockNotFound { uuid_hex } = err else {
        panic!("expected BlockNotFound, got {err:?}");
    };
    assert_eq!(uuid_hex, "00000000000000000000000000000000");
}

/// Helper: copy the full golden_vault_001 tree into a tempdir. Returns
/// the new folder path. Used by the corruption tests below to mutate
/// the on-disk layout without touching the shared fixture.
fn copy_golden_to_tempdir() -> tempfile::TempDir {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::TempDir::new().expect("tempdir");
    for name in ["vault.toml", "identity.bundle.enc", "manifest.cbor.enc"] {
        fs::copy(src.join(name), tmp.path().join(name)).unwrap();
    }
    fs::create_dir_all(tmp.path().join("contacts")).unwrap();
    for entry in fs::read_dir(src.join("contacts")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            tmp.path().join("contacts").join(entry.file_name()),
        )
        .unwrap();
    }
    fs::create_dir_all(tmp.path().join("blocks")).unwrap();
    for entry in fs::read_dir(src.join("blocks")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            tmp.path().join("blocks").join(entry.file_name()),
        )
        .unwrap();
    }
    tmp
}

#[test]
fn open_vault_corrupt_block_file_returns_corrupt_vault() {
    // C.1.1b D6: `open_vault` re-hashes every on-disk block file at
    // open time and surfaces a typed `BlockFingerprintMismatch` (folded
    // to `FfiVaultError::CorruptVault` by the bridge mapper) when the
    // bytes don't match the manifest's `BlockEntry.fingerprint`. Prior
    // to D6 the bridge tolerated the mismatch at open time and only
    // caught it on `read_block`; flipping the first byte of the block
    // envelope is now visible to `open_vault` itself.
    let tmp = copy_golden_to_tempdir();
    let block_path = tmp.path().join("blocks").join(VAULT_001_BLOCK_FILENAME);
    let mut bytes = fs::read(&block_path).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&block_path, &bytes).unwrap();
    let err = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "got {err:?}",
    );
}

#[test]
fn open_vault_missing_block_file_returns_corrupt_vault() {
    // #350/#88: a deleted block file surfaces during `open_vault`'s
    // per-block fingerprint check as the UUID-tagged
    // `VaultError::BlockFileMissing`, which the bridge folds to
    // `FfiVaultError::CorruptVault` alongside `BlockFingerprintMismatch`.
    // Previously this routed to the generic NotFound `FolderInvalid`
    // bucket with no UUID in the message; this test now pins the typed
    // routing.
    let tmp = copy_golden_to_tempdir();
    fs::remove_file(tmp.path().join("blocks").join(VAULT_001_BLOCK_FILENAME)).unwrap();
    let err = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap_err();
    let FfiVaultError::CorruptVault { detail } = err else {
        panic!("expected CorruptVault, got {err:?}");
    };
    assert!(
        detail.contains("file missing from blocks/"),
        "detail: {detail}"
    );
    assert!(
        detail.contains(&format!("{VAULT_001_BLOCK_UUID:02x?}")),
        "detail must carry the failing block uuid: {detail}"
    );
}

#[test]
fn block_read_output_wipe_drops_records() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record_clone = block.record_at(0).expect("record at 0");
    block.wipe();
    assert_eq!(block.record_count(), 0);
    assert!(block.record_at(0).is_none());
    assert_eq!(record_clone.record_uuid(), [0u8; 16]);
    assert_eq!(record_clone.field_count(), 0);
    block.wipe();
    block.wipe();
}

#[test]
fn record_wipe_drops_field_handles() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record = block.record_at(0).unwrap();
    let field_clone = record.field_by_name("password").unwrap();
    record.wipe();
    assert_eq!(record.field_count(), 0);
    assert!(record.field_by_name("password").is_none());
    assert!(record.field_at(0).is_none());
    assert_eq!(field_clone.expose_text(), None);
    assert_eq!(field_clone.name(), "");
    record.wipe();
}

#[test]
fn field_handle_arc_clones_share_wiped_state() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    let record_a = block.record_at(0).unwrap();
    let record_b = block.record_at(0).unwrap();
    let field_a = record_a.field_by_name("password").unwrap();
    let field_b = record_b.field_by_name("password").unwrap();
    assert_eq!(
        field_a.expose_text(),
        Some(VAULT_001_PASSWORD_VALUE.to_string()),
    );
    assert_eq!(
        field_b.expose_text(),
        Some(VAULT_001_PASSWORD_VALUE.to_string()),
    );
    field_a.wipe();
    assert_eq!(field_a.expose_text(), None);
    assert_eq!(field_b.expose_text(), None);
}

#[test]
fn read_block_after_open_vault_with_recovery_succeeds() {
    let folder = fixture_folder("golden_vault_001");
    let phrase: &[u8] = b"wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that";
    let out = open_vault_with_recovery(&folder, phrase).expect("recovery open");
    let block = read_block(&out.identity, &out.manifest, &VAULT_001_BLOCK_UUID, false).unwrap();
    assert_eq!(block.record_count(), 1);
    let record = block.record_at(0).unwrap();
    let pw_field = record.field_by_name("password").unwrap();
    assert_eq!(
        pw_field.expose_text(),
        Some(VAULT_001_PASSWORD_VALUE.to_string()),
    );
}
