//! D.1.4 edit primitives. Hermetic: a writable copy of golden_vault_001 per
//! test (crypto comes from the fixture — no hardcoded key material). These
//! cover the create/append/edit round-trip and sibling byte-faithfulness;
//! the three-level `unknown`-preservation keystone lives inside the bridge
//! crate's own `src/edit/mod.rs` `#[cfg(test)]` module (it needs
//! `pub(crate)` access to `decrypt_block_plaintext` for native-plaintext
//! assertions the foreign read surface can't express).

use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::SecretString;
use secretary_ffi_bridge::{
    append_record, create_block, edit_record, open_vault_with_password, read_block,
    resurrect_record, tombstone_record, BlockReadOutput, FieldInput, FieldInputValue,
    OpenVaultManifest, Record, RecordContent, UnlockedIdentity,
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

/// Opened writable golden-001 vault. Holds the tempdir alive for the test's
/// duration (dropping it cleans up the on-disk copy).
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
fn create_block_then_append_record_is_readable() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x31u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Logins".into(),
        DEVICE_UUID,
        1_715_000_000_000,
    )
    .expect("create_block");

    let record_uuid = [0x32u8; 16];
    append_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        RecordContent {
            record_type: "login".into(),
            tags: vec!["work".into()],
            fields: vec![FieldInput {
                name: "user".into(),
                value: FieldInputValue::Text(SecretString::from("alice")),
            }],
        },
        DEVICE_UUID,
        1_715_000_001_000,
    )
    .expect("append_record");

    let out = read_block(&opened.identity, &opened.manifest, &block_uuid).expect("read");
    assert_eq!(out.record_count(), 1);
    let r = out.record_at(0).unwrap();
    assert_eq!(r.record_type(), "login");
    assert_eq!(r.record_uuid(), record_uuid);
    assert_eq!(r.tags(), vec!["work".to_string()]);
    let user = r.field_by_name("user").expect("user field present");
    assert_eq!(user.expose_text().as_deref(), Some("alice"));
    out.wipe();
}

#[test]
fn edit_record_replaces_target_and_leaves_siblings_byte_faithful() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x41u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "B".into(),
        DEVICE_UUID,
        1_000,
    )
    .unwrap();
    let a = [0xA0u8; 16];
    let b = [0xB0u8; 16];
    for (uuid, user) in [(a, "alice"), (b, "bob")] {
        append_record(
            &opened.identity,
            &opened.manifest,
            block_uuid,
            uuid,
            RecordContent {
                record_type: "login".into(),
                tags: vec![],
                fields: vec![FieldInput {
                    name: "user".into(),
                    value: FieldInputValue::Text(SecretString::from(user)),
                }],
            },
            DEVICE_UUID,
            2_000,
        )
        .unwrap();
    }

    // Edit A; B must be untouched.
    edit_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        a,
        RecordContent {
            record_type: "login".into(),
            tags: vec!["edited".into()],
            fields: vec![FieldInput {
                name: "user".into(),
                value: FieldInputValue::Text(SecretString::from("alice2")),
            }],
        },
        DEVICE_UUID,
        3_000,
    )
    .unwrap();

    let out = read_block(&opened.identity, &opened.manifest, &block_uuid).unwrap();
    let find = |uuid: [u8; 16]| {
        (0..out.record_count())
            .map(|i| out.record_at(i).unwrap())
            .find(|r| r.record_uuid() == uuid)
            .unwrap()
    };
    let ra = find(a);
    assert_eq!(ra.tags(), vec!["edited".to_string()]);
    assert_eq!(
        ra.field_by_name("user").unwrap().expose_text().as_deref(),
        Some("alice2")
    );
    let rb = find(b);
    assert_eq!(
        rb.field_at(0).unwrap().expose_text().unwrap(),
        "bob",
        "sibling B must survive untouched"
    );
    out.wipe();
}

#[test]
fn edit_record_missing_uuid_is_record_not_found() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x61u8; 16];
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "B".into(),
        DEVICE_UUID,
        1_000,
    )
    .unwrap();

    let err = edit_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        [0x99u8; 16],
        RecordContent {
            record_type: "login".into(),
            tags: vec![],
            fields: vec![],
        },
        DEVICE_UUID,
        2_000,
    )
    .expect_err("editing an absent record must fail");
    assert!(
        matches!(
            err,
            secretary_ffi_bridge::FfiVaultError::RecordNotFound { .. }
        ),
        "expected RecordNotFound, got {err:?}"
    );
}

/// Helper: create a block and append one `user`=`alice` login record.
/// Returns `(block_uuid, record_uuid)`.
fn block_with_alice(opened: &Opened, block_uuid: [u8; 16], record_uuid: [u8; 16]) {
    create_block(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        "Logins".into(),
        DEVICE_UUID,
        1_000,
    )
    .expect("create_block");
    append_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        RecordContent {
            record_type: "login".into(),
            tags: vec![],
            fields: vec![FieldInput {
                name: "user".into(),
                value: FieldInputValue::Text(SecretString::from("alice")),
            }],
        },
        DEVICE_UUID,
        2_000,
    )
    .expect("append_record");
}

/// Helper: find a record handle by UUID in a read-block output.
fn find_record(out: &BlockReadOutput, uuid: [u8; 16]) -> Option<Record> {
    (0..out.record_count())
        .map(|i| out.record_at(i).unwrap())
        .find(|r| r.record_uuid() == uuid)
}

#[test]
fn tombstone_record_hides_from_read_block() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x81u8; 16];
    let record_uuid = [0x82u8; 16];
    block_with_alice(&opened, block_uuid, record_uuid);

    tombstone_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        DEVICE_UUID,
        3_000,
    )
    .expect("tombstone_record");

    // The record is STILL present in the block file (soft-delete), but its
    // tombstone flag is now set.
    let out = read_block(&opened.identity, &opened.manifest, &block_uuid).expect("read");
    let found = find_record(&out, record_uuid).expect("tombstoned record still present");
    assert!(
        found.tombstone(),
        "tombstoned record must report tombstone()"
    );
    out.wipe();
}

#[test]
fn resurrect_record_clears_tombstone_and_keeps_fields() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x91u8; 16];
    let record_uuid = [0x92u8; 16];
    block_with_alice(&opened, block_uuid, record_uuid);

    tombstone_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        DEVICE_UUID,
        3_000,
    )
    .expect("tombstone_record");

    resurrect_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        DEVICE_UUID,
        4_000,
    )
    .expect("resurrect_record");

    let out = read_block(&opened.identity, &opened.manifest, &block_uuid).expect("read");
    let r = find_record(&out, record_uuid).expect("resurrected record present");
    assert!(!r.tombstone(), "resurrected record must clear tombstone()");
    assert_eq!(
        r.field_by_name("user").unwrap().expose_text().as_deref(),
        Some("alice"),
        "resurrected record must keep its fields"
    );
    out.wipe();
}

#[test]
fn tombstone_record_errors_on_absent_or_already_tombstoned() {
    let opened = open_writable_golden_001();
    let block_uuid = [0xA1u8; 16];
    let record_uuid = [0xA2u8; 16];
    block_with_alice(&opened, block_uuid, record_uuid);

    // Absent record UUID → RecordNotFound.
    let err = tombstone_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        [0x99u8; 16],
        DEVICE_UUID,
        3_000,
    )
    .expect_err("tombstoning a missing record must fail");
    assert!(
        matches!(
            err,
            secretary_ffi_bridge::FfiVaultError::RecordNotFound { .. }
        ),
        "expected RecordNotFound, got {err:?}"
    );

    // Already-tombstoned record → RecordNotFound (no live record with this UUID).
    tombstone_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        DEVICE_UUID,
        3_000,
    )
    .expect("first tombstone");
    let err = tombstone_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        DEVICE_UUID,
        4_000,
    )
    .expect_err("re-tombstoning an already-tombstoned record must fail");
    assert!(
        matches!(
            err,
            secretary_ffi_bridge::FfiVaultError::RecordNotFound { .. }
        ),
        "expected RecordNotFound, got {err:?}"
    );
}

#[test]
fn resurrect_record_errors_on_absent_or_live() {
    let opened = open_writable_golden_001();
    let block_uuid = [0xB1u8; 16];
    let record_uuid = [0xB2u8; 16];
    block_with_alice(&opened, block_uuid, record_uuid);

    // Absent record UUID → RecordNotFound.
    let err = resurrect_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        [0x99u8; 16],
        DEVICE_UUID,
        3_000,
    )
    .expect_err("resurrecting a missing record must fail");
    assert!(
        matches!(
            err,
            secretary_ffi_bridge::FfiVaultError::RecordNotFound { .. }
        ),
        "expected RecordNotFound, got {err:?}"
    );

    // LIVE (never-tombstoned) record → RecordNotFound (no tombstoned record
    // with this UUID).
    let err = resurrect_record(
        &opened.identity,
        &opened.manifest,
        block_uuid,
        record_uuid,
        DEVICE_UUID,
        4_000,
    )
    .expect_err("resurrecting a live record must fail");
    assert!(
        matches!(
            err,
            secretary_ffi_bridge::FfiVaultError::RecordNotFound { .. }
        ),
        "expected RecordNotFound, got {err:?}"
    );
}

#[test]
fn append_record_to_missing_block_is_block_not_found() {
    let opened = open_writable_golden_001();
    let err = append_record(
        &opened.identity,
        &opened.manifest,
        [0xEEu8; 16],
        [0x32u8; 16],
        RecordContent {
            record_type: "login".into(),
            tags: vec![],
            fields: vec![],
        },
        DEVICE_UUID,
        1_000,
    )
    .expect_err("appending to a non-existent block must fail");
    assert!(
        matches!(
            err,
            secretary_ffi_bridge::FfiVaultError::BlockNotFound { .. }
        ),
        "expected BlockNotFound, got {err:?}"
    );
}
