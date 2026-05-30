//! D.1.4 native-`BlockPlaintext` edit primitives. These keep untouched
//! records as native [`core::Record`](secretary_core::vault::record::Record)
//! (never lowered through the lossy `RecordInput` / foreign handles), so
//! forward-compat `unknown` survives at block / record / field level and
//! sibling secrets never cross into the foreign caller. The whole-block
//! plaintext lives only here, transiently, and zeroizes on drop.
//!
//! Each mutating primitive (`append_record` / `edit_record`) decrypts the
//! target block to a native [`BlockPlaintext`] via
//! [`decrypt_block_plaintext`], mutates only the target record, and
//! re-encrypts through `core::vault::save_block`. `create_block` is the
//! insert path: a fresh empty `BlockPlaintext`.

mod content;
pub use content::RecordContent;

use std::collections::BTreeMap;

use rand_core::OsRng;
use secretary_core::vault::block::BlockPlaintext;
use secretary_core::vault::record::{Record, RecordField};
use secretary_core::vault::OpenVault;

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::save::orchestration::map_core_vault_error;
use crate::vault::OpenVaultManifest;

/// v1 block-body version (matches `BlockInput::into_block_plaintext`).
const BLOCK_VERSION_V1: u32 = 1;
/// v1 record-schema version (matches `BlockInput::into_block_plaintext`).
const SCHEMA_VERSION_V1: u32 = 1;

/// Create a brand-new (empty) block. Insert path: a fresh `block_uuid`
/// that does not yet appear in the manifest.
///
/// # Errors
///
/// [`FfiVaultError::CorruptVault`] (wiped handle), or the save-tail error
/// surface ([`FfiVaultError::FolderInvalid`] / [`FfiVaultError::SaveCryptoFailure`]).
pub fn create_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    block_name: String,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let plaintext = BlockPlaintext {
        block_version: BLOCK_VERSION_V1,
        block_uuid,
        block_name,
        schema_version: SCHEMA_VERSION_V1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    };
    save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}

/// Append a new record to an existing block, preserving all sibling records
/// — and every `unknown` map at block / record / field level — natively.
///
/// # Errors
///
/// [`FfiVaultError::BlockNotFound`] (block UUID not in the manifest),
/// [`FfiVaultError::CorruptVault`] (decrypt failure / wiped handle), or the
/// save-tail error surface.
pub fn append_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    record_uuid: [u8; 16],
    content: RecordContent,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    let record = build_new_record(record_uuid, content, device_uuid, now_ms);
    plaintext.records.push(record);
    save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}

/// Replace one live record's editable part (type / tags / fields),
/// preserving its `record_uuid`, `created_at_ms`, record-level `unknown`,
/// `tombstoned_at_ms`, and — by name-matching — each kept field's
/// `unknown`. A field absent from the delta is dropped (the user removed
/// it). Siblings are untouched. The record-level `last_mod_ms` bumps to
/// `now_ms`.
///
/// Per-field clocks are bumped only on a genuine change: a field whose
/// value is byte-identical to the prior record keeps its prior `last_mod`
/// and `device_uuid` (the editing device touched the record but not that
/// field's value). This matters under cross-device sync — core's
/// field-level merge is `last_mod` last-write-wins, so bumping an
/// untouched field's clock here would let this device's stale-but-newer
/// copy clobber a concurrent edit of that field on another device. Only
/// fields whose value actually changed (or are newly added) get `now_ms`
/// and the editing `device_uuid`.
///
/// # Errors
///
/// [`FfiVaultError::RecordNotFound`] (no live record with this UUID in the
/// block), [`FfiVaultError::BlockNotFound`], [`FfiVaultError::CorruptVault`],
/// or the save-tail error surface.
pub fn edit_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    record_uuid: [u8; 16],
    content: RecordContent,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    let idx = plaintext
        .records
        .iter()
        .position(|r| r.record_uuid == record_uuid && !r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound {
            uuid_hex: hex::encode(record_uuid),
        })?;

    let existing = &plaintext.records[idx];
    let created_at_ms = existing.created_at_ms;
    let tombstoned_at_ms = existing.tombstoned_at_ms;
    let record_unknown = existing.unknown.clone();
    // Snapshot the prior fields by name so the rebuild below can, per field:
    // carry forward its forward-compat `unknown`, and — when the new value is
    // byte-identical — preserve its `last_mod` / `device_uuid`. A field absent
    // from the delta is simply not looked up here, so it (and its unknowns) is
    // dropped — the user deleted it.
    let prior_fields: BTreeMap<String, RecordField> = existing.fields.clone();

    let mut fields_map: BTreeMap<String, RecordField> = BTreeMap::new();
    for f in content.fields {
        let value = f.value.into_core_value();
        // `RecordFieldValue`'s `==` is constant-time (its `SecretString` /
        // `SecretBytes` payloads compare via `subtle::ConstantTimeEq`), so the
        // unchanged-value gate adds no value-dependent timing side channel.
        let (last_mod, field_device_uuid, unknown) = match prior_fields.get(&f.name) {
            // Unchanged value: keep the prior field clock + authoring device.
            Some(prior) if prior.value == value => {
                (prior.last_mod, prior.device_uuid, prior.unknown.clone())
            }
            // Changed value (same field name): bump the clock to this edit,
            // but still carry forward the field's forward-compat `unknown`.
            Some(prior) => (now_ms, device_uuid, prior.unknown.clone()),
            // Newly added field: fresh clock, empty unknown.
            None => (now_ms, device_uuid, BTreeMap::new()),
        };
        fields_map.insert(
            f.name,
            RecordField {
                value,
                last_mod,
                device_uuid: field_device_uuid,
                unknown,
            },
        );
    }

    plaintext.records[idx] = Record {
        record_uuid,
        record_type: content.record_type,
        fields: fields_map,
        tags: content.tags,
        created_at_ms,
        last_mod_ms: now_ms,
        tombstone: false,
        tombstoned_at_ms,
        unknown: record_unknown,
    };
    save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}

/// Build a fresh `core::Record` from a `RecordContent` delta. New records
/// get empty record-level and per-field `unknown` maps and a zero
/// `tombstoned_at_ms` (mirrors `RecordInput::into_core_record`).
fn build_new_record(
    record_uuid: [u8; 16],
    content: RecordContent,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Record {
    let mut fields_map: BTreeMap<String, RecordField> = BTreeMap::new();
    for f in content.fields {
        fields_map.insert(
            f.name,
            RecordField {
                value: f.value.into_core_value(),
                last_mod: now_ms,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        );
    }
    Record {
        record_uuid,
        record_type: content.record_type,
        fields: fields_map,
        tags: content.tags,
        created_at_ms: now_ms,
        last_mod_ms: now_ms,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// Shared save tail: snapshot the manifest, build the temporary
/// [`OpenVault`], call `core::save_block` with owner-only recipients, write
/// the mutated manifest back into the handle. Mirrors
/// [`crate::save::save_block`]'s machinery (its Steps 1, 2, 4, 5, 6) over a
/// pre-built native `BlockPlaintext` rather than a `BlockInput`.
fn save_plaintext(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    plaintext: BlockPlaintext,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;
    let identity_clone =
        identity
            .clone_inner_bundle()
            .ok_or_else(|| FfiVaultError::CorruptVault {
                detail: "identity handle has been closed".into(),
            })?;

    // Clone owner_card a second time so it can serve as both the
    // OpenVault.owner_card field AND the owner-only recipients list.
    let recipients_list = [owner_card.clone()];
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    secretary_core::vault::save_block(
        &vault_folder,
        &mut open_vault,
        plaintext,
        &recipients_list,
        device_uuid,
        now_ms,
        &mut OsRng,
    )
    .map_err(map_core_vault_error)?;

    // Test-only concurrent-wipe-race hook (see issue #35 / save::save_block).
    manifest.run_mid_call_hook();
    manifest
        .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
        .map_err(|e| FfiVaultError::CorruptVault {
            detail: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::{Path, PathBuf};

    use secretary_core::crypto::secret::SecretString;
    use secretary_core::vault::record::{RecordFieldValue, UnknownValue};

    use crate::save::input::{FieldInput, FieldInputValue};
    use crate::{open_vault_with_password, OpenVaultOutput};

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

    /// Open a writable copy of golden_vault_001 in a fresh tempdir. The
    /// tempdir is returned so the caller keeps it alive for the test.
    fn open_writable_golden_001() -> (tempfile::TempDir, OpenVaultOutput) {
        let src = fixture_folder("golden_vault_001");
        let tmp = tempfile::tempdir().expect("tempdir");
        copy_dir_recursive(&src, tmp.path());
        let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
            .expect("open writable copy of golden_vault_001");
        (tmp, out)
    }

    /// The correctness keystone for the whole D.1.4 slice: an edit must
    /// preserve forward-compat `unknown` at ALL THREE levels (block /
    /// record / field) for the data it keeps, and drop a removed field's
    /// unknowns along with the field. Constructed via `core` because the
    /// bridge input types intentionally cannot mint `unknown` keys.
    #[test]
    fn edit_record_preserves_unknown_at_all_three_levels() {
        let (_tmp, opened) = open_writable_golden_001();
        let block_uuid = [0x51u8; 16];
        let record_uuid = [0x52u8; 16];

        // A single CBOR int (0x01) is a valid canonical-CBOR unknown value.
        let mk = || UnknownValue::from_canonical_cbor(&[0x01]).expect("canonical cbor unknown");

        // 1. Build a native BlockPlaintext with synthetic unknowns at all
        //    three levels, plus a "drop" field (no unknown) that the edit
        //    delta will omit.
        let mut block_unknown = BTreeMap::new();
        block_unknown.insert("x_block".to_string(), mk());

        let mut record_unknown = BTreeMap::new();
        record_unknown.insert("x_rec".to_string(), mk());

        let mut keep_unknown = BTreeMap::new();
        keep_unknown.insert("x_fld".to_string(), mk());

        let mut fields = BTreeMap::new();
        fields.insert(
            "keep".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from("v0")),
                last_mod: 1_000,
                device_uuid: DEVICE_UUID,
                unknown: keep_unknown,
            },
        );
        fields.insert(
            "drop".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from("gone")),
                last_mod: 1_000,
                device_uuid: DEVICE_UUID,
                unknown: BTreeMap::new(),
            },
        );

        let plaintext = BlockPlaintext {
            block_version: BLOCK_VERSION_V1,
            block_uuid,
            block_name: "Keystone".to_string(),
            schema_version: SCHEMA_VERSION_V1,
            records: vec![Record {
                record_uuid,
                record_type: "login".to_string(),
                fields,
                tags: vec![],
                created_at_ms: 1_000,
                last_mod_ms: 1_000,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: record_unknown,
            }],
            unknown: block_unknown,
        };

        // 2. Save it through the same OpenVault path the primitives use.
        save_plaintext(
            &opened.identity,
            &opened.manifest,
            plaintext,
            DEVICE_UUID,
            1_000,
        )
        .expect("save synthetic plaintext");

        // 3. Edit the record: keep "keep" (changed value), omit "drop".
        edit_record(
            &opened.identity,
            &opened.manifest,
            block_uuid,
            record_uuid,
            RecordContent {
                record_type: "login".to_string(),
                tags: vec!["edited".to_string()],
                fields: vec![FieldInput {
                    name: "keep".to_string(),
                    value: FieldInputValue::Text(SecretString::from("v1")),
                }],
            },
            DEVICE_UUID,
            2_000,
        )
        .expect("edit_record");

        // 4. Re-decrypt natively and assert the three-level preservation.
        let after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &block_uuid)
            .expect("decrypt after edit");

        // block-level unknown preserved.
        assert!(
            after.unknown.contains_key("x_block"),
            "block-level unknown 'x_block' must survive an edit"
        );

        let rec = after
            .records
            .iter()
            .find(|r| r.record_uuid == record_uuid)
            .expect("edited record present");

        // record-level unknown preserved.
        assert!(
            rec.unknown.contains_key("x_rec"),
            "record-level unknown 'x_rec' must survive an edit"
        );

        // edited/kept field carries forward its field-level unknown.
        let keep = rec.fields.get("keep").expect("kept field present");
        assert!(
            keep.unknown.contains_key("x_fld"),
            "kept field's field-level unknown 'x_fld' must survive an edit"
        );

        // the value was actually updated, proving this is the edited record.
        match &keep.value {
            RecordFieldValue::Text(s) => assert_eq!(*s, SecretString::from("v1")),
            other => panic!("expected Text, got {other:?}"),
        }

        // the omitted field (and its unknowns) is gone — correct, the user
        // deleted it.
        assert!(
            !rec.fields.contains_key("drop"),
            "a field absent from the edit delta must be dropped"
        );

        // record identity / creation time / tags preserved-or-updated.
        assert_eq!(rec.record_uuid, record_uuid);
        assert_eq!(rec.created_at_ms, 1_000, "created_at_ms preserved on edit");
        assert_eq!(rec.last_mod_ms, 2_000, "last_mod_ms bumped to now_ms");
        assert_eq!(rec.tags, vec!["edited".to_string()]);
    }

    /// An edit must bump a field's `last_mod` / `device_uuid` ONLY when its
    /// value actually changed. A field left byte-identical keeps its prior
    /// clock and authoring device, so this device's untouched copy can't
    /// clobber a concurrent edit of that field on another device under core's
    /// field-level last-write-wins merge.
    #[test]
    fn edit_record_preserves_field_clock_for_unchanged_value() {
        let (_tmp, opened) = open_writable_golden_001();
        let block_uuid = [0x71u8; 16];
        let record_uuid = [0x72u8; 16];

        const ORIG_DEVICE: [u8; 16] = [0x07; 16];
        const EDIT_DEVICE: [u8; 16] = [0x09; 16];

        // Seed a record with two fields authored by ORIG_DEVICE at t=1000.
        let mut fields = BTreeMap::new();
        fields.insert(
            "keep".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from("unchanged")),
                last_mod: 1_000,
                device_uuid: ORIG_DEVICE,
                unknown: BTreeMap::new(),
            },
        );
        fields.insert(
            "change".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from("v0")),
                last_mod: 1_000,
                device_uuid: ORIG_DEVICE,
                unknown: BTreeMap::new(),
            },
        );
        let plaintext = BlockPlaintext {
            block_version: BLOCK_VERSION_V1,
            block_uuid,
            block_name: "Clocks".to_string(),
            schema_version: SCHEMA_VERSION_V1,
            records: vec![Record {
                record_uuid,
                record_type: "login".to_string(),
                fields,
                tags: vec![],
                created_at_ms: 1_000,
                last_mod_ms: 1_000,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: BTreeMap::new(),
            }],
            unknown: BTreeMap::new(),
        };
        save_plaintext(
            &opened.identity,
            &opened.manifest,
            plaintext,
            ORIG_DEVICE,
            1_000,
        )
        .expect("seed plaintext");

        // Edit on a DIFFERENT device at t=2000: "keep" identical, "change" updated.
        edit_record(
            &opened.identity,
            &opened.manifest,
            block_uuid,
            record_uuid,
            RecordContent {
                record_type: "login".to_string(),
                tags: vec!["edited".to_string()],
                fields: vec![
                    FieldInput {
                        name: "keep".to_string(),
                        value: FieldInputValue::Text(SecretString::from("unchanged")),
                    },
                    FieldInput {
                        name: "change".to_string(),
                        value: FieldInputValue::Text(SecretString::from("v1")),
                    },
                ],
            },
            EDIT_DEVICE,
            2_000,
        )
        .expect("edit_record");

        let after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &block_uuid)
            .expect("decrypt after edit");
        let rec = after
            .records
            .iter()
            .find(|r| r.record_uuid == record_uuid)
            .expect("edited record present");

        // Unchanged field: prior clock + authoring device survive.
        let keep = rec.fields.get("keep").expect("kept field present");
        assert_eq!(
            keep.last_mod, 1_000,
            "unchanged field must keep its prior last_mod"
        );
        assert_eq!(
            keep.device_uuid, ORIG_DEVICE,
            "unchanged field must keep its prior authoring device"
        );

        // Changed field: bumped to this edit.
        let change = rec.fields.get("change").expect("changed field present");
        assert_eq!(
            change.last_mod, 2_000,
            "changed field must bump last_mod to now_ms"
        );
        assert_eq!(
            change.device_uuid, EDIT_DEVICE,
            "changed field must record the editing device"
        );
    }
}
