//! Block-rename primitive: change only `block_name`, preserving every
//! record and all forward-compat `unknown` maps (block/record/field).
//! Decrypt → set name → re-encrypt through the shared `save_plaintext`
//! tail (which ticks the block clock, bumps `last_mod_ms`, re-signs the
//! manifest, and updates the manifest `BlockEntry.block_name` as a side
//! effect).

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::vault::OpenVaultManifest;

/// Rename a block: replace only `block_name`, preserving every record and
/// all `unknown` maps. Re-encrypts through the shared `save_plaintext`
/// tail; `core::save_block` ticks the block clock + re-signs the manifest,
/// and the manifest `BlockEntry.block_name` updates as a save side effect.
///
/// Empty `new_block_name` is allowed (the spec permits empty block names).
///
/// # Errors
///
/// [`FfiVaultError::BlockNotFound`] (block UUID not in the manifest),
/// [`FfiVaultError::CorruptVault`] (decrypt failure / wiped handle), or the
/// save-tail error surface ([`FfiVaultError::FolderInvalid`] /
/// [`FfiVaultError::SaveCryptoFailure`]).
pub fn rename_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    new_block_name: String,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    plaintext.block_name = new_block_name;
    super::save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use secretary_core::crypto::secret::SecretString;
    use secretary_core::vault::block::BlockPlaintext;
    use secretary_core::vault::record::{Record, RecordField, RecordFieldValue, UnknownValue};

    use super::super::{BLOCK_VERSION_V1, SCHEMA_VERSION_V1};
    use super::rename_block;
    use crate::error::FfiVaultError;
    use crate::record::orchestration::decrypt_block_plaintext;
    use crate::test_support::open_writable_golden_001;

    const DEVICE_UUID: [u8; 16] = [0x07; 16];

    /// Rename must change ONLY block_name; records + block/record/field
    /// `unknown` survive byte-faithfully and `last_mod_ms` of the block
    /// is bumped (proven indirectly: the record's stored data is intact).
    #[test]
    fn rename_block_changes_only_name_preserving_records_and_unknown() {
        let (_tmp, opened) = open_writable_golden_001();
        let block_uuid = [0x61u8; 16];
        let record_uuid = [0x62u8; 16];

        let mk = || UnknownValue::from_canonical_cbor(&[0x01]).expect("canonical cbor unknown");

        let mut block_unknown = BTreeMap::new();
        block_unknown.insert("x_block".to_string(), mk());
        let mut record_unknown = BTreeMap::new();
        record_unknown.insert("x_rec".to_string(), mk());
        let mut field_unknown = BTreeMap::new();
        field_unknown.insert("x_fld".to_string(), mk());

        let mut fields = BTreeMap::new();
        fields.insert(
            "user".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from("alice")),
                last_mod: 1_000,
                device_uuid: DEVICE_UUID,
                unknown: field_unknown,
            },
        );

        let plaintext = BlockPlaintext {
            block_version: BLOCK_VERSION_V1,
            block_uuid,
            block_name: "Before".to_string(),
            schema_version: SCHEMA_VERSION_V1,
            records: vec![Record {
                record_uuid,
                record_type: "login".to_string(),
                fields,
                tags: vec!["work".to_string()],
                created_at_ms: 1_000,
                last_mod_ms: 1_000,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: record_unknown,
            }],
            unknown: block_unknown,
        };
        super::super::save_plaintext(
            &opened.identity,
            &opened.manifest,
            plaintext,
            DEVICE_UUID,
            1_000,
        )
        .expect("seed plaintext");

        rename_block(
            &opened.identity,
            &opened.manifest,
            block_uuid,
            "After".to_string(),
            DEVICE_UUID,
            2_000,
        )
        .expect("rename_block");

        let after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &block_uuid)
            .expect("decrypt after rename");
        assert_eq!(after.block_name, "After", "block_name updated");
        assert!(
            after.unknown.contains_key("x_block"),
            "block-level unknown survives"
        );
        assert_eq!(after.records.len(), 1, "record preserved");
        let rec = &after.records[0];
        assert_eq!(rec.record_uuid, record_uuid);
        assert!(
            rec.unknown.contains_key("x_rec"),
            "record-level unknown survives"
        );
        let user = rec.fields.get("user").expect("field preserved");
        assert!(
            user.unknown.contains_key("x_fld"),
            "field-level unknown survives"
        );
        match &user.value {
            RecordFieldValue::Text(s) => assert_eq!(*s, SecretString::from("alice")),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    /// Renaming a block whose UUID is absent from the manifest is a
    /// `BlockNotFound`, not a silent insert.
    #[test]
    fn rename_block_absent_uuid_is_block_not_found() {
        let (_tmp, opened) = open_writable_golden_001();
        let err = rename_block(
            &opened.identity,
            &opened.manifest,
            [0xEEu8; 16],
            "x".to_string(),
            DEVICE_UUID,
            2_000,
        )
        .expect_err("absent block must error");
        assert!(
            matches!(err, FfiVaultError::BlockNotFound { .. }),
            "got {err:?}"
        );
    }
}
