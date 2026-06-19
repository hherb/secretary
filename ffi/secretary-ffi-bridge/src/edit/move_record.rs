//! Record-move primitive: copy a live record into the target block under a
//! fresh UUID, preserving all secret field values and every forward-compat
//! `unknown` (block / record / field), then tombstone the source record.
//!
//! The copy-before-delete order guarantees that the source survives a mid-move
//! crash (the vault is never in a state where the record has been deleted but
//! the copy has not yet landed). The target block is decrypted before the
//! source is tombstoned, so any decrypt failure on the target leaves the
//! source intact (`decrypt-target-before-write`).
//!
//! Both writes go through the shared [`super::save_plaintext`] tail
//! (which re-signs the manifest and ticks the block clock on each save).

use std::collections::BTreeMap;

use rand_core::{OsRng, RngCore};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::vault::OpenVaultManifest;
use secretary_core::vault::record::{Record, RecordField};

/// Move a live record from one block into another block under a fresh UUID.
///
/// The semantics are copy-before-delete:
/// 1. Decrypt the **target** block (fails fast if the block UUID is absent
///    from the manifest — the source is left untouched).
/// 2. Copy the source record into the target plaintext under a new CSPRNG UUID,
///    preserving all field values, field-level `unknown` maps, the record-level
///    `unknown` map, `record_type`, `tags`, and `created_at_ms`.  `last_mod_ms`
///    is set to `now_ms` (the copy was authored now by `device_uuid`); the copy
///    starts out live (`tombstone = false`, `tombstoned_at_ms = 0`).
/// 3. Save the mutated target block through [`super::save_plaintext`].
/// 4. Decrypt the **source** block and tombstone the source record via
///    [`super::tombstone::tombstone_record`].
///
/// # Same-block precondition
///
/// `src_block_uuid == dst_block_uuid` is enforced at the uniffi wrapper layer
/// (the bridge trusts its caller, exactly as it trusts UUID lengths via
/// `[u8; 16]`).
///
/// # Errors
///
/// - [`FfiVaultError::BlockNotFound`] — `dst_block_uuid` or `src_block_uuid`
///   not in the manifest.
/// - [`FfiVaultError::RecordNotFound`] — no LIVE record with `src_record_uuid`
///   in the source block.
/// - [`FfiVaultError::CorruptVault`] — decrypt or identity/manifest-handle
///   failure.
/// - Save-tail errors ([`FfiVaultError::FolderInvalid`] /
///   [`FfiVaultError::SaveCryptoFailure`]).
pub fn move_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    src_block_uuid: [u8; 16],
    src_record_uuid: [u8; 16],
    dst_block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<[u8; 16], FfiVaultError> {
    // Step 1 + 2 + 3: decrypt target, copy record, save target.
    let new_record_uuid = copy_record_into_target(
        identity,
        manifest,
        src_block_uuid,
        src_record_uuid,
        dst_block_uuid,
        device_uuid,
        now_ms,
    )?;

    // Step 4: tombstone the source record.
    super::tombstone::tombstone_record(
        identity,
        manifest,
        src_block_uuid,
        src_record_uuid,
        device_uuid,
        now_ms,
    )?;

    Ok(new_record_uuid)
}

/// Decrypt the target block, copy the source record (looked up in the source
/// block) into the target under a fresh UUID, and save the target block.
///
/// Returns the freshly-minted UUID assigned to the copy.
///
/// # Errors
///
/// [`FfiVaultError::BlockNotFound`] — target or source UUID absent from the
/// manifest.
/// [`FfiVaultError::RecordNotFound`] — no LIVE record with `src_record_uuid`
/// in the source block.
/// [`FfiVaultError::CorruptVault`] — decrypt failure.
/// Save-tail errors.
fn copy_record_into_target(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    src_block_uuid: [u8; 16],
    src_record_uuid: [u8; 16],
    dst_block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<[u8; 16], FfiVaultError> {
    // Decrypt source block first to locate the record.
    let src_plaintext = decrypt_block_plaintext(identity, manifest, &src_block_uuid)?;

    // Locate the live source record.
    let src_record = src_plaintext
        .records
        .iter()
        .find(|r| r.record_uuid == src_record_uuid && !r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound {
            uuid_hex: hex::encode(src_record_uuid),
        })?;

    // Mint a fresh UUID for the copy.
    let mut new_uuid_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut new_uuid_bytes);

    // Build the copied record.
    let copy = Record {
        record_uuid: new_uuid_bytes,
        record_type: src_record.record_type.clone(),
        fields: src_record
            .fields
            .iter()
            .map(|(name, field)| {
                (
                    name.clone(),
                    RecordField {
                        value: field.value.clone(),
                        last_mod: field.last_mod,
                        device_uuid: field.device_uuid,
                        unknown: field.unknown.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        tags: src_record.tags.clone(),
        created_at_ms: src_record.created_at_ms,
        last_mod_ms: now_ms,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: src_record.unknown.clone(),
    };

    // Decrypt target block and append copy.
    let mut dst_plaintext = decrypt_block_plaintext(identity, manifest, &dst_block_uuid)?;
    dst_plaintext.records.push(copy);

    // Save mutated target block.
    super::save_plaintext(identity, manifest, dst_plaintext, device_uuid, now_ms)?;

    Ok(new_uuid_bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use secretary_core::crypto::secret::SecretString;
    use secretary_core::vault::block::BlockPlaintext;
    use secretary_core::vault::record::{Record, RecordField, RecordFieldValue, UnknownValue};

    use super::super::test_support::open_writable_golden_001;
    use super::super::{BLOCK_VERSION_V1, SCHEMA_VERSION_V1};
    use super::move_record;
    use crate::error::FfiVaultError;
    use crate::record::orchestration::decrypt_block_plaintext;

    const DEVICE_UUID: [u8; 16] = [0x07; 16];

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Seed a block with one live record carrying synthetic unknowns at all
    /// three levels (block / record / field).
    fn seed_block_with_record(
        opened: &crate::OpenVaultOutput,
        block_uuid: [u8; 16],
        record_uuid: [u8; 16],
    ) {
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
            block_name: "Source".to_string(),
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
        super::super::save_plaintext(&opened.identity, &opened.manifest, plaintext, DEVICE_UUID, 1_000)
            .expect("seed source block");
    }

    /// Seed an empty target block.
    fn seed_empty_target(opened: &crate::OpenVaultOutput, block_uuid: [u8; 16]) {
        let plaintext = BlockPlaintext {
            block_version: BLOCK_VERSION_V1,
            block_uuid,
            block_name: "Target".to_string(),
            schema_version: SCHEMA_VERSION_V1,
            records: vec![],
            unknown: BTreeMap::new(),
        };
        super::super::save_plaintext(&opened.identity, &opened.manifest, plaintext, DEVICE_UUID, 1_000)
            .expect("seed target block");
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// Happy path: record appears in target under a FRESH UUID, source record
    /// is tombstoned, all three-level `unknown` maps survive byte-faithfully.
    #[test]
    fn move_record_happy_path() {
        let (_tmp, opened) = open_writable_golden_001();
        let src_block_uuid = [0xA1u8; 16];
        let src_record_uuid = [0xA2u8; 16];
        let dst_block_uuid = [0xA3u8; 16];

        seed_block_with_record(&opened, src_block_uuid, src_record_uuid);
        seed_empty_target(&opened, dst_block_uuid);

        let new_uuid = move_record(
            &opened.identity,
            &opened.manifest,
            src_block_uuid,
            src_record_uuid,
            dst_block_uuid,
            DEVICE_UUID,
            2_000,
        )
        .expect("move_record");

        // Fresh UUID: must differ from source.
        assert_ne!(new_uuid, src_record_uuid, "new UUID must differ from source");

        // Source record is now tombstoned.
        let src_after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &src_block_uuid)
            .expect("decrypt source after move");
        let src_rec = src_after
            .records
            .iter()
            .find(|r| r.record_uuid == src_record_uuid)
            .expect("source record still present (tombstoned)");
        assert!(src_rec.tombstone, "source record must be tombstoned");

        // Target has the copied record under the new UUID.
        let dst_after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &dst_block_uuid)
            .expect("decrypt target after move");
        let dst_rec = dst_after
            .records
            .iter()
            .find(|r| r.record_uuid == new_uuid)
            .expect("copied record present in target");
        assert!(!dst_rec.tombstone, "copied record must be live");
        assert_eq!(dst_rec.record_type, "login");
        assert_eq!(dst_rec.tags, vec!["work".to_string()]);
        assert!(dst_rec.unknown.contains_key("x_rec"), "record-level unknown preserved");

        let user = dst_rec.fields.get("user").expect("field preserved");
        assert!(user.unknown.contains_key("x_fld"), "field-level unknown preserved");
        match &user.value {
            RecordFieldValue::Text(s) => assert_eq!(*s, SecretString::from("alice")),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    /// Missing target block: source record must remain untouched (live) because
    /// `copy_record_into_target` fails before `tombstone_record` is called.
    #[test]
    fn move_record_missing_target_leaves_source_untouched() {
        let (_tmp, opened) = open_writable_golden_001();
        let src_block_uuid = [0xC1u8; 16];
        let src_record_uuid = [0xC2u8; 16];
        seed_block_with_record(&opened, src_block_uuid, src_record_uuid);

        let absent_dst = [0xFFu8; 16]; // not seeded

        let err = move_record(
            &opened.identity,
            &opened.manifest,
            src_block_uuid,
            src_record_uuid,
            absent_dst,
            DEVICE_UUID,
            2_000,
        )
        .expect_err("absent target must error");
        assert!(
            matches!(err, FfiVaultError::BlockNotFound { .. }),
            "expected BlockNotFound, got {err:?}"
        );

        // Source must still be live.
        let src_after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &src_block_uuid)
            .expect("decrypt source after failed move");
        let src_rec = src_after
            .records
            .iter()
            .find(|r| r.record_uuid == src_record_uuid)
            .expect("source record still present");
        assert!(!src_rec.tombstone, "source must remain live after failed move");
    }

    /// Absent source record UUID in source block → `RecordNotFound`.
    #[test]
    fn move_record_absent_source_record_is_record_not_found() {
        let (_tmp, opened) = open_writable_golden_001();
        let src_block_uuid = [0xD1u8; 16];
        let dst_block_uuid = [0xD3u8; 16];
        seed_block_with_record(&opened, src_block_uuid, [0xD2u8; 16]); // seeds a different record UUID
        seed_empty_target(&opened, dst_block_uuid);

        let absent_record = [0xDDu8; 16];

        let err = move_record(
            &opened.identity,
            &opened.manifest,
            src_block_uuid,
            absent_record,
            dst_block_uuid,
            DEVICE_UUID,
            2_000,
        )
        .expect_err("absent source record must error");
        assert!(
            matches!(err, FfiVaultError::RecordNotFound { .. }),
            "expected RecordNotFound, got {err:?}"
        );
    }
}
