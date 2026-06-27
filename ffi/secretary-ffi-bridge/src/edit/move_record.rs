//! Record-move primitive: copy a live record into the target block under a
//! caller-supplied UUID, preserving all secret field values and every
//! forward-compat `unknown` (block / record / field), then tombstone the
//! source record.
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

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::vault::OpenVaultManifest;
use secretary_core::vault::record::{Record, RecordField};

/// Move a live record from one block into another block under a caller-supplied
/// UUID.
///
/// The semantics are copy-before-delete:
/// 1. Decrypt the **source** block; locate the live record (`RecordNotFound`
///    if absent or already tombstoned).
/// 2. Decrypt the **target** block *before any write* (`BlockNotFound` if
///    absent — the source is left untouched).
/// 3. Build the copy under the caller-supplied `new_record_uuid` — a
///    **faithful move**: `created_at_ms`, per-field `last_mod`/`device_uuid`,
///    field values, and every `unknown` map are preserved; only `record_uuid`
///    and the record-level `last_mod_ms` are fresh (set to `new_record_uuid`
///    and `now_ms` respectively).  `tombstone = false`, `tombstoned_at_ms = 0`.
/// 4. Save the mutated target block through `super::save_plaintext`
///    (copy-before-delete).
/// 5. Tombstone the source record via [`super::tombstone::tombstone_record`].
///
/// # Same-block precondition
///
/// `source_block_uuid == target_block_uuid` is enforced at the uniffi wrapper
/// layer (the bridge trusts its caller, exactly as it trusts UUID lengths via
/// `[u8; 16]`).
///
/// # Errors
///
/// - [`FfiVaultError::BlockNotFound`] — `source_block_uuid` or
///   `target_block_uuid` not in the manifest.
/// - [`FfiVaultError::RecordNotFound`] — no LIVE record with
///   `source_record_uuid` in the source block.
/// - [`FfiVaultError::CorruptVault`] — decrypt or identity/manifest-handle
///   failure.
/// - Save-tail errors ([`FfiVaultError::FolderInvalid`] /
///   [`FfiVaultError::SaveCryptoFailure`]).
#[allow(clippy::too_many_arguments)]
pub fn move_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    source_block_uuid: [u8; 16],
    target_block_uuid: [u8; 16],
    source_record_uuid: [u8; 16],
    new_record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Steps 1–4: decrypt source, locate record, decrypt target, build copy,
    // save target.
    copy_record_into_target(
        identity,
        manifest,
        source_block_uuid,
        target_block_uuid,
        source_record_uuid,
        new_record_uuid,
        device_uuid,
        now_ms,
    )?;

    // Step 5: tombstone the source record.
    super::tombstone::tombstone_record(
        identity,
        manifest,
        source_block_uuid,
        source_record_uuid,
        device_uuid,
        now_ms,
    )?;

    Ok(())
}

/// Decrypt the source block, locate the live source record, decrypt the target
/// block, append the copy under `new_record_uuid`, and save the target block.
///
/// The target block is decrypted *before* the source is tombstoned so that any
/// target decrypt failure leaves the source intact
/// (`decrypt-target-before-write` safety).
///
/// # Errors
///
/// [`FfiVaultError::BlockNotFound`] — `source_block_uuid` or
/// `target_block_uuid` absent from the manifest.
/// [`FfiVaultError::RecordNotFound`] — no LIVE record with
/// `source_record_uuid` in the source block.
/// [`FfiVaultError::CorruptVault`] — decrypt failure.
/// Save-tail errors.
#[allow(clippy::too_many_arguments)]
fn copy_record_into_target(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    source_block_uuid: [u8; 16],
    target_block_uuid: [u8; 16],
    source_record_uuid: [u8; 16],
    new_record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Step 1: Decrypt source block first to locate the record.
    let src_plaintext = decrypt_block_plaintext(identity, manifest, &source_block_uuid)?;

    // Locate the live source record.
    let src_record = src_plaintext
        .records
        .iter()
        .find(|r| r.record_uuid == source_record_uuid && !r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound {
            uuid_hex: hex::encode(source_record_uuid),
        })?;

    // Step 2: Decrypt target block before any write (decrypt-target-before-write).
    let mut dst_plaintext = decrypt_block_plaintext(identity, manifest, &target_block_uuid)?;

    // Step 3: Build the faithful copy under the caller-supplied new_record_uuid.
    let copy = Record {
        record_uuid: new_record_uuid,
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

    // Step 4: Append copy and save mutated target block.
    dst_plaintext.records.push(copy);
    super::save_plaintext(identity, manifest, dst_plaintext, device_uuid, now_ms)?;

    Ok(())
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
    /// three levels (block / record / field).  The record is created with
    /// `created_at_ms = 1_000` and field `last_mod = 1_000` so tests can
    /// prove faithful-move preservation independently of `now_ms`.
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
        super::super::save_plaintext(
            &opened.identity,
            &opened.manifest,
            plaintext,
            DEVICE_UUID,
            1_000,
        )
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
        super::super::save_plaintext(
            &opened.identity,
            &opened.manifest,
            plaintext,
            DEVICE_UUID,
            1_000,
        )
        .expect("seed target block");
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// Happy path: record appears in target under the caller-supplied UUID,
    /// source record is tombstoned, faithful-move semantics are locked in:
    /// - `created_at_ms` is preserved (source = 1_000, now_ms = 5_000).
    /// - field `last_mod` and `device_uuid` are preserved from the source.
    /// - record-level `last_mod_ms` equals `now_ms`.
    /// - record-level and field-level `unknown` maps survive byte-faithfully
    ///   (block-level `unknown` belongs to the source block's container and is
    ///   intentionally NOT carried across a record move).
    #[test]
    fn move_record_happy_path() {
        let (_tmp, opened) = open_writable_golden_001();
        let source_block_uuid = [0xA1u8; 16];
        let source_record_uuid = [0xA2u8; 16];
        let target_block_uuid = [0xA3u8; 16];
        let new_record_uuid = [0x84u8; 16];

        seed_block_with_record(&opened, source_block_uuid, source_record_uuid);
        seed_empty_target(&opened, target_block_uuid);

        move_record(
            &opened.identity,
            &opened.manifest,
            source_block_uuid,
            target_block_uuid,
            source_record_uuid,
            new_record_uuid,
            DEVICE_UUID,
            5_000,
        )
        .expect("move_record");

        // Source record is now tombstoned.
        let src_after =
            decrypt_block_plaintext(&opened.identity, &opened.manifest, &source_block_uuid)
                .expect("decrypt source after move");
        let src_rec = src_after
            .records
            .iter()
            .find(|r| r.record_uuid == source_record_uuid)
            .expect("source record still present (tombstoned)");
        assert!(src_rec.tombstone, "source record must be tombstoned");

        // Target has the copied record under the caller-supplied new_record_uuid.
        let dst_after =
            decrypt_block_plaintext(&opened.identity, &opened.manifest, &target_block_uuid)
                .expect("decrypt target after move");
        let dst_rec = dst_after
            .records
            .iter()
            .find(|r| r.record_uuid == new_record_uuid)
            .expect("copied record present in target under new_record_uuid");
        assert!(!dst_rec.tombstone, "copied record must be live");
        assert_eq!(dst_rec.record_type, "login");
        assert_eq!(dst_rec.tags, vec!["work".to_string()]);

        // Faithful-move: created_at_ms preserved from source (1_000), not now_ms (5_000).
        assert_eq!(
            dst_rec.created_at_ms, 1_000,
            "created_at_ms must be preserved from source, not now_ms"
        );
        // Record-level last_mod_ms is fresh (now_ms).
        assert_eq!(
            dst_rec.last_mod_ms, 5_000,
            "record-level last_mod_ms must equal now_ms"
        );

        // Per-field clocks and device_uuid are preserved from source.
        let user = dst_rec.fields.get("user").expect("field preserved");
        assert_eq!(
            user.last_mod, 1_000,
            "field last_mod must be preserved from source"
        );
        assert_eq!(
            user.device_uuid, DEVICE_UUID,
            "field device_uuid must be preserved from source"
        );

        // Record-level and field-level unknown maps survive the move
        // (block-level unknown is not copied — it belongs to the source block).
        assert!(
            dst_rec.unknown.contains_key("x_rec"),
            "record-level unknown preserved"
        );
        assert!(
            user.unknown.contains_key("x_fld"),
            "field-level unknown preserved"
        );
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
        let source_block_uuid = [0xC1u8; 16];
        let source_record_uuid = [0xC2u8; 16];
        seed_block_with_record(&opened, source_block_uuid, source_record_uuid);

        let absent_dst = [0xFFu8; 16]; // not seeded
        let new_record_uuid = [0x84u8; 16];

        let err = move_record(
            &opened.identity,
            &opened.manifest,
            source_block_uuid,
            absent_dst,
            source_record_uuid,
            new_record_uuid,
            DEVICE_UUID,
            2_000,
        )
        .expect_err("absent target must error");
        assert!(
            matches!(err, FfiVaultError::BlockNotFound { .. }),
            "expected BlockNotFound, got {err:?}"
        );

        // Source must still be live.
        let src_after =
            decrypt_block_plaintext(&opened.identity, &opened.manifest, &source_block_uuid)
                .expect("decrypt source after failed move");
        let src_rec = src_after
            .records
            .iter()
            .find(|r| r.record_uuid == source_record_uuid)
            .expect("source record still present");
        assert!(
            !src_rec.tombstone,
            "source must remain live after failed move"
        );
    }

    /// Absent source record UUID in source block → `RecordNotFound`.
    #[test]
    fn move_record_absent_source_record_is_record_not_found() {
        let (_tmp, opened) = open_writable_golden_001();
        let source_block_uuid = [0xD1u8; 16];
        let target_block_uuid = [0xD3u8; 16];
        seed_block_with_record(&opened, source_block_uuid, [0xD2u8; 16]); // seeds a different record UUID
        seed_empty_target(&opened, target_block_uuid);

        let absent_record = [0xDDu8; 16];
        let new_record_uuid = [0x84u8; 16];

        let err = move_record(
            &opened.identity,
            &opened.manifest,
            source_block_uuid,
            target_block_uuid,
            absent_record,
            new_record_uuid,
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
