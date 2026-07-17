//! D.1.5 record soft-delete primitives, layered on the D.1.4
//! native-`BlockPlaintext` round-trip. Each flips exactly one record's
//! tombstone flag and re-encrypts through the shared
//! [`super::save_plaintext`] tail — siblings, the block-level / record-level
//! / field-level `unknown` maps, and every untouched field survive
//! byte-faithfully.
//!
//! These are SEPARATE from [`super::edit_record`]: an edit locates only LIVE
//! records and preserves `tombstone` / `tombstoned_at_ms`, so it can neither
//! delete nor resurrect. The death-clock invariant
//! (`tombstone == true ⇒ tombstoned_at_ms == last_mod_ms`) is the core CRDT
//! merge layer's associativity hinge; these primitives maintain it:
//! `tombstone_record` sets all three of `tombstone` / `tombstoned_at_ms` /
//! `last_mod_ms` to `now_ms`; `resurrect_record` is a live edit at a newer
//! clock that clears `tombstone`, bumps `last_mod_ms`, and PRESERVES the
//! original `tombstoned_at_ms`.

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::vault::OpenVaultManifest;

/// Soft-delete one live record: set its tombstone flag and death clock.
///
/// Locates the record by `record_uuid` among LIVE records (`!tombstone`).
/// Fields are NOT cleared — the record stays fully resurrectable. Sets
/// `tombstone = true`, `tombstoned_at_ms = now_ms`, `last_mod_ms = now_ms`
/// (maintaining the death-clock invariant), preserves everything else, and
/// re-encrypts through `super::save_plaintext`.
///
/// # Errors
///
/// [`FfiVaultError::RecordNotFound`] (no LIVE record with this UUID — covers
/// both absent and already-tombstoned), [`FfiVaultError::BlockNotFound`],
/// [`FfiVaultError::CorruptVault`], or the save-tail error surface.
pub fn tombstone_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    let record = plaintext
        .records
        .iter_mut()
        .find(|r| r.record_uuid == record_uuid && !r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound {
            uuid_hex: hex::encode(record_uuid),
        })?;

    record.tombstone = true;
    record.tombstoned_at_ms = now_ms;
    record.last_mod_ms = now_ms;

    super::save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}

/// Resurrect one tombstoned record: clear its tombstone flag.
///
/// Locates the record by `record_uuid` among TOMBSTONED records
/// (`tombstone == true`). Sets `tombstone = false`, bumps
/// `last_mod_ms = now_ms`, and PRESERVES the original `tombstoned_at_ms`
/// (so a concurrent peer's later delete still wins under core's merge).
/// Fields and all `unknown` maps survive untouched.
///
/// Assumes `now_ms` is monotonic (≥ the preserved `tombstoned_at_ms`), as
/// elsewhere in the bridge; a stale clock would momentarily produce
/// `tombstoned_at_ms > last_mod_ms` (core defensively clamps on merge).
///
/// # Errors
///
/// [`FfiVaultError::RecordNotFound`] (no TOMBSTONED record with this UUID —
/// covers both absent and already-live), [`FfiVaultError::BlockNotFound`],
/// [`FfiVaultError::CorruptVault`], or the save-tail error surface.
pub fn resurrect_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    let record = plaintext
        .records
        .iter_mut()
        .find(|r| r.record_uuid == record_uuid && r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound {
            uuid_hex: hex::encode(record_uuid),
        })?;

    record.tombstone = false;
    record.last_mod_ms = now_ms;
    // tombstoned_at_ms intentionally PRESERVED.

    super::save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use secretary_core::crypto::secret::SecretString;
    use secretary_core::vault::block::BlockPlaintext;
    use secretary_core::vault::record::{Record, RecordField, RecordFieldValue, UnknownValue};

    use super::super::{BLOCK_VERSION_V1, SCHEMA_VERSION_V1};
    use crate::test_support::open_writable_golden_001;

    const DEVICE_UUID: [u8; 16] = [0x07; 16];

    /// The correctness keystone for the D.1.5 soft-delete slice: a
    /// tombstone followed by a resurrect must preserve forward-compat
    /// `unknown` at ALL THREE levels (block / record / field) and the
    /// record's fields, and must maintain the death-clock invariant
    /// (set on tombstone, PRESERVED on resurrect). Built via `core`
    /// because the bridge input types intentionally cannot mint
    /// `unknown` keys.
    #[test]
    fn tombstone_then_resurrect_preserves_unknown_and_death_clock() {
        let (_tmp, opened) = open_writable_golden_001();
        let block_uuid = [0x53u8; 16];
        let record_uuid = [0x54u8; 16];

        // A single CBOR int (0x01) is a valid canonical-CBOR unknown value.
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

        super::super::save_plaintext(
            &opened.identity,
            &opened.manifest,
            plaintext,
            DEVICE_UUID,
            1_000,
        )
        .expect("save synthetic plaintext");

        // 1. Tombstone the record.
        tombstone_record(
            &opened.identity,
            &opened.manifest,
            block_uuid,
            record_uuid,
            DEVICE_UUID,
            2_000,
        )
        .expect("tombstone_record");

        let after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &block_uuid)
            .expect("decrypt after tombstone");
        assert!(
            after.unknown.contains_key("x_block"),
            "block-level unknown 'x_block' must survive a tombstone"
        );
        let rec = after
            .records
            .iter()
            .find(|r| r.record_uuid == record_uuid)
            .expect("record present after tombstone");
        assert!(rec.tombstone, "record must be tombstoned");
        assert_eq!(
            rec.tombstoned_at_ms, 2_000,
            "death clock set to now_ms on tombstone"
        );
        assert_eq!(
            rec.last_mod_ms, 2_000,
            "last_mod_ms set to now_ms on tombstone"
        );
        assert!(
            rec.unknown.contains_key("x_rec"),
            "record-level unknown 'x_rec' must survive a tombstone"
        );
        let user = rec
            .fields
            .get("user")
            .expect("fields NOT cleared on tombstone");
        assert!(
            user.unknown.contains_key("x_fld"),
            "field-level unknown 'x_fld' must survive a tombstone"
        );
        match &user.value {
            RecordFieldValue::Text(s) => assert_eq!(
                *s,
                SecretString::from("alice"),
                "field value must be unchanged by a tombstone"
            ),
            other => panic!("expected Text, got {other:?}"),
        }

        // 2. Resurrect the record at a newer clock.
        resurrect_record(
            &opened.identity,
            &opened.manifest,
            block_uuid,
            record_uuid,
            DEVICE_UUID,
            3_000,
        )
        .expect("resurrect_record");

        let after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &block_uuid)
            .expect("decrypt after resurrect");
        assert!(
            after.unknown.contains_key("x_block"),
            "block-level unknown 'x_block' must survive a resurrect"
        );
        let rec = after
            .records
            .iter()
            .find(|r| r.record_uuid == record_uuid)
            .expect("record present after resurrect");
        assert!(!rec.tombstone, "record must be live after resurrect");
        assert_eq!(
            rec.tombstoned_at_ms, 2_000,
            "tombstoned_at_ms PRESERVED across resurrect"
        );
        assert_eq!(
            rec.last_mod_ms, 3_000,
            "last_mod_ms bumped to now_ms on resurrect"
        );
        assert!(
            rec.unknown.contains_key("x_rec"),
            "record-level unknown 'x_rec' must survive a resurrect"
        );
        let user = rec
            .fields
            .get("user")
            .expect("field 'user' present after resurrect");
        assert!(
            user.unknown.contains_key("x_fld"),
            "field-level unknown 'x_fld' must survive a resurrect"
        );
        match &user.value {
            RecordFieldValue::Text(s) => assert_eq!(*s, SecretString::from("alice")),
            other => panic!("expected Text, got {other:?}"),
        }
    }
}
