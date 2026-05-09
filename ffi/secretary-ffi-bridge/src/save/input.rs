//! `save_block` input types: [`BlockInput`], [`RecordInput`], [`FieldInput`],
//! [`FieldInputValue`].
//!
//! These are the foreign-facing shapes that the bridge accepts on save. They
//! convert into the corresponding `secretary_core::vault` types via the
//! `into_core_*` methods (crate-internal; consumed by the save_block
//! orchestrator added in Task 2).
//!
//! # Zeroize discipline
//!
//! [`FieldInputValue::Text`] wraps `secretary_core::crypto::secret::SecretString`
//! and [`FieldInputValue::Bytes`] wraps `SecretBytes`. Both are
//! `Zeroize, ZeroizeOnDrop` already; the bridge layer adds no new
//! zeroize-typed boundary because `core::vault::record::RecordFieldValue`
//! uses the same wrappers and is the canonical secret-bearing carrier
//! across the v1 vault format. The bridge's only zeroize responsibility on
//! input is to ensure the wrappers are not unwrapped before the core types
//! are constructed (which `into_core_value` honors by moving the wrapped
//! value through unchanged).
//!
//! Foreign-side `String` / `bytes` values *before* crossing the FFI
//! boundary are owned by Python / Swift / Kotlin runtimes and are the
//! caller's responsibility to clear; the bridge cannot enforce that.
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §4.

use std::collections::BTreeMap;

use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_core::vault::block::BlockPlaintext;
use secretary_core::vault::record::{Record, RecordField, RecordFieldValue};

/// Tagged value for a single field on save. Maps to a Kotlin sealed class /
/// Swift enum / Python tagged dataclass at the binding-flavor layer.
///
/// Mirrors [`RecordFieldValue`] structurally; the bridge intentionally
/// re-uses core's [`SecretString`] / [`SecretBytes`] wrappers so the
/// conversion to a `core::RecordFieldValue` is a move (not a re-allocation
/// + zeroize-of-original).
#[derive(Clone, Debug)]
pub enum FieldInputValue {
    /// UTF-8 text, zeroize-on-drop.
    Text(SecretString),
    /// Raw bytes, zeroize-on-drop.
    Bytes(SecretBytes),
}

impl FieldInputValue {
    /// Crate-internal: consume self and produce a [`RecordFieldValue`]. The
    /// secret payload is moved (no re-allocation), preserving the existing
    /// zeroize-on-drop semantics.
    #[allow(dead_code)] // consumed by crate::save::save_block in Task 2
    pub(crate) fn into_core_value(self) -> RecordFieldValue {
        match self {
            FieldInputValue::Text(s) => RecordFieldValue::Text(s),
            FieldInputValue::Bytes(b) => RecordFieldValue::Bytes(b),
        }
    }
}

/// One field on a record being saved.
///
/// `name` is plaintext (CBOR map keys at the wire level are plaintext —
/// secrets live in the value, not the key).
#[derive(Clone, Debug)]
pub struct FieldInput {
    /// Field name (CBOR map key, plaintext on wire).
    pub name: String,
    /// Tagged value with bridged-through zeroize wrappers.
    pub value: FieldInputValue,
}

/// One record being saved.
///
/// `record_uuid` is caller-minted (16 bytes; see spec §4 ID/time policy).
/// Same `record_uuid` on a subsequent save participates in the CRDT
/// per-record merge layer.
#[derive(Clone, Debug)]
pub struct RecordInput {
    /// 16-byte stable record UUID.
    pub record_uuid: [u8; 16],
    /// Fields. Duplicate names collapse to last-write-wins inside the
    /// resulting `BTreeMap<String, RecordField>` (the deduplication
    /// matches `core::Record::fields`'s key invariant).
    pub fields: Vec<FieldInput>,
}

impl RecordInput {
    /// Crate-internal: convert into a [`Record`] populated with the given
    /// `now_ms` and `device_uuid` for both record-level and per-field
    /// timestamps. Per-record / per-field forward-compat `unknown` maps
    /// are empty (B.4c does not surface unknowns; round-trip of unknowns
    /// is a B.4d-or-later concern).
    #[allow(dead_code)] // consumed by crate::save::save_block in Task 2
    pub(crate) fn into_core_record(self, now_ms: u64, device_uuid: [u8; 16]) -> Record {
        let mut fields_map: BTreeMap<String, RecordField> = BTreeMap::new();
        for f in self.fields {
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
            record_uuid: self.record_uuid,
            record_type: String::new(),
            fields: fields_map,
            tags: Vec::new(),
            created_at_ms: now_ms,
            last_mod_ms: now_ms,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        }
    }
}

/// One block being saved. Empty `records` is allowed (the spec permits
/// empty blocks). Same `block_uuid` on a subsequent save replaces the
/// existing manifest entry in-place; new UUID appends.
#[derive(Clone, Debug)]
pub struct BlockInput {
    /// 16-byte stable block UUID.
    pub block_uuid: [u8; 16],
    /// User-visible block label (plaintext within the encrypted manifest).
    pub block_name: String,
    /// Records to save in this block.
    pub records: Vec<RecordInput>,
}

impl BlockInput {
    /// Crate-internal: convert into a [`BlockPlaintext`] populated for v1
    /// (`block_version = 1`, `schema_version = 1`, no forward-compat
    /// unknowns).
    #[allow(dead_code)] // consumed by crate::save::save_block in Task 2
    pub(crate) fn into_block_plaintext(self, now_ms: u64, device_uuid: [u8; 16]) -> BlockPlaintext {
        BlockPlaintext {
            block_version: 1,
            block_uuid: self.block_uuid,
            block_name: self.block_name,
            schema_version: 1,
            records: self
                .records
                .into_iter()
                .map(|r| r.into_core_record(now_ms, device_uuid))
                .collect(),
            unknown: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_input_value_text_converts_to_core_record_field_value_text() {
        let input = FieldInputValue::Text(SecretString::from("password123"));
        match input.into_core_value() {
            RecordFieldValue::Text(s) => {
                assert_eq!(s, SecretString::from("password123"));
            }
            other => panic!("expected Text, got {:?}", other),
        }
    }

    #[test]
    fn field_input_value_bytes_converts_to_core_record_field_value_bytes() {
        let input = FieldInputValue::Bytes(SecretBytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        match input.into_core_value() {
            RecordFieldValue::Bytes(b) => {
                assert_eq!(b, SecretBytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]));
            }
            other => panic!("expected Bytes, got {:?}", other),
        }
    }

    #[test]
    fn record_input_into_core_record_populates_timestamps_and_device_uuid() {
        let input = RecordInput {
            record_uuid: [0xCDu8; 16],
            fields: vec![FieldInput {
                name: "title".to_string(),
                value: FieldInputValue::Text(SecretString::from("hello")),
            }],
        };
        let device = [0x07u8; 16];
        let now: u64 = 1_715_000_000_000;
        let r = input.into_core_record(now, device);
        assert_eq!(r.record_uuid, [0xCDu8; 16]);
        assert_eq!(r.created_at_ms, now);
        assert_eq!(r.last_mod_ms, now);
        assert!(!r.tombstone);
        assert_eq!(r.tombstoned_at_ms, 0);
        assert_eq!(r.fields.len(), 1);
        let f = r.fields.get("title").expect("field present");
        assert_eq!(f.last_mod, now);
        assert_eq!(f.device_uuid, device);
    }

    #[test]
    fn record_input_duplicate_field_names_collapse_to_last_write_wins() {
        // Vec<FieldInput> with two entries sharing the same name: the
        // BTreeMap::insert path makes the second value win. The wire
        // schema has a single value per field name, so this is the
        // correct collapse semantics.
        let input = RecordInput {
            record_uuid: [0xCDu8; 16],
            fields: vec![
                FieldInput {
                    name: "k".to_string(),
                    value: FieldInputValue::Text(SecretString::from("first")),
                },
                FieldInput {
                    name: "k".to_string(),
                    value: FieldInputValue::Text(SecretString::from("second")),
                },
            ],
        };
        let r = input.into_core_record(0, [0u8; 16]);
        assert_eq!(r.fields.len(), 1);
        match &r.fields["k"].value {
            RecordFieldValue::Text(s) => {
                assert_eq!(*s, SecretString::from("second"));
            }
            other => panic!("expected Text, got {:?}", other),
        }
    }

    #[test]
    fn block_input_into_block_plaintext_preserves_uuid_and_name() {
        let input = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "Notes".to_string(),
            records: vec![],
        };
        let plaintext = input.into_block_plaintext(1_000, [7u8; 16]);
        assert_eq!(plaintext.block_uuid, [0xABu8; 16]);
        assert_eq!(plaintext.block_name, "Notes");
        assert_eq!(plaintext.block_version, 1);
        assert_eq!(plaintext.schema_version, 1);
        assert!(plaintext.records.is_empty());
        assert!(plaintext.unknown.is_empty());
    }

    #[test]
    fn block_input_into_block_plaintext_with_records_populates_each() {
        let input = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "x".to_string(),
            records: vec![
                RecordInput {
                    record_uuid: [0x01u8; 16],
                    fields: vec![],
                },
                RecordInput {
                    record_uuid: [0x02u8; 16],
                    fields: vec![],
                },
            ],
        };
        let plaintext = input.into_block_plaintext(1_000, [7u8; 16]);
        assert_eq!(plaintext.records.len(), 2);
        assert_eq!(plaintext.records[0].record_uuid, [0x01u8; 16]);
        assert_eq!(plaintext.records[1].record_uuid, [0x02u8; 16]);
    }
}
