//! `save_block` input types: [`BlockInput`], [`RecordInput`], [`FieldInput`],
//! [`FieldInputValue`].
//!
//! These are the foreign-facing shapes that the bridge accepts on save.
//! `BlockInput::into_block_plaintext` (crate-internal) converts one into a core
//! [`BlockPlaintext`], carrying forward from the block's current copy
//! whatever the caller cannot see (#766).
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
use secretary_core::vault::record::RecordFieldValue;

use crate::edit::{rebuild_record, RecordContent, BLOCK_VERSION_V1, SCHEMA_VERSION_V1};

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
    /// Open-ended record-type discriminator (e.g. `"login"`). Empty string
    /// permitted. (#141 — previously hardcoded empty on save.)
    pub record_type: String,
    /// Cross-cutting tags. Empty `Vec` = absent on the wire. (#141.)
    pub tags: Vec<String>,
    /// Fields. Duplicate names collapse to last-write-wins inside the
    /// resulting `BTreeMap<String, RecordField>` (the deduplication
    /// matches `core::Record::fields`'s key invariant).
    pub fields: Vec<FieldInput>,
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
    /// Crate-internal: convert into a [`BlockPlaintext`].
    ///
    /// `prior` is the block's current plaintext, or `None` for a new block.
    /// A new block is written at v1 with no forward-compat unknowns. An
    /// update keeps the prior `block_version`, `schema_version` and
    /// block-level `unknown`, and rebuilds each record against its prior
    /// copy (matched by `record_uuid`) through the same `rebuild_record`
    /// the edit primitives use. Without this, a v1 client saving over a
    /// block a later client wrote downgraded it and dropped its unknowns,
    /// and the save's clock tick let the next sync propagate that (#766).
    pub(crate) fn into_block_plaintext(
        self,
        prior: Option<&BlockPlaintext>,
        now_ms: u64,
        device_uuid: [u8; 16],
    ) -> BlockPlaintext {
        let records = self
            .records
            .into_iter()
            .map(|r| {
                let prior_record =
                    prior.and_then(|p| p.records.iter().find(|x| x.record_uuid == r.record_uuid));
                let content = RecordContent {
                    record_type: r.record_type,
                    tags: r.tags,
                    fields: r.fields,
                };
                rebuild_record(prior_record, r.record_uuid, content, device_uuid, now_ms)
            })
            .collect();
        BlockPlaintext {
            block_version: prior.map_or(BLOCK_VERSION_V1, |p| p.block_version),
            block_uuid: self.block_uuid,
            block_name: self.block_name,
            schema_version: prior.map_or(SCHEMA_VERSION_V1, |p| p.schema_version),
            records,
            unknown: prior.map_or_else(BTreeMap::new, |p| p.unknown.clone()),
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
    fn record_input_duplicate_field_names_collapse_to_last_write_wins() {
        // Vec<FieldInput> with two entries sharing the same name: the
        // BTreeMap::insert path makes the second value win. The wire
        // schema has a single value per field name, so this is the
        // correct collapse semantics.
        let input = RecordInput {
            record_uuid: [0xCDu8; 16],
            record_type: String::new(),
            tags: Vec::new(),
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
        let block = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "x".to_string(),
            records: vec![input],
        };
        let r = &block.into_block_plaintext(None, 0, [0u8; 16]).records[0];
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
        let plaintext = input.into_block_plaintext(None, 1_000, [7u8; 16]);
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
                    record_type: String::new(),
                    tags: Vec::new(),
                    fields: vec![],
                },
                RecordInput {
                    record_uuid: [0x02u8; 16],
                    record_type: String::new(),
                    tags: Vec::new(),
                    fields: vec![],
                },
            ],
        };
        let plaintext = input.into_block_plaintext(None, 1_000, [7u8; 16]);
        assert_eq!(plaintext.records.len(), 2);
        assert_eq!(plaintext.records[0].record_uuid, [0x01u8; 16]);
        assert_eq!(plaintext.records[1].record_uuid, [0x02u8; 16]);
    }
}
