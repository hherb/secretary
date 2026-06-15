//! C.4 — Python clean-room convergence mirror: Rust fixture generator +
//! always-run guard. Emits `core/tests/data/convergence_kat.json` (two
//! concurrent device sides + the real `merge_block` golden) and replays it
//! both ways to assert order-independence. The Python sibling
//! (`core/tests/python/conformance.py` `section_convergence_kat`) re-runs the
//! merge from spec docs only and asserts the same convergence.
//!
//! See docs/superpowers/specs/2026-06-15-c4-python-convergence-mirror-design.md.
#![forbid(unsafe_code)]
#![allow(dead_code)] // Task 2 (generator + guard) consumes the remaining builders/imports.
#![allow(unused_imports)] // merge_block is consumed by Task 2.

use std::collections::BTreeMap;

use secretary_core::vault::{
    merge_block, BlockPlaintext, Record, RecordField, RecordFieldValue, VectorClockEntry,
};

const A: u8 = 0x0A;
const B: u8 = 0x0B;
const X_BLOCK: u8 = 0xBB;
const X_RECORD: u8 = 0xAA;

#[test]
fn serializes_a_text_field_record_to_kat_shape() {
    let rec = record_live(X_RECORD, &[("f1", text_field("alice", 100, A))], 100);
    let block = block_of(X_BLOCK, vec![rec]);
    let got = block_to_json(&block);
    let expected = serde_json::json!({
        "block_version": 1,
        "block_uuid_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "block_name": "vault",
        "schema_version": 1,
        "records": [{
            "record_uuid_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "record_type": "login",
            "fields": [{
                "name": "f1",
                "value_type": "text",
                "value_text": "alice",
                "last_mod": 100,
                "device_uuid_hex": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
            }],
            "tags": [],
            "created_at_ms": 1000,
            "last_mod_ms": 100,
            "tombstone": false,
            "tombstoned_at_ms": 0,
            "unknown_hex": {}
        }],
        "unknown_hex": {}
    });
    assert_eq!(got, expected);
}

// ---------------------------------------------------------------------------
// Builders (mirror conflict.rs's pt/record/rfield/vc)
// ---------------------------------------------------------------------------

fn vc(d: u8, c: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid: [d; 16],
        counter: c,
    }
}

fn text_field(value: &str, last_mod: u64, dev: u8) -> RecordField {
    RecordField {
        value: RecordFieldValue::Text(value.into()),
        last_mod,
        device_uuid: [dev; 16],
        unknown: BTreeMap::new(),
    }
}

fn record_live(uuid: u8, fields: &[(&str, RecordField)], last_mod_ms: u64) -> Record {
    let mut map = BTreeMap::new();
    for (name, field) in fields {
        map.insert((*name).to_string(), field.clone());
    }
    Record {
        record_uuid: [uuid; 16],
        record_type: "login".to_string(),
        fields: map,
        tags: Vec::new(),
        created_at_ms: 1_000,
        last_mod_ms,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// A tombstoned record: no live fields, death clock = `at_ms`.
fn record_tombstoned(uuid: u8, at_ms: u64) -> Record {
    Record {
        record_uuid: [uuid; 16],
        record_type: "login".to_string(),
        fields: BTreeMap::new(),
        tags: Vec::new(),
        created_at_ms: 1_000,
        last_mod_ms: at_ms,
        tombstone: true,
        tombstoned_at_ms: at_ms,
        unknown: BTreeMap::new(),
    }
}

fn block_of(block_uuid: u8, records: Vec<Record>) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid: [block_uuid; 16],
        block_name: "vault".to_string(),
        schema_version: 1,
        records,
        unknown: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Serializers — inverse of conflict.rs's parse_block/parse_record/parse_field.
// Scenarios carry NO `unknown` maps; we assert that and emit empty unknown_hex
// (fail-loud if a future scenario adds one rather than silently dropping it).
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn field_to_json(name: &str, f: &RecordField) -> serde_json::Value {
    assert!(
        f.unknown.is_empty(),
        "convergence scenarios carry no record-field unknown keys"
    );
    let mut obj = serde_json::Map::new();
    obj.insert("name".into(), name.into());
    match &f.value {
        RecordFieldValue::Text(s) => {
            obj.insert("value_type".into(), "text".into());
            obj.insert("value_text".into(), s.expose().into());
        }
        RecordFieldValue::Bytes(b) => {
            obj.insert("value_type".into(), "bytes".into());
            obj.insert("value_hex".into(), hex(b.expose()).into());
        }
    }
    obj.insert("last_mod".into(), f.last_mod.into());
    obj.insert("device_uuid_hex".into(), hex(&f.device_uuid).into());
    serde_json::Value::Object(obj)
}

fn record_to_json(r: &Record) -> serde_json::Value {
    assert!(
        r.unknown.is_empty(),
        "convergence scenarios carry no record-level unknown keys"
    );
    // BTreeMap iteration is sorted by name → matches py_merge_record's
    // `sorted(set(...))` field order, so the golden compares equal to the
    // Python merge output field-for-field.
    let fields: Vec<serde_json::Value> =
        r.fields.iter().map(|(n, f)| field_to_json(n, f)).collect();
    serde_json::json!({
        "record_uuid_hex": hex(&r.record_uuid),
        "record_type": r.record_type,
        "fields": fields,
        "tags": r.tags,
        "created_at_ms": r.created_at_ms,
        "last_mod_ms": r.last_mod_ms,
        "tombstone": r.tombstone,
        "tombstoned_at_ms": r.tombstoned_at_ms,
        "unknown_hex": serde_json::json!({}),
    })
}

fn block_to_json(b: &BlockPlaintext) -> serde_json::Value {
    assert!(
        b.unknown.is_empty(),
        "convergence scenarios carry no block-level unknown keys"
    );
    let records: Vec<serde_json::Value> = b.records.iter().map(record_to_json).collect();
    serde_json::json!({
        "block_version": b.block_version,
        "block_uuid_hex": hex(&b.block_uuid),
        "block_name": b.block_name,
        "schema_version": b.schema_version,
        "records": records,
        "unknown_hex": serde_json::json!({}),
    })
}

fn clock_to_json(clock: &[VectorClockEntry]) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = clock
        .iter()
        .map(|e| {
            serde_json::json!({
                "device_uuid_hex": hex(&e.device_uuid),
                "counter": e.counter,
            })
        })
        .collect();
    serde_json::Value::Array(entries)
}
