//! C.4 — Python clean-room convergence mirror: Rust fixture generator +
//! always-run guard. Emits `core/tests/data/convergence_kat.json` (two
//! concurrent device sides + the real `merge_block` golden) and replays it
//! both ways to assert order-independence. The Python sibling
//! (`core/tests/python/conformance.py` `section_convergence_kat`) re-runs the
//! merge from spec docs only and asserts the same convergence.
//!
//! See docs/superpowers/specs/2026-06-15-c4-python-convergence-mirror-design.md.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use secretary_core::vault::{
    merge_block, BlockPlaintext, Record, RecordField, RecordFieldValue, UnknownValue,
    VectorClockEntry,
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

/// Serialise a record- or block-level `unknown` map to the KAT's
/// `{"key": "<hex-cbor>"}` shape. Currently asserts the map is empty: no
/// convergence scenario exercises forward-compat unknown keys. This is the
/// single extension point — implement the hex-CBOR mapping here when the first
/// such scenario is added, rather than re-deriving it at three call sites.
fn unknown_to_json(map: &BTreeMap<String, UnknownValue>) -> serde_json::Value {
    assert!(
        map.is_empty(),
        "convergence scenarios carry no unknown keys — implement unknown_to_json when first needed"
    );
    serde_json::json!({})
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
        "unknown_hex": unknown_to_json(&r.unknown),
    })
}

fn block_to_json(b: &BlockPlaintext) -> serde_json::Value {
    let records: Vec<serde_json::Value> = b.records.iter().map(record_to_json).collect();
    serde_json::json!({
        "block_version": b.block_version,
        "block_uuid_hex": hex(&b.block_uuid),
        "block_name": b.block_name,
        "schema_version": b.schema_version,
        "records": records,
        "unknown_hex": unknown_to_json(&b.unknown),
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

// ---------------------------------------------------------------------------
// The four CRDT-pure convergence scenarios (single record X each).
// ---------------------------------------------------------------------------

struct Scenario {
    name: &'static str,
    a_block: BlockPlaintext,
    a_clock: Vec<VectorClockEntry>,
    b_block: BlockPlaintext,
    b_clock: Vec<VectorClockEntry>,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        // 1. auto-apply: A live, B behind (empty block + empty clock).
        Scenario {
            name: "auto_apply",
            a_block: block_of(
                X_BLOCK,
                vec![record_live(
                    X_RECORD,
                    &[("f1", text_field("alice", 100, A))],
                    100,
                )],
            ),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(X_BLOCK, vec![]),
            b_clock: vec![],
        },
        // 2. concurrent disjoint fields.
        Scenario {
            name: "concurrent_disjoint",
            a_block: block_of(
                X_BLOCK,
                vec![record_live(
                    X_RECORD,
                    &[("f1", text_field("alice", 100, A))],
                    100,
                )],
            ),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(
                X_BLOCK,
                vec![record_live(
                    X_RECORD,
                    &[("f2", text_field("bob", 101, B))],
                    101,
                )],
            ),
            b_clock: vec![vc(B, 1)],
        },
        // 3. LWW collision on field "k": later last_mod (101 > 100) wins.
        Scenario {
            name: "lww_collision",
            a_block: block_of(
                X_BLOCK,
                vec![record_live(
                    X_RECORD,
                    &[("k", text_field("alice-loses", 100, A))],
                    100,
                )],
            ),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(
                X_BLOCK,
                vec![record_live(
                    X_RECORD,
                    &[("k", text_field("bob-wins", 101, B))],
                    101,
                )],
            ),
            b_clock: vec![vc(B, 1)],
        },
        // 4. tombstone AcceptTombstone: B's death clock (200) > A's edit (100).
        Scenario {
            name: "tombstone_accept",
            a_block: block_of(
                X_BLOCK,
                vec![record_live(
                    X_RECORD,
                    &[("k", text_field("alice-live", 100, A))],
                    100,
                )],
            ),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(X_BLOCK, vec![record_tombstoned(X_RECORD, 200)]),
            b_clock: vec![vc(B, 1)],
        },
    ]
}

/// Merge a scenario in one ordering. `merger` syncs: its own side is `local`,
/// the canonical side is `remote`, and the merge ticks `merger`'s clock entry.
fn merge_ordering(
    local: &BlockPlaintext,
    local_clock: &[VectorClockEntry],
    remote: &BlockPlaintext,
    remote_clock: &[VectorClockEntry],
    merger: [u8; 16],
) -> BlockPlaintext {
    merge_block(local, local_clock, remote, remote_clock, merger)
        .expect("merge_block")
        .merged
}

#[test]
fn convergence_kat_replays_are_order_independent() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("convergence_kat.json");
    let raw = std::fs::read_to_string(&path).expect("read convergence_kat.json");
    let kat: serde_json::Value = serde_json::from_str(&raw).expect("parse convergence_kat.json");
    assert_eq!(kat["version"], 1);

    let scenarios = scenarios();
    let vectors = kat["scenarios"].as_array().expect("scenarios[]");
    assert_eq!(
        vectors.len(),
        scenarios.len(),
        "fixture scenario count must match the in-Rust scenario table"
    );

    for sc in &scenarios {
        // Ordering AB: A canonical, B merges (B=local, A=remote, merger=B).
        let ab = merge_ordering(&sc.b_block, &sc.b_clock, &sc.a_block, &sc.a_clock, [B; 16]);
        // Ordering BA: B canonical, A merges (A=local, B=remote, merger=A).
        let ba = merge_ordering(&sc.a_block, &sc.a_clock, &sc.b_block, &sc.b_clock, [A; 16]);
        assert_eq!(
            block_to_json(&ab),
            block_to_json(&ba),
            "scenario {}: orderings diverged (order-independence violated)",
            sc.name
        );

        // Golden in the fixture must equal the converged block.
        let vector = vectors
            .iter()
            .find(|v| v["name"] == sc.name)
            .unwrap_or_else(|| panic!("fixture missing scenario {}", sc.name));
        assert_eq!(
            block_to_json(&ab),
            vector["golden"]["block"],
            "scenario {}: golden does not match converged block",
            sc.name
        );
    }
}

/// Regenerate the committed fixture. Run explicitly; review the diff before
/// commit:
///   cargo test --release --workspace -- --ignored generate_convergence_kat --nocapture
#[test]
#[ignore]
fn generate_convergence_kat() {
    let scenarios = scenarios();
    let mut out_scenarios: Vec<serde_json::Value> = Vec::new();
    for sc in &scenarios {
        // Golden = real merge_block output, ordering AB (golden is
        // order-independent; the always-run guard proves AB == BA).
        let golden = merge_ordering(&sc.b_block, &sc.b_clock, &sc.a_block, &sc.a_clock, [B; 16]);
        out_scenarios.push(serde_json::json!({
            "name": sc.name,
            "device_a": { "block": block_to_json(&sc.a_block), "vector_clock": clock_to_json(&sc.a_clock) },
            "device_b": { "block": block_to_json(&sc.b_block), "vector_clock": clock_to_json(&sc.b_clock) },
            "merging_device_a_hex": hex(&[A; 16]),
            "merging_device_b_hex": hex(&[B; 16]),
            "golden": { "block": block_to_json(&golden) },
        }));
    }
    let doc = serde_json::json!({
        "version": 1,
        "_doc": "C.4 convergence conformance vectors. Each scenario carries two \
    concurrent device sides (block plaintext + vector clock) plus the golden \
    converged block produced by the real Rust merge_block. Replayed by \
    core/tests/convergence_kat_gen.rs (always-run guard) and \
    core/tests/python/conformance.py (clean-room, stdlib only): both merge BOTH \
    orderings and assert order-independence + golden-match. The vector clock is \
    intentionally absent from `golden` (it differs by which device was the merger; \
    convergence is logical, on records not clocks). Regenerate with: cargo test \
    --release --workspace -- --ignored generate_convergence_kat --nocapture",
        "scenarios": out_scenarios,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("convergence_kat.json");
    let pretty = serde_json::to_string_pretty(&doc).expect("serialize");
    std::fs::write(&path, format!("{pretty}\n")).expect("write convergence_kat.json");
    eprintln!(
        "generate_convergence_kat: wrote {} ({} scenarios)",
        path.display(),
        scenarios.len()
    );
}
