//! Integration tests for [`secretary_core::vault::conflict`].
//!
//! Exercises the public CRDT-merge API end-to-end via realistic
//! multi-record / multi-clock / multi-edit scenarios. The narrow,
//! property-of-one-helper coverage lives in `core/src/vault/conflict.rs`'s
//! inline `mod tests`; this file delivers the cross-helper scenarios
//! that simulate Sub-project C's call patterns.
//!
//! Scenarios covered:
//!
//! - Three-way merge sequence (a ⊕ b ⊕ c) — convergent state regardless
//!   of pairing.
//! - Mixed-tombstone tag override (§11.3) end-to-end.
//! - Forward-compat `unknown` maps at both record and block level.
//! - Vector-clock dispatch: each [`ClockRelation`] branch via
//!   [`merge_block`] with realistic clocks.
//! - Multi-record block where some records collide and others don't.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ciborium::Value;
use secretary_core::vault::{
    clock_relation, merge_block, merge_record, merge_vector_clocks, BlockPlaintext, ClockRelation,
    ConflictError, Record, RecordField, RecordFieldValue, UnknownValue, VectorClockEntry,
};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn vc(d: u8, c: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid: [d; 16],
        counter: c,
    }
}

fn rfield(value: RecordFieldValue, last_mod: u64, dev: u8) -> RecordField {
    RecordField {
        value,
        last_mod,
        device_uuid: [dev; 16],
        unknown: BTreeMap::new(),
    }
}

fn record(record_uuid: u8, fields: &[(&str, RecordField)], last_mod_ms: u64) -> Record {
    let mut map = BTreeMap::new();
    for (name, field) in fields {
        map.insert((*name).to_string(), field.clone());
    }
    Record {
        record_uuid: [record_uuid; 16],
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

fn pt(block_uuid: u8, records: Vec<Record>) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid: [block_uuid; 16],
        block_name: "vault".to_string(),
        schema_version: 1,
        records,
        unknown: BTreeMap::new(),
    }
}

fn unknown_int(n: u64) -> UnknownValue {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Integer(n.into()), &mut bytes)
        .expect("ciborium serialize is infallible");
    UnknownValue::from_canonical_cbor(&bytes).expect("v1-canonical bytes")
}

// ---------------------------------------------------------------------------
// Three-way merge convergence
// ---------------------------------------------------------------------------

#[test]
fn three_way_merge_is_associative_on_persisted_record() {
    // Three concurrent edits to the same record_uuid, by three devices,
    // each picking different fields. Merging in any pairing order must
    // converge on the same persisted state.
    let a = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("alice".into()), 100, 1),
        )],
        100,
    );
    let b = record(
        7,
        &[(
            "p",
            rfield(RecordFieldValue::Text("pass-b".into()), 200, 2),
        )],
        200,
    );
    let c = record(
        7,
        &[(
            "n",
            rfield(RecordFieldValue::Text("notes-c".into()), 300, 3),
        )],
        300,
    );

    let ab = merge_record(&a, &b).merged;
    let abc = merge_record(&ab, &c).merged;

    let bc = merge_record(&b, &c).merged;
    let abc_alt = merge_record(&a, &bc).merged;

    assert_eq!(abc, abc_alt, "associative on the persisted record");
    assert_eq!(abc.fields.len(), 3);
    assert_eq!(abc.last_mod_ms, 300, "max of the three");
    assert_eq!(abc.created_at_ms, 1_000, "min of the three");
}

#[test]
fn three_way_merge_with_collisions_picks_global_lww_winner() {
    // Three devices write conflicting values to the same field. The
    // pairwise merge sequence must still pick the last-writer-wins
    // value.
    let a = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("v-a".into()), 100, 1),
        )],
        100,
    );
    let b = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("v-b".into()), 200, 2),
        )],
        200,
    );
    let c = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("v-c".into()), 150, 3),
        )],
        150,
    );

    let abc = merge_record(&merge_record(&a, &b).merged, &c).merged;
    let bca = merge_record(&merge_record(&b, &c).merged, &a).merged;
    let cab = merge_record(&merge_record(&c, &a).merged, &b).merged;

    assert_eq!(abc.fields["u"].value, RecordFieldValue::Text("v-b".into()));
    assert_eq!(bca.fields["u"].value, RecordFieldValue::Text("v-b".into()));
    assert_eq!(cab.fields["u"].value, RecordFieldValue::Text("v-b".into()));
    assert_eq!(abc, bca);
    assert_eq!(bca, cab);
}

// ---------------------------------------------------------------------------
// §11.3 mixed-tombstone tag override
// ---------------------------------------------------------------------------

#[test]
fn mixed_tombstone_tie_takes_tombstone_side_tags() {
    // Local: tombstoned, tags = ["archived"], last_mod_ms = 100.
    // Remote: live, tags = ["work"], last_mod_ms = 100.
    // Tombstone wins on tie; merged tags follow the tombstoning side.
    let mut local = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("alice".into()), 100, 1),
        )],
        100,
    );
    local.tombstone = true;
    local.fields.clear(); // tombstoned records carry empty fields
    local.tags = vec!["archived".to_string()];

    let mut remote = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("alice".into()), 100, 2),
        )],
        100,
    );
    remote.tags = vec!["work".to_string()];

    let m = merge_record(&local, &remote);
    assert!(m.merged.tombstone, "tombstone wins on tie");
    assert!(m.merged.fields.is_empty(), "tombstoned records have no fields");
    assert_eq!(
        m.merged.tags,
        vec!["archived".to_string()],
        "tombstoning side's tags win per §11.3"
    );
}

// ---------------------------------------------------------------------------
// Forward-compat unknown maps
// ---------------------------------------------------------------------------

#[test]
fn record_unknown_lex_larger_canonical_cbor_wins_on_collision() {
    let mut a = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("alice".into()), 100, 1),
        )],
        100,
    );
    a.unknown.insert("v2_key".to_string(), unknown_int(5));

    let mut b = record(
        7,
        &[(
            "u",
            rfield(RecordFieldValue::Text("alice".into()), 100, 1),
        )],
        100,
    );
    b.unknown.insert("v2_key".to_string(), unknown_int(10));

    let m = merge_record(&a, &b);
    // Canonical CBOR encoding of an integer puts smaller integers in
    // shorter encodings; 10 encodes to a longer/larger byte string than
    // 5 does. The lex-larger-bytes rule picks the larger-encoding side.
    let bytes_5 = unknown_int(5).to_canonical_cbor().unwrap();
    let bytes_10 = unknown_int(10).to_canonical_cbor().unwrap();
    let expected = if bytes_5 >= bytes_10 {
        unknown_int(5)
    } else {
        unknown_int(10)
    };
    assert_eq!(m.merged.unknown["v2_key"], expected);
}

#[test]
fn block_unknown_keys_disjoint_keep_both() {
    let mut a = pt(5, Vec::new());
    a.unknown.insert("v2_a".to_string(), unknown_int(1));
    let mut b = pt(5, Vec::new());
    b.unknown.insert("v2_b".to_string(), unknown_int(2));

    let m = merge_block(&a, &[vc(1, 1)], &b, &[vc(2, 1)], [9; 16]).expect("ok");
    assert_eq!(m.merged.unknown.len(), 2);
    assert_eq!(m.merged.unknown["v2_a"], unknown_int(1));
    assert_eq!(m.merged.unknown["v2_b"], unknown_int(2));
}

// ---------------------------------------------------------------------------
// Vector-clock dispatch on realistic clocks
// ---------------------------------------------------------------------------

#[test]
fn clock_relation_used_by_merge_block_dispatch() {
    let local = vec![vc(1, 3), vc(2, 5)];
    let incoming = vec![vc(1, 4), vc(2, 5)];
    assert_eq!(
        clock_relation(&local, &incoming),
        ClockRelation::IncomingDominates
    );

    let mut a = pt(5, Vec::new());
    a.block_name = "old".to_string();
    let mut b = pt(5, Vec::new());
    b.block_name = "new".to_string();

    let m = merge_block(&a, &local, &b, &incoming, [9; 16]).expect("ok");
    assert_eq!(m.relation, ClockRelation::IncomingDominates);
    assert_eq!(
        m.merged.block_name, "new",
        "the dominant side's plaintext is adopted whole"
    );
    assert_eq!(m.vector_clock, incoming, "and so is its clock — no tick");
}

#[test]
fn concurrent_merge_ticks_merging_device_into_existing_clock() {
    let local = vec![vc(1, 3)];
    let incoming = vec![vc(2, 4)];
    let merging_device = [9; 16];
    let m = merge_block(
        &pt(5, Vec::new()),
        &local,
        &pt(5, Vec::new()),
        &incoming,
        merging_device,
    )
    .expect("ok");
    assert_eq!(m.relation, ClockRelation::Concurrent);
    // Clock is sorted ascending by device_uuid; entries 1, 2, 9.
    assert_eq!(m.vector_clock.len(), 3);
    let merging_entry = m
        .vector_clock
        .iter()
        .find(|e| e.device_uuid == merging_device)
        .expect("merging device present");
    assert_eq!(merging_entry.counter, 1);
}

#[test]
fn concurrent_merge_ticks_merging_device_already_in_clock() {
    let merging_device = [9; 16];
    // The merging device already has a counter — tick increments it.
    let local = vec![vc(1, 3), VectorClockEntry { device_uuid: merging_device, counter: 7 }];
    let incoming = vec![vc(2, 4)];
    let m = merge_block(
        &pt(5, Vec::new()),
        &local,
        &pt(5, Vec::new()),
        &incoming,
        merging_device,
    )
    .expect("ok");
    let merging_entry = m
        .vector_clock
        .iter()
        .find(|e| e.device_uuid == merging_device)
        .expect("merging device present");
    assert_eq!(merging_entry.counter, 8, "existing counter incremented");
}

// ---------------------------------------------------------------------------
// Mixed-records block: some collide, some don't
// ---------------------------------------------------------------------------

#[test]
fn merge_block_partitions_collisions_correctly() {
    // Block has 4 records: 2 disjoint, 1 identical, 1 conflicting.
    let r_disjoint_a = record(
        1,
        &[("u", rfield(RecordFieldValue::Text("only-a".into()), 100, 1))],
        100,
    );
    let r_disjoint_b = record(
        2,
        &[("u", rfield(RecordFieldValue::Text("only-b".into()), 100, 2))],
        100,
    );
    let r_identical = record(
        3,
        &[("u", rfield(RecordFieldValue::Text("same".into()), 100, 1))],
        100,
    );
    let r_conflicting_a = record(
        4,
        &[("u", rfield(RecordFieldValue::Text("conflict-a".into()), 100, 1))],
        100,
    );
    let r_conflicting_b = record(
        4,
        &[("u", rfield(RecordFieldValue::Text("conflict-b".into()), 200, 2))],
        200,
    );

    let a = pt(5, vec![r_disjoint_a, r_identical.clone(), r_conflicting_a]);
    let b = pt(5, vec![r_disjoint_b, r_identical, r_conflicting_b]);

    let local_clock = vec![vc(1, 1)];
    let incoming_clock = vec![vc(2, 1)];
    let m = merge_block(&a, &local_clock, &b, &incoming_clock, [9; 16]).expect("ok");
    assert_eq!(m.relation, ClockRelation::Concurrent);
    assert_eq!(m.merged.records.len(), 4);
    // Only record 4 has a collision.
    assert_eq!(m.collisions.len(), 1);
    assert_eq!(m.collisions[0].record_uuid, [4; 16]);
    assert_eq!(m.collisions[0].field_collisions.len(), 1);
    assert_eq!(m.collisions[0].field_collisions[0].field_name, "u");
    // Records emerge in record_uuid order: 1, 2, 3, 4.
    assert_eq!(m.merged.records[0].record_uuid, [1; 16]);
    assert_eq!(m.merged.records[3].record_uuid, [4; 16]);
    // Record 4 winner is the LWW: last_mod_ms 200 > 100 → conflict-b.
    assert_eq!(
        m.merged.records[3].fields["u"].value,
        RecordFieldValue::Text("conflict-b".into())
    );
}

// ---------------------------------------------------------------------------
// VaultError #[from] propagation
// ---------------------------------------------------------------------------

#[test]
fn conflict_error_propagates_through_vault_error_from() {
    use secretary_core::vault::VaultError;
    let err = merge_block(
        &pt(1, Vec::new()),
        &[],
        &pt(2, Vec::new()),
        &[],
        [9; 16],
    )
    .expect_err("uuid mismatch");
    let vault_err: VaultError = err.into();
    assert!(matches!(vault_err, VaultError::Conflict(ConflictError::BlockUuidMismatch { .. })));
}

// ---------------------------------------------------------------------------
// Vector-clock primitives stand alone
// ---------------------------------------------------------------------------

#[test]
fn merge_vector_clocks_yields_lattice_join() {
    let a = vec![vc(1, 3), vc(2, 5)];
    let b = vec![vc(2, 7), vc(3, 9)];
    let merged = merge_vector_clocks(&a, &b);
    assert_eq!(merged, vec![vc(1, 3), vc(2, 7), vc(3, 9)]);
    // join is commutative
    assert_eq!(merge_vector_clocks(&a, &b), merge_vector_clocks(&b, &a));
}

// ---------------------------------------------------------------------------
// §15 cross-language KAT replay
// ---------------------------------------------------------------------------
//
// Loads `core/tests/data/conflict_kat.json` and replays each vector through
// the Rust merge primitives, asserting bit-equal output against the JSON's
// `expected` field. The Python sibling (`core/tests/python/conformance.py`
// Section 4) re-runs the merge from spec docs only and asserts the same
// expected output, completing the §15 cross-language conformance contract
// for the merge layer.

fn parse_hex_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect();
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn parse_field_value(spec: &serde_json::Value) -> RecordFieldValue {
    let value_type = spec["value_type"].as_str().expect("value_type");
    match value_type {
        "text" => RecordFieldValue::Text(
            spec["value_text"]
                .as_str()
                .expect("value_text")
                .to_string(),
        ),
        "bytes" => {
            let hex = spec["value_hex"].as_str().expect("value_hex");
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
                .collect();
            RecordFieldValue::Bytes(bytes)
        }
        other => panic!("unknown value_type {other}"),
    }
}

fn parse_record_field(spec: &serde_json::Value) -> RecordField {
    RecordField {
        value: parse_field_value(spec),
        last_mod: spec["last_mod"].as_u64().expect("last_mod"),
        device_uuid: parse_hex_array(spec["device_uuid_hex"].as_str().expect("device_uuid_hex")),
        unknown: BTreeMap::new(),
    }
}

fn parse_record(spec: &serde_json::Value) -> Record {
    let mut fields = BTreeMap::new();
    for f in spec["fields"].as_array().expect("fields[]") {
        fields.insert(
            f["name"].as_str().expect("name").to_string(),
            parse_record_field(f),
        );
    }
    let tags: Vec<String> = spec["tags"]
        .as_array()
        .expect("tags[]")
        .iter()
        .map(|t| t.as_str().expect("tag").to_string())
        .collect();
    Record {
        record_uuid: parse_hex_array(spec["record_uuid_hex"].as_str().expect("record_uuid_hex")),
        record_type: spec["record_type"].as_str().expect("record_type").to_string(),
        fields,
        tags,
        created_at_ms: spec["created_at_ms"].as_u64().expect("created_at_ms"),
        last_mod_ms: spec["last_mod_ms"].as_u64().expect("last_mod_ms"),
        tombstone: spec["tombstone"].as_bool().expect("tombstone"),
        tombstoned_at_ms: spec
            .get("tombstoned_at_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        unknown: BTreeMap::new(),
    }
}

fn parse_block(spec: &serde_json::Value) -> BlockPlaintext {
    let records: Vec<Record> = spec["records"]
        .as_array()
        .expect("records[]")
        .iter()
        .map(parse_record)
        .collect();
    BlockPlaintext {
        block_version: spec["block_version"].as_u64().expect("block_version") as u32,
        block_uuid: parse_hex_array(spec["block_uuid_hex"].as_str().expect("block_uuid_hex")),
        block_name: spec["block_name"].as_str().expect("block_name").to_string(),
        schema_version: spec["schema_version"].as_u64().expect("schema_version") as u32,
        records,
        unknown: BTreeMap::new(),
    }
}

fn parse_clock(spec: &serde_json::Value) -> Vec<VectorClockEntry> {
    spec.as_array()
        .expect("vector_clock[]")
        .iter()
        .map(|e| VectorClockEntry {
            device_uuid: parse_hex_array(e["device_uuid_hex"].as_str().expect("device_uuid_hex")),
            counter: e["counter"].as_u64().expect("counter"),
        })
        .collect()
}

fn parse_relation(s: &str) -> ClockRelation {
    match s {
        "Equal" => ClockRelation::Equal,
        "IncomingDominates" => ClockRelation::IncomingDominates,
        "IncomingDominated" => ClockRelation::IncomingDominated,
        "Concurrent" => ClockRelation::Concurrent,
        other => panic!("unknown ClockRelation {other}"),
    }
}

#[test]
fn kat_replays_match_rust_merge() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("conflict_kat.json");
    let raw = std::fs::read_to_string(&path).expect("read conflict_kat.json");
    let kat: serde_json::Value = serde_json::from_str(&raw).expect("parse conflict_kat.json");
    assert_eq!(kat["version"], 1);

    let vectors = kat["vectors"].as_array().expect("vectors[]");
    assert!(!vectors.is_empty(), "KAT has at least one vector");

    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let merging_device: [u8; 16] =
            parse_hex_array(vector["merging_device_hex"].as_str().expect("merging_device_hex"));

        let local_block = parse_block(&vector["local"]["block"]);
        let local_clock = parse_clock(&vector["local"]["vector_clock"]);
        let remote_block = parse_block(&vector["remote"]["block"]);
        let remote_clock = parse_clock(&vector["remote"]["vector_clock"]);

        let merged =
            merge_block(&local_block, &local_clock, &remote_block, &remote_clock, merging_device)
                .unwrap_or_else(|e| panic!("vector {name}: merge_block failed: {e}"));

        let expected_relation = parse_relation(vector["expected"]["relation"].as_str().expect("relation"));
        assert_eq!(merged.relation, expected_relation, "vector {name}: relation");

        let expected_block = parse_block(&vector["expected"]["block"]);
        assert_eq!(merged.merged, expected_block, "vector {name}: merged block plaintext");

        let expected_clock = parse_clock(&vector["expected"]["vector_clock"]);
        assert_eq!(merged.vector_clock, expected_clock, "vector {name}: merged vector clock");

        let expected_collisions = vector["expected"]["collisions"]
            .as_array()
            .expect("collisions[]");
        assert_eq!(
            merged.collisions.len(),
            expected_collisions.len(),
            "vector {name}: collision count"
        );
        for (got, want) in merged.collisions.iter().zip(expected_collisions.iter()) {
            let want_uuid: [u8; 16] = parse_hex_array(
                want["record_uuid_hex"].as_str().expect("record_uuid_hex"),
            );
            assert_eq!(got.record_uuid, want_uuid, "vector {name}: collision record_uuid");
            let want_fcs = want["field_collisions"]
                .as_array()
                .expect("field_collisions[]");
            assert_eq!(
                got.field_collisions.len(),
                want_fcs.len(),
                "vector {name}: field collision count"
            );
            for (gfc, wfc) in got.field_collisions.iter().zip(want_fcs.iter()) {
                assert_eq!(
                    gfc.field_name,
                    wfc["field_name"].as_str().expect("field_name"),
                    "vector {name}: field_name"
                );
                assert_eq!(
                    gfc.winner,
                    parse_record_field(&wfc["winner"]),
                    "vector {name}: collision winner"
                );
                assert_eq!(
                    gfc.loser,
                    parse_record_field(&wfc["loser"]),
                    "vector {name}: collision loser"
                );
            }
        }
    }
}
