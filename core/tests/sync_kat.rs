//! Replay `sync_kat.json` through `__test_dispatch`. Pinned vector
//! file — any change to the dispatch logic that changes an outcome
//! must be accompanied by a deliberate KAT edit.
//!
//! Python clean-room replay lands in C.4 (cross-device convergence
//! conformance), matching the staging pattern of B.6's
//! conformance_kat.json.

#![forbid(unsafe_code)]

use secretary_core::sync::{__test_dispatch, RollbackEvidence, SyncOutcome, SyncState};
use secretary_core::vault::block::VectorClockEntry;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Kat {
    schema_version: u32,
    #[allow(dead_code)]
    description: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    state_vault_uuid: String,
    state_highest_vector_clock: Vec<EntryJson>,
    disk_vector_clock: Vec<EntryJson>,
    expected_outcome: String,
    #[serde(default)]
    expected_new_state_clock: Option<Vec<EntryJson>>,
}

#[derive(Debug, Deserialize)]
struct EntryJson {
    device_uuid: String,
    counter: u64,
}

const EXPECTED_SCHEMA_VERSION: u32 = 1;
const EXPECTED_VECTOR_COUNT: usize = 9;
const UUID_LEN: usize = 16;

fn hex_to_uuid(s: &str) -> [u8; UUID_LEN] {
    let bytes = hex::decode(s).expect("hex");
    assert_eq!(bytes.len(), UUID_LEN, "uuid hex must be 16 bytes");
    let mut out = [0u8; UUID_LEN];
    out.copy_from_slice(&bytes);
    out
}

fn entries_from_json(js: &[EntryJson]) -> Vec<VectorClockEntry> {
    js.iter()
        .map(|e| VectorClockEntry {
            device_uuid: hex_to_uuid(&e.device_uuid),
            counter: e.counter,
        })
        .collect()
}

#[test]
fn replay_sync_kat() {
    let raw = std::fs::read_to_string("tests/data/sync_kat.json").unwrap();
    let kat: Kat = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        kat.schema_version, EXPECTED_SCHEMA_VERSION,
        "sync_kat.json schema_version drift"
    );

    for v in &kat.vectors {
        let state_clock = entries_from_json(&v.state_highest_vector_clock);
        let disk_clock = entries_from_json(&v.disk_vector_clock);
        let state = SyncState::new(hex_to_uuid(&v.state_vault_uuid), state_clock)
            .unwrap_or_else(|e| panic!("vector {} state invalid: {e}", v.name));
        let outcome = __test_dispatch(disk_clock.clone(), &state)
            .unwrap_or_else(|e| panic!("vector {} dispatch failed: {e}", v.name));

        match (v.expected_outcome.as_str(), &outcome) {
            ("NothingToDo", SyncOutcome::NothingToDo) => {}
            ("AppliedAutomatically", SyncOutcome::AppliedAutomatically { new_state }) => {
                let expected = entries_from_json(
                    v.expected_new_state_clock
                        .as_ref()
                        .expect("AppliedAutomatically vector must carry expected_new_state_clock"),
                );
                assert_eq!(
                    new_state.highest_vector_clock_seen, expected,
                    "vector {} new_state clock mismatch",
                    v.name
                );
            }
            ("ForkDetected", SyncOutcome::ForkDetected { .. }) => {}
            ("RollbackRejected", SyncOutcome::RollbackRejected(RollbackEvidence { .. })) => {}
            (expected, actual) => {
                panic!("vector {} expected {} got {:?}", v.name, expected, actual)
            }
        }
    }

    assert_eq!(
        kat.vectors.len(),
        EXPECTED_VECTOR_COUNT,
        "sync_kat.json vector count drift"
    );
}
