//! Replay `sync_kat.json` through the public sync API. Pinned vector
//! file — any change to dispatch logic that alters an outcome must be
//! accompanied by a deliberate KAT edit.
//!
//! ## Vector families (schema v2)
//!
//! - `clock_dispatch` — pure vector-clock dispatch via the lib's
//!   `__test_dispatch` helper. State (`state_vault_uuid` +
//!   `state_highest_vector_clock`) × disk (`disk_vector_clock`) maps to
//!   a `SyncOutcome` variant name. The `__test_dispatch` helper
//!   intentionally avoids disk I/O — `ConcurrentDetected` is signalled
//!   by `Ok(None)` and treated as a pass-through here.
//! - `concurrent_merge_apply_decisions` — full three-step merge flow
//!   (`sync_once → prepare_merge → commit_with_decisions`) on a
//!   per-block-divergent fixture built by a scenario-named fixture
//!   builder (`no_veto`, `single_veto`, `two_veto`). Decisions are
//!   deserialised from JSON and applied verbatim.
//! - `evidence_stale` — drives the commit-time TOCTOU re-check by
//!   mutating the manifest between `prepare_merge` and
//!   `commit_with_decisions`; asserts `SyncError::EvidenceStale`.
//! - `fingerprint_repair` — simulates a partial-commit (block file
//!   rewritten without the manifest update) and asserts that
//!   `open_vault` fires `VaultError::BlockFingerprintMismatch`. The
//!   recovery (idempotent reconvergence via re-running the three-step
//!   flow) is exercised in `sync_merge_crash.rs` proper; the KAT
//!   pins the typed-error surface only.
//!
//! Python clean-room replay lands in C.4 (cross-device convergence
//! conformance) — see issue #76. At that point the JSON may bump to
//! schema v3 to encode fully self-describing fixture parameters; the
//! current v2 carries scenario-names plus expected outcome shape only.

#![forbid(unsafe_code)]

use secretary_core::sync::{
    __test_dispatch, commit_with_decisions, compute_manifest_hash, prepare_merge, sync_once,
    RollbackEvidence, SyncError, SyncOutcome, SyncState, VetoDecision,
};
use secretary_core::vault::block::VectorClockEntry;
use serde::Deserialize;

mod fixtures;
mod sync_helpers;
mod sync_merge_proptest_helpers;

use sync_merge_proptest_helpers::{
    build_no_veto_fixture, build_same_block_field_lww_no_veto_fixture, build_single_veto_fixture,
    build_two_veto_fixture, drive_sync_once_concurrent, open_identity,
    read_canonical_block_records, COMMIT_NOW_MS, RECORD_A_UUID, RECORD_B_UUID,
};

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
    #[serde(flatten)]
    body: VectorBody,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "vector_type")]
enum VectorBody {
    #[serde(rename = "clock_dispatch")]
    ClockDispatch(ClockDispatchVector),
    #[serde(rename = "concurrent_merge_apply_decisions")]
    ConcurrentMergeApplyDecisions(ConcurrentMergeApplyDecisionsVector),
    #[serde(rename = "evidence_stale")]
    EvidenceStale(EvidenceStaleVector),
}

#[derive(Debug, Deserialize)]
struct ClockDispatchVector {
    state_vault_uuid: String,
    state_highest_vector_clock: Vec<EntryJson>,
    disk_vector_clock: Vec<EntryJson>,
    expected_outcome: String,
    #[serde(default)]
    expected_new_state_clock: Option<Vec<EntryJson>>,
}

#[derive(Debug, Deserialize)]
struct EvidenceStaleVector {
    scenario: String,
    counter_canonical: u64,
    counter_sibling: u64,
    /// New counter written into the racing manifest. The racing
    /// manifest's clock has exactly one entry — `(RACING_DEVICE_UUID,
    /// racing_counter)` — which is well-formed but byte-different from
    /// the prepare-time canonical manifest envelope, forcing the
    /// commit-time freshness re-check to fire `EvidenceStale`.
    racing_counter: u64,
}

#[derive(Debug, Deserialize)]
struct ConcurrentMergeApplyDecisionsVector {
    scenario: String,
    counter_canonical: u64,
    counter_sibling: u64,
    decisions: Vec<DecisionJson>,
    expected_vetoes_count: usize,
    expected_diverging_blocks_count: usize,
    expected_post_commit_outcome: String,
    /// Optional: the number of records the canonical block holds after
    /// commit_with_decisions returns. Distinguishes disjoint-UUID merges
    /// (record count = 2) from same-UUID-LWW merges (count = 1).
    #[serde(default)]
    expected_post_commit_canonical_records_count: Option<usize>,
    /// Optional: the `tombstone` flag of the FIRST record in the
    /// post-commit canonical block. Distinguishes `KeepLocal` (live —
    /// `false`) from `AcceptTombstone` (tombstoned — `true`) at the
    /// KAT level; the deeper field-by-field semantics (death-clock
    /// preserved, last_mod_ms advanced) live in `sync_merge_vetoes.rs`.
    /// Only consulted when
    /// `expected_post_commit_canonical_records_count` is set.
    #[serde(default)]
    expected_canonical_record_tombstoned: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct EntryJson {
    device_uuid: String,
    counter: u64,
}

#[derive(Debug, Deserialize)]
struct DecisionJson {
    kind: String,
    record_id: String,
}

const EXPECTED_SCHEMA_VERSION: u32 = 2;
const EXPECTED_VECTOR_COUNT: usize = 15;
const UUID_LEN: usize = 16;

/// Synthetic device UUID for the `evidence_stale` race-window manifest
/// rewrite. Distinct from the fixture's canonical / sibling device
/// UUIDs (which are private to the proptest helpers) so this binary
/// doesn't couple to those constants. Any well-formed new clock advances
/// the on-disk manifest envelope hash off `draft.manifest_hash`.
const RACING_DEVICE_UUID: [u8; UUID_LEN] = [0x99; UUID_LEN];

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

/// Convert a JSON `DecisionJson` into a `VetoDecision`. `record_id` may
/// be a literal 16-byte hex string OR one of the symbolic aliases
/// (`RECORD_A_UUID`, `RECORD_B_UUID`) bound to the proptest-helper
/// fixture constants. Symbolic aliases let scenario vectors reference
/// records by stable name rather than hex copy.
fn decision_from_json(d: &DecisionJson) -> VetoDecision {
    let record_id = match d.record_id.as_str() {
        "RECORD_A_UUID" => RECORD_A_UUID,
        "RECORD_B_UUID" => RECORD_B_UUID,
        hex_id => hex_to_uuid(hex_id),
    };
    match d.kind.as_str() {
        "KeepLocal" => VetoDecision::KeepLocal { record_id },
        "AcceptTombstone" => VetoDecision::AcceptTombstone { record_id },
        other => panic!("unknown VetoDecision kind: {other}"),
    }
}

/// Replay a `clock_dispatch` vector through the public
/// `__test_dispatch` helper. Mirrors the v1 schema's loop body.
fn replay_clock_dispatch(name: &str, v: &ClockDispatchVector) {
    let state_clock = entries_from_json(&v.state_highest_vector_clock);
    let disk_clock = entries_from_json(&v.disk_vector_clock);
    let state = SyncState::new(hex_to_uuid(&v.state_vault_uuid), state_clock)
        .unwrap_or_else(|e| panic!("vector {name} state invalid: {e}"));
    let outcome_opt = __test_dispatch(disk_clock.clone(), &state)
        .unwrap_or_else(|e| panic!("vector {name} dispatch failed: {e}"));

    // `__test_dispatch` deliberately avoids disk I/O — `ConcurrentDetected`
    // is signalled by `Ok(None)`; all other outcomes arrive as `Some(_)`.
    let outcome = match (&outcome_opt, v.expected_outcome.as_str()) {
        (None, "ConcurrentDetected" | "ForkDetected") => return,
        (None, other) => {
            panic!("vector {name} expected {other} but dispatch signalled Concurrent (None)",)
        }
        (Some(o), _) => o,
    };

    match (v.expected_outcome.as_str(), outcome) {
        ("NothingToDo", SyncOutcome::NothingToDo) => {}
        ("AppliedAutomatically", SyncOutcome::AppliedAutomatically { new_state }) => {
            let expected = entries_from_json(
                v.expected_new_state_clock
                    .as_ref()
                    .expect("AppliedAutomatically vector must carry expected_new_state_clock"),
            );
            assert_eq!(
                new_state.highest_vector_clock_seen, expected,
                "vector {name} new_state clock mismatch",
            );
        }
        ("RollbackRejected", SyncOutcome::RollbackRejected(RollbackEvidence { .. })) => {}
        (expected, actual) => {
            panic!("vector {name} expected {expected} got {actual:?}")
        }
    }
}

/// Build a per-block-divergent fixture by scenario name and return the
/// `(folder, _tmp, block_uuid)` triple. The `_tmp` handle MUST stay
/// alive while the folder is in use — dropping it removes the temp
/// directory.
fn build_concurrent_fixture(
    scenario: &str,
    counter_canonical: u64,
    counter_sibling: u64,
) -> (std::path::PathBuf, tempfile::TempDir, [u8; UUID_LEN]) {
    match scenario {
        "no_veto" => build_no_veto_fixture(counter_canonical, counter_sibling),
        "same_block_field_lww_no_veto" => {
            build_same_block_field_lww_no_veto_fixture(counter_canonical, counter_sibling)
        }
        "single_veto" => build_single_veto_fixture(counter_canonical, counter_sibling),
        "two_veto" => build_two_veto_fixture(counter_canonical, counter_sibling),
        other => panic!("unknown scenario name: {other}"),
    }
}

/// Replay a `concurrent_merge_apply_decisions` vector through the full
/// three-step merge flow. The fixture is built from
/// `(scenario, counter_canonical, counter_sibling)`; decisions are
/// deserialised verbatim from JSON; assertions cover the
/// `DraftMerge` shape, `commit_with_decisions` success, and the
/// post-commit `sync_once` outcome.
fn replay_concurrent_merge_apply_decisions(name: &str, v: &ConcurrentMergeApplyDecisionsVector) {
    let (folder, _tmp, block_uuid) =
        build_concurrent_fixture(&v.scenario, v.counter_canonical, v.counter_sibling);
    let identity = open_identity(&folder);
    let (bundle, plan) = drive_sync_once_concurrent(&folder);

    let draft = prepare_merge(&folder, &identity, &bundle, &plan)
        .unwrap_or_else(|e| panic!("vector {name} prepare_merge failed: {e}"));
    assert_eq!(
        draft.vetoes.len(),
        v.expected_vetoes_count,
        "vector {name} vetoes count mismatch",
    );
    assert_eq!(
        draft.plan.diverging_blocks.len(),
        v.expected_diverging_blocks_count,
        "vector {name} diverging_blocks count mismatch",
    );

    let decisions: Vec<VetoDecision> = v.decisions.iter().map(decision_from_json).collect();
    let password = fixtures::golden_vault_001_password();
    let new_state = commit_with_decisions(&folder, &password, draft, decisions, COMMIT_NOW_MS)
        .unwrap_or_else(|e| panic!("vector {name} commit_with_decisions failed: {e}"));

    if let Some(expected_count) = v.expected_post_commit_canonical_records_count {
        let records = read_canonical_block_records(&folder, block_uuid);
        assert_eq!(
            records.len(),
            expected_count,
            "vector {name} canonical-block records count mismatch",
        );
        if let Some(expected_tombstoned) = v.expected_canonical_record_tombstoned {
            assert!(
                !records.is_empty(),
                "vector {name} expected canonical record tombstone flag but block is empty",
            );
            assert_eq!(
                records[0].tombstone, expected_tombstoned,
                "vector {name} canonical-block first record tombstone-flag mismatch",
            );
        }
    }

    // Closure property: re-running `sync_once` against the post-commit
    // state on the now-updated disk returns the expected terminal
    // outcome. For all current vectors this is `NothingToDo` (the
    // commit folded both manifests' clocks into the canonical, so
    // `clock_relation` sees `Equal`).
    let outcome2 = sync_once(&folder, &identity, &new_state, 0u64)
        .unwrap_or_else(|e| panic!("vector {name} post-commit sync_once failed: {e}"));
    match (v.expected_post_commit_outcome.as_str(), &outcome2) {
        ("NothingToDo", SyncOutcome::NothingToDo) => {}
        (expected, actual) => {
            panic!("vector {name} expected post-commit {expected} got {actual:?}",)
        }
    }
}

/// Replay an `evidence_stale` vector. Drives the commit-time TOCTOU
/// freshness re-check (`commit_with_decisions` step 2): after
/// `prepare_merge` captures the manifest hash, the canonical manifest
/// is rewritten with a fresh well-formed clock. The subsequent commit
/// must abort with `SyncError::EvidenceStale` and leave the manifest
/// bytes unchanged (zero disk writes from the commit).
fn replay_evidence_stale(name: &str, v: &EvidenceStaleVector) {
    let (folder, _tmp, _block_uuid) =
        build_concurrent_fixture(&v.scenario, v.counter_canonical, v.counter_sibling);
    let identity = open_identity(&folder);
    let (bundle, plan) = drive_sync_once_concurrent(&folder);

    let draft = prepare_merge(&folder, &identity, &bundle, &plan)
        .unwrap_or_else(|e| panic!("vector {name} prepare_merge failed: {e}"));

    let racing_clock = vec![VectorClockEntry {
        device_uuid: RACING_DEVICE_UUID,
        counter: v.racing_counter,
    }];
    sync_helpers::write_manifest_at(
        &folder,
        sync_helpers::MANIFEST_FILENAME,
        racing_clock,
        &sync_helpers::SIBLING_NONCE_C,
    );

    let manifest_path = folder.join(sync_helpers::MANIFEST_FILENAME);
    let bytes_before = std::fs::read(&manifest_path)
        .unwrap_or_else(|e| panic!("vector {name} read manifest pre-commit failed: {e}"));
    let hash_before = compute_manifest_hash(&bytes_before);

    let password = fixtures::golden_vault_001_password();
    let err =
        commit_with_decisions(&folder, &password, draft, Vec::new(), COMMIT_NOW_MS).unwrap_err();
    assert!(
        matches!(err, SyncError::EvidenceStale),
        "vector {name} expected SyncError::EvidenceStale, got {err:?}",
    );

    let bytes_after = std::fs::read(&manifest_path)
        .unwrap_or_else(|e| panic!("vector {name} read manifest post-commit failed: {e}"));
    let hash_after = compute_manifest_hash(&bytes_after);
    assert_eq!(
        hash_before, hash_after,
        "vector {name} EvidenceStale must abort with NO disk writes",
    );
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
        match &v.body {
            VectorBody::ClockDispatch(body) => replay_clock_dispatch(&v.name, body),
            VectorBody::ConcurrentMergeApplyDecisions(body) => {
                replay_concurrent_merge_apply_decisions(&v.name, body)
            }
            VectorBody::EvidenceStale(body) => replay_evidence_stale(&v.name, body),
        }
    }

    assert_eq!(
        kat.vectors.len(),
        EXPECTED_VECTOR_COUNT,
        "sync_kat.json vector count drift"
    );
}
