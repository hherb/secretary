//! Cross-language sync-pass classification KAT — Task 6 of the D.1.13 plan.
//!
//! Pins the pause-on-conflict truth table that
//! `secretary_cli::pipeline::sync_pass_pause_on_conflict` implements, plus the
//! post-merge LUB it advances `state.highest_vector_clock_seen` to on the
//! advancing arms. This guard derives the outcome label from
//! [`clock_relation`] + `diverging_blocks` + `veto_count` exactly as the cli
//! does, and computes the post-clock via [`merge_vector_clocks`] — the same
//! primitives the production path uses. The stdlib-only
//! `conformance.py::section_sync_pass_kat` replays the SAME fixture from a
//! clean-room re-implementation; a divergence between the two is the
//! cross-language bug this KAT exists to catch.
//!
//! No crypto: this is pure vector-clock classification. The per-record / LUB
//! merge math is also covered cross-language by conflict_kat.
//!
//! ## clock_relation direction (the load-bearing detail)
//!
//! `sync_once` (core/src/sync/once.rs:84) calls
//! `clock_relation(&state.highest_vector_clock_seen, &disk_clock)` — local
//! FIRST, disk (incoming) SECOND. The [`ClockRelation`] variants are named
//! from the incoming (disk) perspective (core/src/vault/conflict.rs:53-88), so:
//!
//! - `Equal` -> NothingToDo (once.rs:87)
//! - `IncomingDominates` -> AppliedAutomatically (once.rs:88; disk > local)
//! - `IncomingDominated` -> RollbackRejected (once.rs:94; local > disk)
//! - `Concurrent` -> {SilentMerge|MergedClean|ConflictsPending}
//!
//! This guard calls `clock_relation(local_seen, disk_clock)` to match.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{clock_relation, merge_vector_clocks, ClockRelation};

fn sync_pass_kat_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("sync_pass_kat")
}

/// Parse a `[hex, counter]` pair into a [`VectorClockEntry`]: the hex string is
/// a single-byte fill of the 16-byte device_uuid.
fn parse_entry(pair: &serde_json::Value) -> VectorClockEntry {
    let arr = pair
        .as_array()
        .expect("clock entry must be a [hex, counter] array");
    assert_eq!(arr.len(), 2, "clock entry must be [hex, counter]");
    let hex = arr[0].as_str().expect("device hex must be a string");
    let fill = u8::from_str_radix(hex, 16).expect("device hex must be a single byte");
    let counter = arr[1].as_u64().expect("counter must be a u64");
    VectorClockEntry {
        device_uuid: [fill; 16],
        counter,
    }
}

/// Parse a clock (array of `[hex, counter]` pairs) into a `Vec`.
fn parse_clock(v: &serde_json::Value) -> Vec<VectorClockEntry> {
    v.as_array()
        .expect("clock must be an array")
        .iter()
        .map(parse_entry)
        .collect()
}

/// Canonicalize a clock to a sorted `(device_uuid, counter)` set for
/// order-independent comparison.
fn clock_set(clock: &[VectorClockEntry]) -> Vec<([u8; 16], u64)> {
    let mut out: Vec<([u8; 16], u64)> = clock.iter().map(|e| (e.device_uuid, e.counter)).collect();
    out.sort();
    out
}

/// Derive the sync-pass outcome label from the clock relation + flags, exactly
/// as `sync_pass_pause_on_conflict` does. Returns the label string used in the
/// fixture's `expected_outcome`.
fn derive_outcome(
    local_seen: &[VectorClockEntry],
    disk_clock: &[VectorClockEntry],
    diverging_blocks: u64,
    veto_count: u64,
) -> &'static str {
    // Direction: local first, disk (incoming) second — see module docs +
    // core/src/sync/once.rs:84.
    match clock_relation(local_seen, disk_clock) {
        ClockRelation::Equal => "NothingToDo",
        ClockRelation::IncomingDominates => "AppliedAutomatically",
        ClockRelation::IncomingDominated => "RollbackRejected",
        ClockRelation::Concurrent => {
            if diverging_blocks == 0 {
                "SilentMerge"
            } else if veto_count > 0 {
                "ConflictsPending"
            } else {
                "MergedClean"
            }
        }
    }
}

/// Post-merge LUB for the advancing arms: fold `merge_vector_clocks` over the
/// disk clock + every copy clock + the prior local-seen. Mirrors
/// `silent_merge_clock` (cli/src/pipeline.rs) for the SilentMerge arm.
///
/// For NothingToDo (Equal case), disk == local so the LUB is disk itself;
/// production writes nothing on that arm, but the post-clock check here is a
/// schema-consistency guard — it confirms the fixture's `expected_post_clock`
/// equals the vacuous LUB (disk). For AppliedAutomatically (disk dominates),
/// disk already dominates local so the fold is a no-op beyond disk.
fn post_merge_lub(
    disk_clock: &[VectorClockEntry],
    copy_clocks: &[Vec<VectorClockEntry>],
    local_seen: &[VectorClockEntry],
) -> Vec<VectorClockEntry> {
    let mut acc = disk_clock.to_vec();
    for copy in copy_clocks {
        acc = merge_vector_clocks(&acc, copy);
    }
    merge_vector_clocks(&acc, local_seen)
}

#[test]
fn sync_pass_kat_classification_matches_truth_table() {
    let raw = fs::read_to_string(sync_pass_kat_dir().join("cases.json"))
        .expect("sync_pass_kat/cases.json must be readable");
    let fixture: serde_json::Value = serde_json::from_str(&raw).expect("cases.json must parse");

    assert_eq!(
        fixture["schema"].as_str(),
        Some("sync_pass_kat/v1"),
        "unexpected fixture schema"
    );

    let cases = fixture["cases"].as_array().expect("cases must be an array");
    assert!(!cases.is_empty(), "fixture has no cases");

    for case in cases {
        let name = case["name"].as_str().expect("case name");

        let disk_clock = parse_clock(&case["disk_clock"]);
        let local_seen = parse_clock(&case["local_seen"]);
        let copy_clocks: Vec<Vec<VectorClockEntry>> = case["copy_clocks"]
            .as_array()
            .expect("copy_clocks array")
            .iter()
            .map(parse_clock)
            .collect();
        let diverging_blocks = case["diverging_blocks"].as_u64().expect("diverging_blocks");
        let veto_count = case["veto_count"].as_u64().expect("veto_count");

        // (1) Outcome label matches the truth table.
        let derived = derive_outcome(&local_seen, &disk_clock, diverging_blocks, veto_count);
        let expected = case["expected_outcome"].as_str().expect("expected_outcome");
        assert_eq!(
            derived, expected,
            "case {name}: derived outcome {derived} != expected {expected}"
        );

        // (2) Post-merge clock: advancing arms carry a clock; pausing arms null.
        let post = &case["expected_post_clock"];
        let is_advancing = matches!(
            expected,
            "NothingToDo" | "AppliedAutomatically" | "SilentMerge" | "MergedClean"
        );
        if is_advancing {
            assert!(
                !post.is_null(),
                "case {name}: advancing arm {expected} must carry a post_clock"
            );
            let lub = post_merge_lub(&disk_clock, &copy_clocks, &local_seen);
            let expected_clock = parse_clock(post);
            assert_eq!(
                clock_set(&lub),
                clock_set(&expected_clock),
                "case {name}: computed LUB != expected_post_clock"
            );
        } else {
            assert!(
                post.is_null(),
                "case {name}: pausing arm {expected} must have null post_clock"
            );
        }
    }
}
