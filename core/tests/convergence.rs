//! C.4 — cross-device convergence conformance. Two real device
//! identities edit one user's vault and reconcile through a shared
//! folder; the harness proves they converge to the same logical state
//! independent of sync order. See
//! docs/superpowers/specs/2026-06-15-c4-convergence-conformance-design.md.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use convergence_helpers::{reconcile, Baseline, Device};
use convergence_helpers::{sync_as_adopter, sync_as_merger, VetoPolicy};

const A_UUID: [u8; 16] = [0x0A; 16];
const B_UUID: [u8; 16] = [0x0B; 16];
const X_RECORD: [u8; 16] = [0xAA; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];

#[test]
fn baseline_creates_an_empty_openable_vault() {
    let baseline = Baseline::create();
    let manifest = baseline.open_manifest();
    assert!(
        manifest.blocks.is_empty(),
        "fresh baseline must have no blocks"
    );
    assert!(
        manifest.vector_clock.is_empty(),
        "fresh baseline must have an empty manifest vector clock",
    );
}

#[test]
fn reconcile_lays_out_canonical_plus_conflict_copy() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 100);

    // A canonical, B merger (B's files become conflict-copies in S).
    let shared = reconcile(&a, Some(&b), X_BLOCK);

    let s = shared.folder();
    assert!(s.join("manifest.cbor.enc").exists());
    let manifest_siblings: Vec<_> = std::fs::read_dir(s)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("manifest.cbor.enc") && n != "manifest.cbor.enc")
        .collect();
    assert_eq!(
        manifest_siblings.len(),
        1,
        "expected exactly one manifest conflict-copy"
    );
}

#[test]
fn device_edit_writes_a_record_with_its_device_clock() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, /*seed*/ 0xA0);
    a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice", /*now_ms*/ 100);

    let records = a.decrypt_block_records(X_BLOCK);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_uuid, X_RECORD);
    assert!(!records[0].tombstone);

    let clock = a.manifest_clock();
    assert!(
        clock
            .iter()
            .any(|e| e.device_uuid == A_UUID && e.counter >= 1),
        "device A's edit must tick its own vector-clock entry",
    );
}

#[test]
fn merger_then_adopter_both_quiesce_on_disjoint_fields() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 100);

    // A canonical / B merger.
    let shared = reconcile(&a, Some(&b), X_BLOCK);

    // B merges (disjoint fields → no veto needed).
    let b_state = sync_as_merger(
        &baseline,
        shared.folder(),
        &b,
        VetoPolicy::NoVetoExpected,
        1_000,
    );
    // A adopts the merged LUB.
    let a_state = sync_as_adopter(&baseline, shared.folder(), &a, 1_001);

    // Quiescence: re-running sync on each device's final state is a no-op.
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &b_state,
        1_002
    ));
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &a_state,
        1_003
    ));
}
