//! C.4 — cross-device convergence conformance. Two real device
//! identities edit one user's vault and reconcile through a shared
//! folder; the harness proves they converge to the same logical state
//! independent of sync order. See
//! docs/superpowers/specs/2026-06-15-c4-convergence-conformance-design.md.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use convergence_helpers::{Baseline, Device};

const A_UUID: [u8; 16] = [0x0A; 16];
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
