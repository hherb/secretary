//! C.4 — cross-device convergence conformance. Two real device
//! identities edit one user's vault and reconcile through a shared
//! folder; the harness proves they converge to the same logical state
//! independent of sync order. See
//! docs/superpowers/specs/2026-06-15-c4-convergence-conformance-design.md.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use convergence_helpers::Baseline;

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
