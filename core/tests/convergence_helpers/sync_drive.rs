//! C.4 Task 4 — merger + adopter sync drivers.
//!
//! These free functions wire the convergence harness's `Baseline` /
//! `Device` handles to the *real* `sync_once` / `prepare_merge` /
//! `commit_with_decisions` pipeline. They are the first end-to-end proof
//! that two real device edits, reconciled through a shared folder, drive
//! the production sync code to convergence.
//!
//! The correctness model (one user's vault on two of their devices,
//! sharing one identity but distinct `device_uuid`s):
//! - The **merger** = the conflict-copy device. Its remembered
//!   `SyncState` clock is its own post-edit manifest clock, which is
//!   *concurrent* with the canonical clock (each ticked a different
//!   device_uuid from the same empty baseline). So `sync_once` returns
//!   `ConcurrentDetected`; the merger then `prepare_merge` →
//!   `commit_with_decisions`.
//! - The **adopter** = the canonical device. After the merger commits,
//!   the merged LUB strictly dominates the adopter's remembered clock,
//!   so `sync_once` returns `AppliedAutomatically`.

use std::path::Path;

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncOutcome, SyncState, VetoDecision,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};

use crate::convergence_helpers::{Baseline, Device};

/// How the merger resolves any tombstone-vs-edit veto in `prepare_merge`.
#[derive(Clone, Copy, Debug)]
pub enum VetoPolicy {
    /// The scenario must produce zero vetoes; assert that and pass `[]`.
    NoVetoExpected,
    /// Keep every locally-live record over a peer tombstone.
    KeepLocal,
    /// Honour every peer tombstone.
    AcceptTombstone,
}

/// Unlock the baseline identity from its on-disk vault.toml + bundle.
/// Every device shares this one identity (same signing keys); the
/// `UnlockedIdentity` is what `sync_once` / `prepare_merge` consume.
fn unlocked_identity(baseline: &Baseline) -> UnlockedIdentity {
    let folder = baseline.folder();
    let vt = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).expect("read bundle");
    open_with_password(&vt, &bundle, baseline.password()).expect("open_with_password")
}

fn vault_uuid(baseline: &Baseline) -> [u8; 16] {
    baseline.open_manifest().vault_uuid
}

/// Drive the merger device: its remembered state is its own post-edit
/// clock (concurrent with canonical), so `sync_once` returns
/// `ConcurrentDetected`; resolve per `policy` and commit. Returns the
/// post-commit `SyncState`.
pub fn sync_as_merger(
    baseline: &Baseline,
    shared: &Path,
    merger: &Device,
    policy: VetoPolicy,
    now_ms: u64,
) -> SyncState {
    let identity = unlocked_identity(baseline);
    let state =
        SyncState::new(vault_uuid(baseline), merger.manifest_clock()).expect("merger SyncState");
    match sync_once(shared, &identity, &state, now_ms).expect("merger sync_once") {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => {
            let draft = prepare_merge(shared, &identity, &bundle, &plan).expect("prepare_merge");
            let decisions: Vec<VetoDecision> = match policy {
                VetoPolicy::NoVetoExpected => {
                    assert!(
                        draft.vetoes.is_empty(),
                        "scenario expected no vetoes, got {}",
                        draft.vetoes.len()
                    );
                    Vec::new()
                }
                VetoPolicy::KeepLocal => draft
                    .vetoes
                    .iter()
                    .map(|v| VetoDecision::KeepLocal {
                        record_id: v.record_id,
                    })
                    .collect(),
                VetoPolicy::AcceptTombstone => draft
                    .vetoes
                    .iter()
                    .map(|v| VetoDecision::AcceptTombstone {
                        record_id: v.record_id,
                    })
                    .collect(),
            };
            commit_with_decisions(shared, baseline.password(), draft, decisions, now_ms)
                .expect("commit_with_decisions")
        }
        other => panic!("merger expected ConcurrentDetected, got {other:?}"),
    }
}

/// Drive the adopter device: the merged canonical LUB strictly dominates its
/// remembered (post-edit) clock, so `sync_once` **must** return
/// `AppliedAutomatically`. Any other outcome — including `NothingToDo` —
/// panics: a `NothingToDo` here would mean the fixture had no real divergence
/// and the quiescence check that follows would pass vacuously. Returns the
/// new `SyncState`.
pub fn sync_as_adopter(
    baseline: &Baseline,
    shared: &Path,
    adopter: &Device,
    now_ms: u64,
) -> SyncState {
    let identity = unlocked_identity(baseline);
    let state =
        SyncState::new(vault_uuid(baseline), adopter.manifest_clock()).expect("adopter SyncState");
    match sync_once(shared, &identity, &state, now_ms).expect("adopter sync_once") {
        SyncOutcome::AppliedAutomatically { new_state } => new_state,
        other => panic!("adopter expected AppliedAutomatically, got {other:?}"),
    }
}

/// True iff re-running `sync_once` from `state` is a no-op (quiescence).
pub fn is_nothing_to_do(
    baseline: &Baseline,
    shared: &Path,
    state: &SyncState,
    now_ms: u64,
) -> bool {
    let identity = unlocked_identity(baseline);
    matches!(
        sync_once(shared, &identity, state, now_ms).expect("quiescence sync_once"),
        SyncOutcome::NothingToDo
    )
}

/// Adopter whose clock is empty (it never edited) — scenario 1.
pub fn sync_as_pure_adopter(baseline: &Baseline, shared: &Path, now_ms: u64) -> SyncState {
    let identity = unlocked_identity(baseline);
    let state = SyncState::empty(vault_uuid(baseline));
    match sync_once(shared, &identity, &state, now_ms).expect("pure adopter sync_once") {
        SyncOutcome::AppliedAutomatically { new_state } => new_state,
        other => panic!("pure adopter expected AppliedAutomatically, got {other:?}"),
    }
}
