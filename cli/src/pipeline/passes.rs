//! The four sync passes plus their shared clock-folding helpers.
//!
//! Each pass composes `sync_once → prepare_merge → commit_with_decisions`
//! and updates the caller-held [`SyncState`] in place; they differ only in
//! how they handle the `ConcurrentDetected` arm (auto-veto, pause, inspect,
//! commit). The outcome enums they return live in [`super::outcomes`].

use std::path::Path;

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, DiffPlan, DraftMerge, ManifestHash, SyncError,
    SyncOutcome, SyncState, VaultBundle, VetoDecision,
};
use secretary_core::unlock::UnlockedIdentity;
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::merge_vector_clocks;

use super::outcomes::{InspectOutcome, RunOutcome, SyncPassOutcome};
use crate::veto::VetoUx;

/// Run one sync attempt against `vault_folder`. `identity` serves the
/// reads and the commit-side re-verification. `state` is both input
/// ("what clock have we already seen?") and output (mutated in place
/// when the disk-side clock advances).
///
/// `veto_ux` is invoked exactly on the
/// [`SyncOutcome::ConcurrentDetected`] arm with a non-empty diff plan.
/// Non-interactive callers pass [`crate::veto::noninteractive::AutoKeepLocalVetoUx`];
/// interactive callers pass [`crate::veto::interactive::TtyVetoUx`].
/// Either way the trait method takes `&mut self`, so the same UX
/// instance can adjudicate multiple records in one call.
///
/// `now_ms` is forwarded into the underlying merge timestamp; callers
/// without a wall-clock requirement may pass `0` (the C.1 era pre-
/// merge-timestamp default — `sync_once` itself currently does not
/// consume it, but `commit_with_decisions` writes it into tombstone
/// resurrection metadata).
///
/// # Errors
///
/// Any [`SyncError`] raised by the underlying `sync_once`,
/// `prepare_merge`, or `commit_with_decisions` calls bubbles up
/// verbatim. The caller maps it via
/// [`crate::exit::ExitCode::from_sync_error`].
///
/// # State mutation contract
///
/// - [`RunOutcome::NothingToDo`] / [`RunOutcome::RollbackRejected`] —
///   `state` is unchanged byte-for-byte.
/// - [`RunOutcome::AppliedAutomatically`] — `state.highest_vector_clock_seen`
///   advances to the disk clock (the dominance case — disk strictly
///   ≥ local, so the disk clock alone is already the LUB).
/// - [`RunOutcome::SilentMerge`] / [`RunOutcome::MergedAndCommitted`] —
///   a merged manifest is written and `state` becomes its clock: the LUB
///   of the canonical disk clock, every conflict-copy clock and the
///   prior local-seen (see `commit_merge`). `SilentMerge` is the arm
///   where no block diverged, so only the manifest is rewritten (#730).
///
/// On `Err`, `state` may have been partially mutated only if the error
/// came from `commit_with_decisions` after state was updated — but
/// `commit_with_decisions` returns `Result<SyncState, SyncError>` and
/// the implementation only assigns to `*state` on `Ok`, so an error
/// path leaves the caller's previous state intact. Callers that
/// retry on transient `EvidenceStale` errors can safely re-invoke
/// `run_one` with the same `state` without re-loading from disk.
pub fn run_one(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &mut SyncState,
    veto_ux: &mut dyn VetoUx,
    now_ms: u64,
) -> Result<RunOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(RunOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(RunOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(evidence) => Ok(RunOutcome::RollbackRejected(evidence)),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash: _,
            disk_vector_clock: _,
            local_highest_seen: _,
        } => {
            // Concurrent clocks with no diverging block: nothing to
            // re-encrypt, but §10 still requires the merge to be written.
            if plan.diverging_blocks.is_empty() {
                commit_manifest_only_merge(vault_folder, identity, state, &bundle, &plan, now_ms)?;
                return Ok(RunOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            let vetoes_count = draft.vetoes.len();
            let decisions = veto_ux.decide(&draft.vetoes);
            commit_merge(vault_folder, identity, state, draft, decisions, now_ms)?;
            Ok(RunOutcome::MergedAndCommitted {
                vetoes_resolved: vetoes_count,
            })
        }
    }
}

/// Run one sync pass that auto-applies every safe arm and **pauses**
/// (commits nothing, advances no state) the instant a tombstone veto needs
/// human judgement. Unlike [`run_one`], it drives no [`crate::veto::VetoUx`]:
/// the `ConcurrentDetected` arm commits only when the prepared draft has an
/// empty veto set, and otherwise returns [`SyncPassOutcome::ConflictsPending`]
/// without writing.
///
/// State-mutation contract matches [`run_one`] on the shared arms; on the
/// `ConflictsPending` arm `state` is byte-identical and the vault unwritten.
///
/// # Errors
/// Any [`SyncError`] from the underlying `sync_once` / `prepare_merge` /
/// `commit_with_decisions` bubbles up verbatim.
pub fn sync_pass_pause_on_conflict(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &mut SyncState,
    now_ms: u64,
) -> Result<SyncPassOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(SyncPassOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(SyncPassOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(_evidence) => Ok(SyncPassOutcome::RollbackRejected),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash: _,
            disk_vector_clock: _,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                commit_manifest_only_merge(vault_folder, identity, state, &bundle, &plan, now_ms)?;
                return Ok(SyncPassOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            if !draft.vetoes.is_empty() {
                return Ok(SyncPassOutcome::ConflictsPending {
                    veto_count: draft.vetoes.len(),
                });
            }
            commit_merge(vault_folder, identity, state, draft, Vec::new(), now_ms)?;
            Ok(SyncPassOutcome::MergedClean)
        }
    }
}

/// Run one **stateless inspect** pass — the call-1 of the interactive
/// resolution flow. Structurally parallel to
/// [`sync_pass_pause_on_conflict`] on every arm except the conflict arm:
/// where the pause helper returns just a `veto_count`, this helper
/// returns the full draft detail (`vetoes` + `collisions` +
/// `manifest_hash`) the UI needs to render the resolution modal. It
/// commits nothing and advances no state on the conflict arm, and it
/// drives no [`crate::veto::VetoUx`].
///
/// State-mutation contract matches [`sync_pass_pause_on_conflict`] on the
/// shared arms (`AppliedAutomatically` / `SilentMerge` advance `state`,
/// `MergedClean` advances after a zero-veto commit); on the
/// `ConflictsPending` arm `state` is byte-identical and the vault
/// unwritten — the commit happens later in [`sync_pass_commit_decisions`]
/// re-checking `manifest_hash` for freshness.
///
/// # Errors
/// Any [`SyncError`] from the underlying `sync_once` / `prepare_merge` /
/// `commit_with_decisions` bubbles up verbatim.
pub fn sync_pass_inspect(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &mut SyncState,
    now_ms: u64,
) -> Result<InspectOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(InspectOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(InspectOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(_evidence) => Ok(InspectOutcome::RollbackRejected),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash: _,
            disk_vector_clock: _,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                commit_manifest_only_merge(vault_folder, identity, state, &bundle, &plan, now_ms)?;
                return Ok(InspectOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            if !draft.vetoes.is_empty() {
                // Read the detail BEFORE `draft` is consumed below. On the
                // no-veto branch `commit_with_decisions` takes `draft` by
                // value; here we clone the display detail and return it.
                return Ok(InspectOutcome::ConflictsPending {
                    vetoes: draft.vetoes.clone(),
                    collisions: draft.collisions.clone(),
                    manifest_hash: draft.manifest_hash.clone(),
                });
            }
            commit_merge(vault_folder, identity, state, draft, Vec::new(), now_ms)?;
            Ok(InspectOutcome::MergedClean)
        }
    }
}

/// Run one **stateless commit** pass — the call-2 of the interactive
/// resolution flow, the counterpart to [`sync_pass_inspect`]. The UI
/// first calls `sync_pass_inspect` (call-1) to obtain the veto set and a
/// `manifest_hash` freshness token, lets the operator adjudicate each
/// veto, then calls this function with those `decisions` and the token.
///
/// This helper is **stateless** in the same sense as its sibling: it
/// recomputes the merge draft from scratch via `sync_once` /
/// `prepare_merge` (call-1's draft is never carried across the
/// round-trip) and then re-validates freshness before writing.
///
/// # Freshness contract (TOCTOU gate)
/// On the `ConcurrentDetected` arm — the only arm a real resolution
/// round-trip reaches — the recomputed `manifest_hash` is compared
/// against `expected_manifest_hash` (the token call-1 handed the UI).
/// If a concurrent writer advanced the on-disk manifest between call-1
/// and call-2, the recomputed hash differs and this returns
/// [`SyncError::EvidenceStale`] **before** `prepare_merge` /
/// `commit_with_decisions` run — so a stale token never writes a byte.
/// (`commit_with_decisions` re-checks the hash internally as a second,
/// independent gate; this early check keeps the failure cheap and makes
/// the no-write guarantee hold even on the recompute path.)
///
/// **Scope of the gate — auto-advance arms discard the decisions.** The
/// token is only consulted on the diverging (`ConcurrentDetected` +
/// non-empty `diverging_blocks`) arm. If a concurrent writer races the
/// disk forward so that `sync_once` now re-classifies the state as a
/// non-diverging arm — `NothingToDo`, `AppliedAutomatically`, or
/// `SilentMerge` — this returns that arm directly and the caller's
/// `decisions` are **silently dropped** (the merge that produced the
/// veto no longer exists in the same shape). This is CRDT-correct. On
/// `NothingToDo` / `AppliedAutomatically` the disk's vector clock already
/// subsumes the local one, so adopting it is the right resolution
/// regardless of what the operator chose in the now-stale modal. On
/// `SilentMerge` the clocks are still concurrent but no block diverges, so
/// the arm writes a manifest-only merge (#730) and there is no veto left to
/// decide. Either way a `KeepLocal` choice can be overridden by an incoming
/// update that carries the tombstone. Nothing *incorrect* is written; the
/// modal's intent is simply moot. A caller that needs the operator's choice
/// to be authoritative must re-inspect and re-prompt.
///
/// # Decision coverage
/// `decisions` must exactly cover the **recomputed** veto set:
/// `commit_with_decisions` enforces a bijection between decision and
/// veto `record_id`s, failing with [`SyncError::MissingVetoDecision`] /
/// [`SyncError::UnknownVetoDecision`] otherwise. Because the draft is
/// recomputed, the freshness gate above is what guarantees the veto set
/// the caller adjudicated still matches the one being committed against.
///
/// # State mutation
/// Mirrors [`sync_pass_inspect`] on the shared arms
/// (`AppliedAutomatically` / `SilentMerge` advance `state`,
/// `MergedClean` advances after the decision-driven commit). On the
/// stale-token path nothing is written and `state` is left untouched.
///
/// # Errors
/// Returns [`SyncError::EvidenceStale`] if the freshness token no longer
/// matches the on-disk manifest. Any other [`SyncError`] from the
/// underlying `sync_once` / `prepare_merge` / `commit_with_decisions`
/// (including the veto-coverage errors above) bubbles up verbatim.
pub fn sync_pass_commit_decisions(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &mut SyncState,
    expected_manifest_hash: ManifestHash,
    decisions: Vec<VetoDecision>,
    now_ms: u64,
) -> Result<SyncPassOutcome, SyncError> {
    let outcome = sync_once(vault_folder, identity, state, now_ms)?;
    match outcome {
        SyncOutcome::NothingToDo => Ok(SyncPassOutcome::NothingToDo),
        SyncOutcome::AppliedAutomatically { new_state } => {
            *state = new_state;
            Ok(SyncPassOutcome::AppliedAutomatically)
        }
        SyncOutcome::RollbackRejected(_evidence) => Ok(SyncPassOutcome::RollbackRejected),
        SyncOutcome::ConcurrentDetected {
            bundle,
            plan,
            manifest_hash,
            disk_vector_clock: _,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                commit_manifest_only_merge(vault_folder, identity, state, &bundle, &plan, now_ms)?;
                return Ok(SyncPassOutcome::SilentMerge);
            }
            // Freshness gate FIRST: if a concurrent writer advanced the
            // manifest since call-1, reject before any write so a stale
            // token can never mutate the vault.
            if manifest_hash != expected_manifest_hash {
                return Err(SyncError::EvidenceStale);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            commit_merge(vault_folder, identity, state, draft, decisions, now_ms)?;
            Ok(SyncPassOutcome::MergedClean)
        }
    }
}

/// The `SilentMerge` arm: the clocks are concurrent but no block diverged.
/// There is nothing to re-encrypt, yet crypto-design §10 still requires a
/// concurrent clock to end in a written merge. Saving the LUB without writing
/// it left the saved clock strictly dominating the disk, so this device's next
/// pass, refresh and open were all refused as a rollback (#730). With no
/// diverging block the draft has no vetoes, so no decisions are needed.
fn commit_manifest_only_merge(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &mut SyncState,
    bundle: &VaultBundle,
    plan: &DiffPlan,
    now_ms: u64,
) -> Result<(), SyncError> {
    let draft = prepare_merge(vault_folder, identity, bundle, plan)?;
    commit_merge(vault_folder, identity, state, draft, Vec::new(), now_ms)
}

/// Commit `draft` and adopt the written clock as `state`.
///
/// The written manifest clock folds in `state`'s prior highest-seen clock as
/// well as the canonical and conflict-copy clocks `prepare_merge` folded. A
/// concurrent prior clock is ahead of the disk on some entry (a write the
/// cloud dropped, say); writing it keeps the saved clock equal to the disk
/// clock, so §10 neither forgets what this device has seen nor later reads
/// this device's own merge as a rollback. `state` is only assigned on `Ok`.
fn commit_merge(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &mut SyncState,
    mut draft: DraftMerge,
    decisions: Vec<VetoDecision>,
    now_ms: u64,
) -> Result<(), SyncError> {
    draft.post_merge_clock =
        fold_local_clock(&draft.post_merge_clock, &state.highest_vector_clock_seen);
    *state = commit_with_decisions(vault_folder, identity, draft, decisions, now_ms)?;
    Ok(())
}

/// The clock a merge writes: the merged peer clocks joined with this device's
/// prior highest-seen clock.
fn fold_local_clock(
    merged: &[VectorClockEntry],
    prior_local_seen: &[VectorClockEntry],
) -> Vec<VectorClockEntry> {
    merge_vector_clocks(merged, prior_local_seen)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vc(fill: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [fill; 16],
            counter,
        }
    }

    /// An entry only the prior local clock carries survives into the
    /// written clock; that is what keeps the saved clock from dominating
    /// the disk after the commit (#730).
    #[test]
    fn a_local_only_entry_reaches_the_written_clock() {
        let merged = vec![vc(0xAA, 5)];
        let prior = vec![vc(0xAA, 3), vc(0xDD, 9)];
        assert_eq!(
            fold_local_clock(&merged, &prior),
            vec![vc(0xAA, 5), vc(0xDD, 9)]
        );
    }

    /// Element-wise max: neither side's counter is taken wholesale.
    #[test]
    fn the_written_clock_is_the_element_wise_max() {
        let merged = vec![vc(0xAA, 1), vc(0xBB, 9)];
        let prior = vec![vc(0xAA, 5), vc(0xBB, 2)];
        assert_eq!(
            fold_local_clock(&merged, &prior),
            vec![vc(0xAA, 5), vc(0xBB, 9)]
        );
    }
}
