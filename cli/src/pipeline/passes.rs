//! The four sync passes plus their shared clock-folding helpers.
//!
//! Each pass composes `sync_once → prepare_merge → commit_with_decisions`
//! and updates the caller-held [`SyncState`] in place; they differ only in
//! how they handle the `ConcurrentDetected` arm (auto-veto, pause, inspect,
//! commit). The outcome enums they return live in [`super::outcomes`].

use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, ManifestHash, SyncError, SyncOutcome,
    SyncState, VaultBundle, VetoDecision,
};
use secretary_core::unlock::UnlockedIdentity;
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::merge_vector_clocks;

use super::outcomes::{InspectOutcome, RunOutcome, SyncPassOutcome};
use crate::veto::VetoUx;

/// Run one sync attempt against `vault_folder` using `identity` for
/// reads, `password` for the commit-side re-open, and `state` as both
/// input ("what clock have we already seen?") and output (mutated in
/// place when the disk-side clock advances).
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
/// - [`RunOutcome::SilentMerge`] — `state.highest_vector_clock_seen`
///   advances to the LUB of the canonical disk clock, every
///   conflict-copy clock in the authenticated bundle, and the prior
///   local-seen. Mirrors what `commit_with_decisions` returns on the
///   [`RunOutcome::MergedAndCommitted`] arm (which folds canonical +
///   copies into `DraftMerge::post_merge_clock`); folding in the
///   prior local-seen is defensive — under monotone clock evolution
///   it's already dominated by the LUB, but the fold is cheap and
///   keeps the contract independent of that invariant.
/// - [`RunOutcome::MergedAndCommitted`] — `state` is replaced with the
///   `SyncState` returned by `commit_with_decisions` (the post-merge
///   clock that includes both local and peer contributions).
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
    password: &SecretBytes,
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
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            // Silent-merge fast path: the manifest clocks are concurrent
            // but no block-level divergence survived authentication. We
            // can advance the local clock without re-encrypting anything,
            // but we MUST advance it to the LUB of every clock visible at
            // this moment — not just the canonical disk clock. See
            // `silent_merge_clock` for the full rationale.
            if plan.diverging_blocks.is_empty() {
                let copy_clocks = gather_copy_clocks(&bundle);
                state.highest_vector_clock_seen = silent_merge_clock(
                    &disk_vector_clock,
                    &copy_clocks,
                    &state.highest_vector_clock_seen,
                );
                return Ok(RunOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            let vetoes_count = draft.vetoes.len();
            let decisions = veto_ux.decide(&draft.vetoes);
            let new_state =
                commit_with_decisions(vault_folder, password, draft, decisions, now_ms)?;
            *state = new_state;
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
    password: &SecretBytes,
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
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                let copy_clocks = gather_copy_clocks(&bundle);
                state.highest_vector_clock_seen = silent_merge_clock(
                    &disk_vector_clock,
                    &copy_clocks,
                    &state.highest_vector_clock_seen,
                );
                return Ok(SyncPassOutcome::SilentMerge);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            if !draft.vetoes.is_empty() {
                return Ok(SyncPassOutcome::ConflictsPending {
                    veto_count: draft.vetoes.len(),
                });
            }
            let new_state =
                commit_with_decisions(vault_folder, password, draft, Vec::new(), now_ms)?;
            *state = new_state;
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
    password: &SecretBytes,
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
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                let copy_clocks = gather_copy_clocks(&bundle);
                state.highest_vector_clock_seen = silent_merge_clock(
                    &disk_vector_clock,
                    &copy_clocks,
                    &state.highest_vector_clock_seen,
                );
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
            let new_state =
                commit_with_decisions(vault_folder, password, draft, Vec::new(), now_ms)?;
            *state = new_state;
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
/// veto no longer exists in the same shape). This is CRDT-correct: on
/// those arms the disk's vector clock has moved to a state that already
/// subsumes the local one, so adopting it is the right resolution
/// regardless of what the operator chose in the now-stale modal — but it
/// does mean a `KeepLocal` choice can be overridden by an incoming
/// dominating update that carries the tombstone. Nothing *incorrect* is
/// written; the modal's intent is simply moot. A caller that needs the
/// operator's choice to be authoritative must re-inspect and re-prompt.
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
    password: &SecretBytes,
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
            disk_vector_clock,
            local_highest_seen: _,
        } => {
            if plan.diverging_blocks.is_empty() {
                let copy_clocks = gather_copy_clocks(&bundle);
                state.highest_vector_clock_seen = silent_merge_clock(
                    &disk_vector_clock,
                    &copy_clocks,
                    &state.highest_vector_clock_seen,
                );
                return Ok(SyncPassOutcome::SilentMerge);
            }
            // Freshness gate FIRST: if a concurrent writer advanced the
            // manifest since call-1, reject before any write so a stale
            // token can never mutate the vault.
            if manifest_hash != expected_manifest_hash {
                return Err(SyncError::EvidenceStale);
            }
            let draft = prepare_merge(vault_folder, identity, &bundle, &plan)?;
            let new_state =
                commit_with_decisions(vault_folder, password, draft, decisions, now_ms)?;
            *state = new_state;
            Ok(SyncPassOutcome::MergedClean)
        }
    }
}

/// Borrow every conflict-copy manifest's `vector_clock` out of `bundle`
/// as a slice-of-slices, ready to feed [`silent_merge_clock`] as its
/// `copy_clocks` argument.
///
/// Each of the four sync passes reaches the silent-merge fast path with
/// the same need — fold every conflict copy's clock into the LUB — so the
/// gather lives here once rather than copy-pasted per pass. Pure: borrows
/// from `bundle` without allocating beyond the outer `Vec` of references.
fn gather_copy_clocks(bundle: &VaultBundle) -> Vec<&[VectorClockEntry]> {
    bundle
        .copies
        .iter()
        .map(|c| c.manifest.vector_clock.as_slice())
        .collect()
}

/// Compute the post-silent-merge `highest_vector_clock_seen` as the
/// LUB of:
///
/// 1. The authenticated canonical disk vector clock (`disk_clock`).
/// 2. Every conflict-copy manifest's `vector_clock` in `copy_clocks`.
/// 3. The prior `state.highest_vector_clock_seen` (`prior_local_seen`).
///
/// (1) + (2) mirrors what `commit_with_decisions` writes into
/// `DraftMerge::post_merge_clock` on the
/// [`RunOutcome::MergedAndCommitted`] arm — a conflict-copy's clock
/// may contain a (device, counter) pair that's strictly greater than
/// the canonical's, and a silent merge MUST preserve those.
///
/// (3) is defensive — `clock_relation(prior, disk) == Concurrent`
/// implies prior has some entry strictly greater than disk's only if
/// monotone-clock evolution is somehow violated (e.g. backup restore,
/// future-protocol bug). The fold is cheap and keeps this function's
/// correctness independent of that invariant.
///
/// Pure function — no I/O, no logging, no side effects. Takes raw
/// clock slices (rather than `&[ManifestSnapshot]`) so the
/// `silent_merge_clock_*` unit tests can pin the LUB contract
/// without constructing manifest fixtures.
fn silent_merge_clock(
    disk_clock: &[VectorClockEntry],
    copy_clocks: &[&[VectorClockEntry]],
    prior_local_seen: &[VectorClockEntry],
) -> Vec<VectorClockEntry> {
    let mut new_clock = disk_clock.to_vec();
    for copy in copy_clocks {
        new_clock = merge_vector_clocks(&new_clock, copy);
    }
    merge_vector_clocks(&new_clock, prior_local_seen)
}

#[cfg(test)]
mod tests {
    //! Pure LUB-contract tests for [`silent_merge_clock`]. End-to-end
    //! orchestration tests for the pass functions live in
    //! `cli/tests/pipeline_integration.rs` /
    //! `cli/tests/sync_pass_integration.rs` (they need a real
    //! `golden_vault_001`-backed on-disk vault the unit harness can't fake).

    use super::*;

    /// Build a `VectorClockEntry` from a fill byte + counter — keeps
    /// the LUB-helper tests' fixture lines compact and self-evident.
    fn vc(fill: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [fill; 16],
            counter,
        }
    }

    /// With no conflict copies and a prior local-seen that's already
    /// dominated by disk, the LUB is just the disk clock. This is the
    /// degenerate but most common silent-merge shape — concurrent
    /// solely because two devices' counters happened to advance, all
    /// of which the disk now reflects.
    #[test]
    fn silent_merge_clock_no_copies_disk_dominates() {
        let disk = vec![vc(0xAA, 5), vc(0xBB, 3)];
        let copies: Vec<&[VectorClockEntry]> = Vec::new();
        let prior = vec![vc(0xAA, 5), vc(0xBB, 3)];
        let result = silent_merge_clock(&disk, &copies, &prior);
        assert_eq!(result, vec![vc(0xAA, 5), vc(0xBB, 3)]);
    }

    /// A conflict-copy carrying a (device, counter) pair strictly
    /// greater than the canonical disk's MUST land in the LUB.
    /// This is the regression test for the bug fixed in this commit:
    /// the previous implementation set `state = disk_clock` only,
    /// silently dropping any counter that was only in a conflict copy.
    #[test]
    fn silent_merge_clock_folds_in_copy_with_higher_counter() {
        let disk = vec![vc(0xAA, 5)];
        let copy = vec![vc(0xAA, 7), vc(0xCC, 2)];
        let copies: Vec<&[VectorClockEntry]> = vec![copy.as_slice()];
        let prior: Vec<VectorClockEntry> = Vec::new();
        let result = silent_merge_clock(&disk, &copies, &prior);
        // 0xAA: max(5, 7) = 7. 0xCC: only-in-copy = 2.
        assert_eq!(result, vec![vc(0xAA, 7), vc(0xCC, 2)]);
    }

    /// A prior local-seen entry not present on disk or in any copy
    /// MUST survive the LUB fold. Defensive: under monotone clock
    /// evolution this is unreachable (disk-canonical only grows,
    /// state was previously observed from it), but the helper's
    /// contract is defined independent of that invariant — a backup
    /// restore or future-protocol bug shouldn't silently regress the
    /// local-seen clock.
    #[test]
    fn silent_merge_clock_folds_in_prior_local_seen() {
        let disk = vec![vc(0xAA, 5)];
        let copies: Vec<&[VectorClockEntry]> = Vec::new();
        let prior = vec![vc(0xAA, 5), vc(0xDD, 9)];
        let result = silent_merge_clock(&disk, &copies, &prior);
        // 0xAA: max(5, 5) = 5. 0xDD: only-in-prior = 9 — must survive.
        assert_eq!(result, vec![vc(0xAA, 5), vc(0xDD, 9)]);
    }

    /// Multiple copies, disk, and prior all contribute disjoint
    /// device entries — the LUB is the union with element-wise max.
    /// Sanity-check that the three-source fold composes correctly.
    #[test]
    fn silent_merge_clock_folds_disjoint_sources() {
        let disk = vec![vc(0xAA, 3)];
        let copy1 = vec![vc(0xBB, 4)];
        let copy2 = vec![vc(0xCC, 5)];
        let copies: Vec<&[VectorClockEntry]> = vec![copy1.as_slice(), copy2.as_slice()];
        let prior = vec![vc(0xDD, 6)];
        let result = silent_merge_clock(&disk, &copies, &prior);
        // All four sources contributed one disjoint device each.
        assert_eq!(
            result,
            vec![vc(0xAA, 3), vc(0xBB, 4), vc(0xCC, 5), vc(0xDD, 6)]
        );
    }

    /// Element-wise max across all three sources: every device's
    /// counter resolves to the max seen across disk + every copy +
    /// prior, not the value from any single source.
    #[test]
    fn silent_merge_clock_element_wise_max_across_sources() {
        let disk = vec![vc(0xAA, 1), vc(0xBB, 9)];
        let copy = vec![vc(0xAA, 5), vc(0xBB, 2)];
        let copies: Vec<&[VectorClockEntry]> = vec![copy.as_slice()];
        let prior = vec![vc(0xAA, 3), vc(0xBB, 4)];
        let result = silent_merge_clock(&disk, &copies, &prior);
        // 0xAA: max(1, 5, 3) = 5. 0xBB: max(9, 2, 4) = 9.
        assert_eq!(result, vec![vc(0xAA, 5), vc(0xBB, 9)]);
    }
}
