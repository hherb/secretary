//! One sync attempt — composes
//! `sync_once → prepare_merge → veto UX → commit_with_decisions` and
//! updates the caller-held [`SyncState`] in place.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Module layout" + §"Daemon loop sketch".
//!
//! The [`run_one`] entry point is the single seam consumed by both
//! `once` (one attempt then exit) and `run` (daemon loop) subcommands.
//! It is intentionally pure-orchestration: every disk read/write and
//! every cryptographic step happens inside the `core::sync` primitives
//! it dispatches to. The local side effects are limited to:
//!
//! - Mutating `state` in place when the disk-side clock moves forward
//!   (`AppliedAutomatically`, `SilentMerge`, `MergedAndCommitted`).
//! - Driving the caller-supplied [`VetoUx`] on the
//!   `ConcurrentDetected` arm.
//!
//! `RollbackRejected` deliberately does NOT advance state — `state`
//! survives byte-for-byte so the caller can persist the same value
//! after dispatching the [`RunOutcome::RollbackRejected`] exit code.

use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::draft::RecordCollisionSummary;
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, ManifestHash, RecordTombstoneVeto, SyncError,
    SyncOutcome, SyncState, VetoDecision,
};
use secretary_core::unlock::UnlockedIdentity;
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::merge_vector_clocks;

use crate::veto::VetoUx;

/// Outcome of one sync attempt. The caller logs the variant and maps
/// it to an [`crate::exit::ExitCode`] (in `once` mode) or continues the
/// daemon loop (in `run` mode).
///
/// `vetoes_resolved` on the merged-and-committed variant doubles as a
/// metric (how many record-level vetoes the operator's chosen
/// [`VetoUx`] adjudicated this pass). Zero means a concurrent state
/// was detected but every divergence merged cleanly without any veto
/// candidates — distinct from [`Self::SilentMerge`], where the diff
/// plan itself was empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Disk vector clock equals the local `highest_vector_clock_seen`.
    /// No state mutation.
    NothingToDo,
    /// Disk strictly dominates the local `highest_vector_clock_seen`.
    /// `state` advanced to match.
    AppliedAutomatically,
    /// Concurrent state was detected and the diff plan was non-empty:
    /// `prepare_merge` produced a draft, the veto UX adjudicated any
    /// tombstone disputes, and `commit_with_decisions` wrote the
    /// merged result. `state` advanced to the post-merge clock.
    /// `vetoes_resolved` reports the number of record-level vetoes the
    /// UX handled (zero is valid — happens when the concurrent
    /// divergence was all field-level merges with no tombstone fights).
    MergedAndCommitted {
        /// Number of [`secretary_core::sync::RecordTombstoneVeto`]
        /// entries the veto UX adjudicated. Zero ⇒ silent record merge
        /// (still a real commit, just no operator decisions surfaced).
        vetoes_resolved: usize,
    },
    /// Concurrent state was detected but the diff plan was empty
    /// (no diverging blocks after authentication; this is the
    /// "concurrent at the manifest level, identical at the block
    /// level" fast path). `state.highest_vector_clock_seen` advanced
    /// to the LUB of the canonical disk clock, every conflict-copy
    /// clock in the bundle, and the prior local-seen — mirroring
    /// what `commit_with_decisions` returns on the
    /// [`Self::MergedAndCommitted`] arm via
    /// [`secretary_core::sync::DraftMerge::post_merge_clock`]. No
    /// commit was issued.
    SilentMerge,
    /// Disk vector clock is strictly dominated by the local
    /// `highest_vector_clock_seen` (rollback per
    /// `docs/crypto-design.md` §10). `state` is NOT advanced — caller
    /// surfaces [`crate::exit::ExitCode::RollbackRejected`] and the
    /// next attempt sees the same disk state.
    RollbackRejected,
}

/// Outcome of one [`sync_pass_pause_on_conflict`] pass. Mirrors
/// [`RunOutcome`] for the safe arms, but replaces the always-commit
/// `MergedAndCommitted` with two outcomes: [`Self::MergedClean`] (a
/// concurrent state that merged with zero tombstone vetoes, committed) and
/// [`Self::ConflictsPending`] (a concurrent state whose merge raised
/// tombstone vetoes — **not** committed; the caller surfaces the count and
/// defers to interactive resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPassOutcome {
    /// Disk clock == local highest-seen. No state mutation, no write.
    NothingToDo,
    /// Disk strictly dominates local. `state` advanced; no vault write.
    AppliedAutomatically,
    /// Concurrent, `diverging_blocks` empty → silent-merge clock advance.
    /// `state` advanced; no vault write.
    SilentMerge,
    /// Concurrent, `diverging_blocks` non-empty, **zero** vetoes →
    /// `commit_with_decisions(.., [])` wrote the merged result. `state` advanced.
    MergedClean,
    /// Concurrent, `diverging_blocks` non-empty, **non-empty** vetoes →
    /// nothing committed, `state` NOT advanced. `veto_count` is the number of
    /// tombstone disputes awaiting a human decision.
    ConflictsPending { veto_count: usize },
    /// Disk clock strictly dominated by local (rollback). `state` unchanged.
    RollbackRejected,
}

/// Outcome of one [`sync_pass_inspect`] pass — the stateless call-1 of the
/// interactive resolution flow. Identical to [`SyncPassOutcome`] on every arm
/// except `ConflictsPending`, which carries the full draft detail (vetoes +
/// collision summaries + the manifest-hash freshness token) the UI needs to
/// render the resolution modal. Nothing is committed on this arm and `state`
/// is not advanced — the commit happens in `sync_pass_commit_decisions` (Task 3).
#[derive(Debug, Clone, PartialEq)]
pub enum InspectOutcome {
    /// Disk clock == local highest-seen. No state mutation, no write.
    NothingToDo,
    /// Disk strictly dominates local. `state` advanced; no vault write.
    AppliedAutomatically,
    /// Concurrent, `diverging_blocks` empty -> silent-merge clock advance.
    /// `state` advanced; no vault write.
    SilentMerge,
    /// Concurrent, `diverging_blocks` non-empty, **zero** vetoes ->
    /// `commit_with_decisions(.., [])` wrote the merged result. `state` advanced.
    MergedClean,
    /// Concurrent, `diverging_blocks` non-empty, **non-empty** vetoes ->
    /// nothing committed, `state` NOT advanced. Carries the full draft
    /// detail the UI needs to render the resolution modal.
    ConflictsPending {
        /// Tombstone disputes awaiting a human decision.
        ///
        /// **Secret hygiene.** Each [`RecordTombstoneVeto`] carries
        /// `local_state: Record` — the AEAD-decrypted canonical record,
        /// i.e. plaintext secret material. It is wiped on drop by
        /// `RecordTombstoneVeto`'s own `ZeroizeOnDrop` (firing whenever this
        /// `Vec` drops), and the secret field *values* redact under `Debug`
        /// (`SecretString`/`SecretBytes` print `<redacted>`), so only
        /// metadata is loggable. `InspectOutcome` is deliberately NOT
        /// `ZeroizeOnDrop` itself — that would forbid the bridge from moving
        /// these fields out when projecting to its DTO. Consumers MUST NOT
        /// cache, stash, or widen the lifetime of this `Vec` beyond the
        /// resolution flow.
        vetoes: Vec<RecordTombstoneVeto>,
        /// Metadata-only field-level LWW collisions surfaced for display.
        collisions: Vec<RecordCollisionSummary>,
        /// Freshness token (TOCTOU anchor) the commit step re-checks.
        manifest_hash: ManifestHash,
    },
    /// Disk clock strictly dominated by local (rollback). `state` unchanged.
    RollbackRejected,
}

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
        SyncOutcome::RollbackRejected(_evidence) => Ok(RunOutcome::RollbackRejected),
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
                let copy_clocks: Vec<&[VectorClockEntry]> = bundle
                    .copies
                    .iter()
                    .map(|c| c.manifest.vector_clock.as_slice())
                    .collect();
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
                let copy_clocks: Vec<&[VectorClockEntry]> = bundle
                    .copies
                    .iter()
                    .map(|c| c.manifest.vector_clock.as_slice())
                    .collect();
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
/// unwritten — the commit happens later in `sync_pass_commit_decisions`
/// (Task 3) re-checking `manifest_hash` for freshness.
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
                let copy_clocks: Vec<&[VectorClockEntry]> = bundle
                    .copies
                    .iter()
                    .map(|c| c.manifest.vector_clock.as_slice())
                    .collect();
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
                let copy_clocks: Vec<&[VectorClockEntry]> = bundle
                    .copies
                    .iter()
                    .map(|c| c.manifest.vector_clock.as_slice())
                    .collect();
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
    //! Pure variant-level tests for [`RunOutcome`]. End-to-end
    //! orchestration tests for [`run_one`] live in
    //! [`cli/tests/pipeline_integration.rs`] because they need a real
    //! `golden_vault_001`-backed on-disk vault that the unit test
    //! harness can't easily fake (every `sync_once` call authenticates
    //! a signed manifest and AEAD-decrypts a body).

    use super::*;

    /// Identical variants compare equal via the derived [`Eq`] impl.
    #[test]
    fn nothing_to_do_is_self_equal() {
        assert_eq!(RunOutcome::NothingToDo, RunOutcome::NothingToDo);
    }

    /// Identical `AppliedAutomatically` values compare equal.
    #[test]
    fn applied_automatically_is_self_equal() {
        assert_eq!(
            RunOutcome::AppliedAutomatically,
            RunOutcome::AppliedAutomatically
        );
    }

    /// Identical `SilentMerge` values compare equal.
    #[test]
    fn silent_merge_is_self_equal() {
        assert_eq!(RunOutcome::SilentMerge, RunOutcome::SilentMerge);
    }

    /// Identical `RollbackRejected` values compare equal.
    #[test]
    fn rollback_rejected_is_self_equal() {
        assert_eq!(RunOutcome::RollbackRejected, RunOutcome::RollbackRejected);
    }

    /// Two `MergedAndCommitted` with the same `vetoes_resolved` count
    /// compare equal — the variant's discriminant + payload is the
    /// equality contract callers see.
    #[test]
    fn merged_and_committed_eq_when_counts_match() {
        assert_eq!(
            RunOutcome::MergedAndCommitted { vetoes_resolved: 0 },
            RunOutcome::MergedAndCommitted { vetoes_resolved: 0 }
        );
        assert_eq!(
            RunOutcome::MergedAndCommitted { vetoes_resolved: 7 },
            RunOutcome::MergedAndCommitted { vetoes_resolved: 7 }
        );
    }

    /// Two `MergedAndCommitted` with DIFFERENT veto counts must NOT
    /// compare equal. Pins the discriminant payload as part of the
    /// equality contract — a future refactor that boxed the count into
    /// a struct would break this test rather than silently collapsing
    /// distinct outcomes.
    #[test]
    fn merged_and_committed_ne_when_counts_differ() {
        assert_ne!(
            RunOutcome::MergedAndCommitted { vetoes_resolved: 0 },
            RunOutcome::MergedAndCommitted { vetoes_resolved: 1 }
        );
        assert_ne!(
            RunOutcome::MergedAndCommitted { vetoes_resolved: 1 },
            RunOutcome::MergedAndCommitted { vetoes_resolved: 2 }
        );
    }

    /// Distinct variants compare not-equal. Sanity check that the
    /// derived `PartialEq` discriminates on variant, not just payload.
    #[test]
    fn distinct_variants_are_not_equal() {
        assert_ne!(RunOutcome::NothingToDo, RunOutcome::AppliedAutomatically);
        assert_ne!(RunOutcome::AppliedAutomatically, RunOutcome::SilentMerge);
        assert_ne!(RunOutcome::SilentMerge, RunOutcome::RollbackRejected);
        assert_ne!(RunOutcome::NothingToDo, RunOutcome::RollbackRejected);
        assert_ne!(
            RunOutcome::AppliedAutomatically,
            RunOutcome::MergedAndCommitted { vetoes_resolved: 0 }
        );
        assert_ne!(
            RunOutcome::SilentMerge,
            RunOutcome::MergedAndCommitted { vetoes_resolved: 0 }
        );
    }

    /// `Debug` is available on every variant (rules out a future
    /// refactor that removed the derive). The exact format isn't part
    /// of the contract, but we sanity-check that the variant name is
    /// present in the rendered output — that's what an operator-facing
    /// log line would surface.
    #[test]
    fn debug_format_includes_variant_name() {
        assert!(format!("{:?}", RunOutcome::NothingToDo).contains("NothingToDo"));
        assert!(format!("{:?}", RunOutcome::AppliedAutomatically).contains("AppliedAutomatically"));
        assert!(format!("{:?}", RunOutcome::SilentMerge).contains("SilentMerge"));
        assert!(format!("{:?}", RunOutcome::RollbackRejected).contains("RollbackRejected"));
        let merged = RunOutcome::MergedAndCommitted { vetoes_resolved: 3 };
        let dbg = format!("{merged:?}");
        assert!(dbg.contains("MergedAndCommitted"));
        assert!(dbg.contains('3'));
    }

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

    #[test]
    fn sync_pass_outcome_variants_are_self_equal() {
        assert_eq!(SyncPassOutcome::NothingToDo, SyncPassOutcome::NothingToDo);
        assert_eq!(
            SyncPassOutcome::AppliedAutomatically,
            SyncPassOutcome::AppliedAutomatically
        );
        assert_eq!(SyncPassOutcome::SilentMerge, SyncPassOutcome::SilentMerge);
        assert_eq!(SyncPassOutcome::MergedClean, SyncPassOutcome::MergedClean);
        assert_eq!(
            SyncPassOutcome::RollbackRejected,
            SyncPassOutcome::RollbackRejected
        );
        assert_eq!(
            SyncPassOutcome::ConflictsPending { veto_count: 3 },
            SyncPassOutcome::ConflictsPending { veto_count: 3 }
        );
    }
    #[test]
    fn sync_pass_outcome_conflicts_pending_discriminates_on_count() {
        assert_ne!(
            SyncPassOutcome::ConflictsPending { veto_count: 1 },
            SyncPassOutcome::ConflictsPending { veto_count: 2 }
        );
    }
    #[test]
    fn sync_pass_outcome_debug_includes_variant_name() {
        assert!(format!("{:?}", SyncPassOutcome::SilentMerge).contains("SilentMerge"));
        let c = SyncPassOutcome::ConflictsPending { veto_count: 7 };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ConflictsPending"));
        assert!(dbg.contains('7'));
    }

    /// `Clone` round-trip preserves variant + payload. Pins the
    /// derived impl in place — callers in the daemon loop will clone
    /// outcomes for logging while continuing to dispatch on the
    /// original.
    #[test]
    fn clone_preserves_variant_and_payload() {
        let outcomes = [
            RunOutcome::NothingToDo,
            RunOutcome::AppliedAutomatically,
            RunOutcome::SilentMerge,
            RunOutcome::RollbackRejected,
            RunOutcome::MergedAndCommitted {
                vetoes_resolved: 42,
            },
        ];
        for outcome in &outcomes {
            assert_eq!(outcome, &outcome.clone());
        }
    }
}
