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
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncError, SyncOutcome, SyncState,
};
use secretary_core::unlock::UnlockedIdentity;

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
    /// level" fast path). `state` advanced to the bundled disk clock;
    /// no commit was issued.
    SilentMerge,
    /// Disk vector clock is strictly dominated by the local
    /// `highest_vector_clock_seen` (rollback per
    /// `docs/crypto-design.md` §10). `state` is NOT advanced — caller
    /// surfaces [`crate::exit::ExitCode::RollbackRejected`] and the
    /// next attempt sees the same disk state.
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
/// - [`RunOutcome::AppliedAutomatically`] / [`RunOutcome::SilentMerge`]
///   — `state.highest_vector_clock_seen` advances to the disk clock.
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
            // can advance the local clock to the bundled disk clock
            // without re-encrypting anything.
            if plan.diverging_blocks.is_empty() {
                state.highest_vector_clock_seen = disk_vector_clock;
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
