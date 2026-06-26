//! Outcome enums returned by the four sync passes in [`super::passes`].
//!
//! These are pure data types — no I/O, no crypto. [`RunOutcome`] is the
//! daemon/`once` entry-point result; [`SyncPassOutcome`] and
//! [`InspectOutcome`] are the auto-pause / interactive-resolution pass
//! results. They live apart from the pass functions so the orchestration
//! logic in [`super::passes`] reads as control flow, not type definitions.

use secretary_core::sync::draft::RecordCollisionSummary;
use secretary_core::sync::{ManifestHash, RecordTombstoneVeto, RollbackEvidence};

/// Outcome of one sync attempt. The caller logs the variant and maps
/// it to an [`crate::exit::ExitCode`] (in `once` mode) or continues the
/// daemon loop (in `run` mode).
///
/// `vetoes_resolved` on the merged-and-committed variant doubles as a
/// metric (how many record-level vetoes the operator's chosen
/// [`crate::veto::VetoUx`] adjudicated this pass). Zero means a concurrent
/// state was detected but every divergence merged cleanly without any veto
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
    /// next attempt sees the same disk state. Carries the
    /// [`RollbackEvidence`] (disk clock + local clock) so the daemon
    /// loop can log the attack indicator with forensic detail (#207).
    RollbackRejected(RollbackEvidence),
}

impl RunOutcome {
    /// `true` iff this outcome advanced `state.highest_vector_clock_seen`
    /// and therefore must be persisted before the next daemon iteration.
    /// Matches the C.2 spec §"State persistence" persist-list (extended
    /// to include `SilentMerge`, which post-dates the spec text but does
    /// advance the clock — see [`super::passes::run_one`]'s
    /// `# State mutation contract` doc section for the per-variant details).
    #[must_use]
    pub fn advanced_state(&self) -> bool {
        matches!(
            self,
            Self::AppliedAutomatically | Self::SilentMerge | Self::MergedAndCommitted { .. }
        )
    }
}

/// Outcome of one [`super::passes::sync_pass_pause_on_conflict`] pass. Mirrors
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

/// Outcome of one [`super::passes::sync_pass_inspect`] pass — the stateless
/// call-1 of the interactive resolution flow. Identical to [`SyncPassOutcome`]
/// on every arm except `ConflictsPending`, which carries the full draft detail
/// (vetoes + collision summaries + the manifest-hash freshness token) the UI
/// needs to render the resolution modal. Nothing is committed on this arm and
/// `state` is not advanced — the commit happens in
/// [`super::passes::sync_pass_commit_decisions`].
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

#[cfg(test)]
mod tests {
    //! Pure variant-level tests for the outcome enums (equality, `Debug`,
    //! `Clone`, `advanced_state`). End-to-end orchestration tests for the
    //! pass functions live in `cli/tests/pipeline_integration.rs` /
    //! `cli/tests/sync_pass_integration.rs` because they need a real
    //! `golden_vault_001`-backed on-disk vault that the unit-test harness
    //! can't easily fake (every `sync_once` call authenticates a signed
    //! manifest and AEAD-decrypts a body).

    use super::*;

    fn sample_evidence() -> RollbackEvidence {
        RollbackEvidence {
            disk_vector_clock: Vec::new(),
            local_highest_seen: Vec::new(),
        }
    }

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
        assert_eq!(
            RunOutcome::RollbackRejected(sample_evidence()),
            RunOutcome::RollbackRejected(sample_evidence())
        );
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
        assert_ne!(
            RunOutcome::SilentMerge,
            RunOutcome::RollbackRejected(sample_evidence())
        );
        assert_ne!(
            RunOutcome::NothingToDo,
            RunOutcome::RollbackRejected(sample_evidence())
        );
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
        assert!(
            format!("{:?}", RunOutcome::RollbackRejected(sample_evidence()))
                .contains("RollbackRejected")
        );
        let merged = RunOutcome::MergedAndCommitted { vetoes_resolved: 3 };
        let dbg = format!("{merged:?}");
        assert!(dbg.contains("MergedAndCommitted"));
        assert!(dbg.contains('3'));
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

    #[test]
    fn advanced_state_true_for_advancing_arms() {
        assert!(RunOutcome::AppliedAutomatically.advanced_state());
        assert!(RunOutcome::SilentMerge.advanced_state());
        assert!(RunOutcome::MergedAndCommitted { vetoes_resolved: 0 }.advanced_state());
        assert!(RunOutcome::MergedAndCommitted { vetoes_resolved: 5 }.advanced_state());
    }

    #[test]
    fn advanced_state_false_for_non_advancing_arms() {
        assert!(!RunOutcome::NothingToDo.advanced_state());
        assert!(!RunOutcome::RollbackRejected(sample_evidence()).advanced_state());
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
            RunOutcome::RollbackRejected(sample_evidence()),
            RunOutcome::MergedAndCommitted {
                vetoes_resolved: 42,
            },
        ];
        for outcome in &outcomes {
            assert_eq!(outcome, &outcome.clone());
        }
    }
}
