//! The pass body every sync entry point shares (#101): lockfile, state load,
//! the cli pass, persist on the advancing arms, and the error/outcome maps.
//! The password variants ([`crate::sync::orchestration`]) and the session
//! variants ([`crate::sync::session`]) differ only in where the core identity
//! comes from.

use std::path::{Path, PathBuf};

use secretary_cli::pipeline::{InspectOutcome, SyncPassOutcome};
use secretary_cli::state::{default_state_dir, load, save, LockfileGuard};
use secretary_core::sync::{ManifestHash, SyncError, SyncState, VetoDecision};

use crate::error::detail;
use crate::error::FfiVaultError;
use crate::sync::dto::{SyncOutcomeDto, VetoDecisionDto};
use crate::sync::status::map_state_error;

/// A pass that ran under the per-vault lockfile. The lock is held until this
/// value drops, so a caller can act on the outcome (e.g. refresh a session
/// handle) before another pass can start.
pub(crate) struct LockedPass<O> {
    pub(crate) outcome: O,
    /// The in-memory `SyncState` after the pass (persisted iff it advanced).
    pub(crate) state: SyncState,
    _guard: LockfileGuard,
}

/// Acquire the lockfile (held ⇒ `SyncInProgress`), load the state (missing
/// file ⇒ empty), run `pass`, and persist the state ONLY when
/// `advanced(&outcome)`. `pass` borrows the caller's core identity.
pub(crate) fn run_locked_pass<O>(
    state_dir: &Path,
    vault_uuid: [u8; 16],
    pass: impl FnOnce(&mut SyncState) -> Result<O, SyncError>,
    advanced: impl FnOnce(&O) -> bool,
) -> Result<LockedPass<O>, FfiVaultError> {
    let guard = LockfileGuard::acquire(state_dir, vault_uuid).map_err(map_state_error)?;
    let mut state = load(state_dir, vault_uuid).map_err(map_state_error)?;
    let outcome = pass(&mut state).map_err(map_sync_error)?;
    if advanced(&outcome) {
        save(state_dir, &state).map_err(map_state_error)?;
    }
    Ok(LockedPass {
        outcome,
        state,
        _guard: guard,
    })
}

/// Whether an inspect outcome advanced (and so persists) the state.
/// `NothingToDo` / `RollbackRejected` / `ConflictsPending` write nothing.
pub(crate) fn inspect_advanced(o: &InspectOutcome) -> bool {
    match o {
        InspectOutcome::AppliedAutomatically
        | InspectOutcome::SilentMerge
        | InspectOutcome::MergedClean => true,
        InspectOutcome::NothingToDo
        | InspectOutcome::RollbackRejected
        | InspectOutcome::ConflictsPending { .. } => false,
    }
}

/// Whether a commit outcome advanced (and so persists) the state.
pub(crate) fn commit_advanced(o: &SyncPassOutcome) -> bool {
    match o {
        SyncPassOutcome::AppliedAutomatically
        | SyncPassOutcome::SilentMerge
        | SyncPassOutcome::MergedClean => true,
        SyncPassOutcome::NothingToDo
        | SyncPassOutcome::RollbackRejected
        | SyncPassOutcome::ConflictsPending { .. } => false,
    }
}

/// The default state dir, or `SyncFailed` when the platform has none.
pub(crate) fn default_state_dir_or_err() -> Result<PathBuf, FfiVaultError> {
    default_state_dir().ok_or_else(|| FfiVaultError::SyncFailed {
        detail: detail::literal("no platform data directory available for the sync state cache"),
    })
}

/// Reconstruct the call-1 freshness token and convert each DTO decision. A
/// wrong-length token is a caller/UI bug (the bytes did not round-trip from
/// call-1's `ConflictsPending`), as is a malformed `record_uuid` hex; both
/// surface as `SyncFailed` rather than a panic.
pub(crate) fn parse_commit_args(
    decisions: &[VetoDecisionDto],
    manifest_hash: &[u8],
) -> Result<(ManifestHash, Vec<VetoDecision>), FfiVaultError> {
    let expected = ManifestHash(<[u8; 32]>::try_from(manifest_hash).map_err(|_| {
        FfiVaultError::SyncFailed {
            detail: detail::literal("manifest_hash must be 32 bytes"),
        }
    })?);
    let core_decisions = decisions
        .iter()
        .map(VetoDecisionDto::to_core)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((expected, core_decisions))
}

/// Map a commit outcome to its DTO. Explicit per arm (no `From` impl) so a
/// future arm cannot silently flow into the wrong DTO. The commit path can
/// never legitimately return `ConflictsPending` (committing decisions resolves
/// the vetoes); if it does, that is an internal-consistency violation,
/// surfaced as an `Err` rather than a silently-empty `ConflictsPending` DTO.
pub(crate) fn commit_outcome_to_dto(o: SyncPassOutcome) -> Result<SyncOutcomeDto, FfiVaultError> {
    Ok(match o {
        SyncPassOutcome::NothingToDo => SyncOutcomeDto::NothingToDo,
        SyncPassOutcome::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
        SyncPassOutcome::SilentMerge => SyncOutcomeDto::SilentMerge,
        SyncPassOutcome::MergedClean => SyncOutcomeDto::MergedClean,
        SyncPassOutcome::RollbackRejected => SyncOutcomeDto::RollbackRejected,
        SyncPassOutcome::ConflictsPending { .. } => {
            return Err(FfiVaultError::SyncFailed {
                detail: detail::literal("commit unexpectedly returned ConflictsPending"),
            })
        }
    })
}

/// Map `secretary_core::sync::SyncError` → `FfiVaultError`.
fn map_sync_error(e: SyncError) -> FfiVaultError {
    match e {
        SyncError::VaultUuidMismatch { .. } => FfiVaultError::SyncStateVaultMismatch,
        SyncError::StateDecodeFailed { .. } | SyncError::StateEncodeFailed { .. } => {
            FfiVaultError::SyncStateCorrupt {
                detail: detail::gated(&e),
            }
        }
        SyncError::EvidenceStale => FfiVaultError::SyncEvidenceStale,
        SyncError::Vault(ve) => ve.into(),
        // Decision-coverage failures on the commit path: the supplied
        // decisions did not bijectively cover the recomputed veto set (a UI
        // bug, or the on-disk veto set shifted under a stale token). Caller-
        // actionable — the desktop should re-run inspect and re-prompt — so
        // these get their own typed surface instead of folding to SyncFailed.
        SyncError::MissingVetoDecision { .. } | SyncError::UnknownVetoDecision { .. } => {
            FfiVaultError::SyncDecisionsIncomplete
        }
        // The remaining SyncError variants are internal-consistency guards the
        // caller cannot act on — they fold to the generic SyncFailed. Listed
        // EXHAUSTIVELY (no `_` catch-all) on purpose: when a future SyncError
        // variant is added, this match fails to compile, forcing a deliberate
        // triage decision (is the new variant caller-actionable → its own arm,
        // or another opaque guard → add it here) rather than silently folding
        // it to SyncFailed.
        SyncError::InvalidArgument { .. }
        | SyncError::ConflictCopyScanIoFailed { .. }
        | SyncError::EmptyDraftWithVetoes => FfiVaultError::SyncFailed {
            detail: detail::gated(&e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_sync_error_uncollapses_decision_errors() {
        // The un-collapse: MissingVetoDecision / UnknownVetoDecision now route
        // to their own typed surface instead of folding into SyncFailed.
        let missing = map_sync_error(SyncError::MissingVetoDecision {
            record_id: [0u8; 16],
        });
        assert!(
            matches!(missing, FfiVaultError::SyncDecisionsIncomplete),
            "got {missing:?}"
        );
        let unknown = map_sync_error(SyncError::UnknownVetoDecision {
            record_id: [1u8; 16],
        });
        assert!(
            matches!(unknown, FfiVaultError::SyncDecisionsIncomplete),
            "got {unknown:?}"
        );
        // A still-folded variant stays SyncFailed (pins the un-collapse didn't
        // accidentally widen the SyncDecisionsIncomplete bucket).
        let other = map_sync_error(SyncError::EmptyDraftWithVetoes);
        assert!(
            matches!(other, FfiVaultError::SyncFailed { .. }),
            "got {other:?}"
        );
    }
}
