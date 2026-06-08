//! `sync_vault` — one manual, inspect-based sync pass. Opens a core
//! identity from the re-prompted password, holds the per-vault lockfile, runs
//! `secretary_cli::pipeline::sync_pass_inspect`, persists `SyncState`
//! on the advancing arms, maps errors. The cli pass owns vault disk I/O; the
//! bridge owns identity lifetime + state persistence.

use std::path::Path;

use secretary_cli::pipeline::{
    sync_pass_commit_decisions, sync_pass_inspect, InspectOutcome, SyncPassOutcome,
};
use secretary_cli::state::{default_state_dir, load, save, LockfileGuard};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::{ManifestHash, SyncError};
use secretary_core::vault::Unlocker;

use crate::error::FfiVaultError;
use crate::sync::dto::{SyncOutcomeDto, VetoDecisionDto};
use crate::sync::status::map_state_error;

/// Run one manual sync pass against `vault_folder`, unlocking with `password`.
/// `now_ms` is the caller's wall-clock (Unix ms) — used as the merge timestamp
/// when the pass commits a clean concurrent merge (`MergedClean`); D.1.14 passes
/// real time. On advancing arms the new `SyncState` is persisted; on
/// `ConflictsPending`/`NothingToDo`/`RollbackRejected` nothing is written.
///
/// # Errors
/// - `SyncInProgress` — the per-vault lockfile is held.
/// - `WrongPasswordOrCorrupt` — `password` failed to unlock.
/// - `SyncStateVaultMismatch` / `SyncStateCorrupt` — local sync cache for another vault / corrupt.
/// - `SyncEvidenceStale` — concurrent writer mid-pass; retry.
/// - `SyncFailed` — any other sync error; vault unchanged.
pub fn sync_vault(
    vault_folder: &Path,
    password: SecretBytes,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let state_dir = default_state_dir().ok_or_else(|| FfiVaultError::SyncFailed {
        detail: "no platform data directory available for the sync state cache".into(),
    })?;
    sync_vault_in(&state_dir, vault_folder, password, now_ms)
}

/// Public explicit-`state_dir` seam — the API the uniffi/pyo3 bindings project
/// (mobile passes its sandbox path; tests pass a tempdir). The param-free
/// [`sync_vault`] is the desktop default-dir convenience wrapper. Mirrors
/// [`crate::sync::status::sync_status_in`].
pub fn sync_vault_in(
    state_dir: &Path,
    vault_folder: &Path,
    password: SecretBytes,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    // 1. Open the vault → owned core::UnlockedIdentity + vault_uuid. We keep
    //    the whole `core::vault::OpenVault` (`core_out`) alive for the pass so
    //    we can borrow `&core_out.identity_block_key`/`&core_out.identity` —
    //    rather than splitting into the two FFI handles. `open_vault` BORROWS
    //    `&password`, so we still own `password` afterwards and can pass `&`
    //    of it to the pass below. `?` on the `From<VaultError>` yields
    //    `WrongPasswordOrCorrupt` for a bad password.
    let core_out =
        secretary_core::vault::open_vault(vault_folder, Unlocker::Password(&password), None)?;
    let vault_uuid = core_out.manifest.vault_uuid;

    // Reconstruct the owned core `UnlockedIdentity` the pass requires. The two
    // secret fields move out of `core_out`; both remain ZeroizeOnDrop and are
    // wiped when `identity` drops at function end.
    // NOTE: if `UnlockedIdentity` gains a field this struct literal fails to
    // compile — fail-loud is correct; do NOT paper over it with `..Default::default()`.
    let identity = secretary_core::unlock::UnlockedIdentity {
        identity_block_key: core_out.identity_block_key,
        identity: core_out.identity,
    };

    // 2. Acquire the per-vault lockfile. A held lock maps (via map_state_error)
    //    to SyncInProgress.
    let _guard = LockfileGuard::acquire(state_dir, vault_uuid).map_err(map_state_error)?;

    // 3. Load the SyncState (missing file ⇒ empty state).
    let mut state = load(state_dir, vault_uuid).map_err(map_state_error)?;

    // 4. Run the inspect pass. It re-opens the vault commit-side, so
    //    it needs `&password` AND the by-ref identity.
    let outcome: InspectOutcome =
        sync_pass_inspect(vault_folder, &identity, &password, &mut state, now_ms)
            .map_err(map_sync_error)?;

    // 5. Persist ONLY on the advancing arms. NothingToDo / RollbackRejected /
    //    ConflictsPending leave `state` byte-identical and write nothing.
    match outcome {
        InspectOutcome::AppliedAutomatically
        | InspectOutcome::SilentMerge
        | InspectOutcome::MergedClean => {
            save(state_dir, &state).map_err(map_state_error)?;
        }
        InspectOutcome::NothingToDo
        | InspectOutcome::RollbackRejected
        | InspectOutcome::ConflictsPending { .. } => {}
    }

    Ok(outcome.into())
    // `identity` (owned core::UnlockedIdentity) + `password` (SecretBytes) drop
    // here → ZeroizeOnDrop wipes both. `_guard` drops → lockfile released.
}

/// Commit the caller's tombstone-veto `decisions` for a sync pass that paused on
/// `ConflictsPending` — the stateless **call-2** of the interactive resolution
/// flow. [`sync_vault`] is call-1: it inspects, surfaces the pending vetoes +
/// the `manifest_hash` freshness token, and writes nothing. The desktop renders
/// the resolution modal, collects one [`VetoDecisionDto`] per veto, then calls
/// this with those decisions plus the opaque `manifest_hash` from call-1.
///
/// `manifest_hash` is the 32-byte BLAKE3 token returned in
/// [`SyncOutcomeDto::ConflictsPending`]; it gates freshness. If the canonical
/// manifest changed on disk between call-1 and this call (another writer, or a
/// daemon merged first), the token no longer matches and the commit returns
/// [`FfiVaultError::SyncEvidenceStale`] without writing — the caller must
/// re-run [`sync_vault`] and re-prompt. `now_ms` is the caller's wall-clock
/// (Unix ms), used as the merge timestamp for the committed result.
///
/// On success the merged result is written to the vault and the advanced
/// `SyncState` is persisted; the returned [`SyncOutcomeDto`] is `MergedClean`
/// in the common case (or another clean arm if the disk state changed to a
/// non-diverging shape in the interim). This path never returns
/// `ConflictsPending` — committing decisions resolves the vetoes.
///
/// # Errors
/// - `SyncFailed` — `manifest_hash` is not exactly 32 bytes, or an internal
///   guard fired (e.g. the commit unexpectedly reported `ConflictsPending`).
/// - `SyncDecisionsIncomplete` — the supplied decisions did not bijectively
///   cover the recomputed veto set (a UI bug, or the on-disk veto set shifted).
/// - `SyncEvidenceStale` — the manifest changed on disk since call-1; retry.
/// - `SyncInProgress` — the per-vault lockfile is held.
/// - `WrongPasswordOrCorrupt` — `password` failed to unlock.
/// - `SyncStateVaultMismatch` / `SyncStateCorrupt` — local sync cache for
///   another vault / corrupt.
pub fn sync_commit_decisions(
    vault_folder: &Path,
    password: SecretBytes,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let state_dir = default_state_dir().ok_or_else(|| FfiVaultError::SyncFailed {
        detail: "no platform data directory available for the sync state cache".into(),
    })?;
    sync_commit_decisions_in(
        &state_dir,
        vault_folder,
        password,
        decisions,
        manifest_hash,
        now_ms,
    )
}

/// Public explicit-`state_dir` seam — the API the uniffi/pyo3 bindings project
/// (mobile passes its sandbox path; tests pass a tempdir). The param-free
/// [`sync_commit_decisions`] is the desktop default-dir convenience wrapper.
/// Mirrors [`sync_vault_in`].
pub fn sync_commit_decisions_in(
    state_dir: &Path,
    vault_folder: &Path,
    password: SecretBytes,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    // 1. Reconstruct the freshness token. A wrong length is a caller/UI bug
    //    (the bytes did not round-trip from call-1's ConflictsPending), not a
    //    data-integrity failure, so it surfaces as SyncFailed with a precise
    //    detail rather than a panic.
    let expected = ManifestHash(<[u8; 32]>::try_from(manifest_hash.as_slice()).map_err(|_| {
        FfiVaultError::SyncFailed {
            detail: "manifest_hash must be 32 bytes".into(),
        }
    })?);

    // 2. Convert each DTO decision to its core form. A malformed record_uuid
    //    hex surfaces as SyncFailed (see VetoDecisionDto::to_core).
    let core_decisions = decisions
        .iter()
        .map(VetoDecisionDto::to_core)
        .collect::<Result<Vec<_>, _>>()?;

    // 3. Open the vault → owned identity + vault_uuid (same as sync_vault_in).
    let core_out =
        secretary_core::vault::open_vault(vault_folder, Unlocker::Password(&password), None)?;
    let vault_uuid = core_out.manifest.vault_uuid;
    let identity = secretary_core::unlock::UnlockedIdentity {
        identity_block_key: core_out.identity_block_key,
        identity: core_out.identity,
    };

    // 4. Acquire the per-vault lockfile + load state.
    let _guard = LockfileGuard::acquire(state_dir, vault_uuid).map_err(map_state_error)?;
    let mut state = load(state_dir, vault_uuid).map_err(map_state_error)?;

    // 5. Run the commit pass. It re-opens the vault commit-side and re-verifies
    //    the freshness token, returning EvidenceStale if the disk moved.
    let outcome = sync_pass_commit_decisions(
        vault_folder,
        &identity,
        &password,
        &mut state,
        expected,
        core_decisions,
        now_ms,
    )
    .map_err(map_sync_error)?;

    // 6. Persist on the advancing arms, then map to the DTO. Save BEFORE
    //    building the dto, matching sync_vault_in's order.
    match outcome {
        SyncPassOutcome::AppliedAutomatically
        | SyncPassOutcome::SilentMerge
        | SyncPassOutcome::MergedClean => {
            save(state_dir, &state).map_err(map_state_error)?;
        }
        SyncPassOutcome::NothingToDo
        | SyncPassOutcome::RollbackRejected
        | SyncPassOutcome::ConflictsPending { .. } => {}
    }

    // The `From<SyncPassOutcome>` impl was deliberately removed in Task 4 — the
    // two callers (inspect / commit) map their own outcome enums explicitly so a
    // future arm cannot silently flow into the wrong DTO. The commit path can
    // never legitimately return ConflictsPending (committing decisions resolves
    // the vetoes); if it does, that's an internal-consistency violation, surfaced
    // as an Err rather than a silently-empty ConflictsPending DTO.
    let dto = match outcome {
        SyncPassOutcome::NothingToDo => SyncOutcomeDto::NothingToDo,
        SyncPassOutcome::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
        SyncPassOutcome::SilentMerge => SyncOutcomeDto::SilentMerge,
        SyncPassOutcome::MergedClean => SyncOutcomeDto::MergedClean,
        SyncPassOutcome::RollbackRejected => SyncOutcomeDto::RollbackRejected,
        SyncPassOutcome::ConflictsPending { .. } => {
            return Err(FfiVaultError::SyncFailed {
                detail: "commit unexpectedly returned ConflictsPending".into(),
            })
        }
    };
    Ok(dto)
    // `identity` + `password` drop here → ZeroizeOnDrop wipes both.
    // `_guard` drops → lockfile released.
}

/// Map `secretary_core::sync::SyncError` → `FfiVaultError`.
fn map_sync_error(e: SyncError) -> FfiVaultError {
    match e {
        SyncError::VaultUuidMismatch { .. } => FfiVaultError::SyncStateVaultMismatch,
        SyncError::StateDecodeFailed { .. } | SyncError::StateEncodeFailed { .. } => {
            FfiVaultError::SyncStateCorrupt {
                detail: e.to_string(),
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
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

    fn fixture_folder(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data")
            .join(name)
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir_recursive(&from, &to);
            } else {
                std::fs::copy(&from, &to).unwrap();
            }
        }
    }

    /// Stage a writable copy of golden_vault_001, returning the tempdir guard
    /// (keep it alive), the vault folder path, a fresh password `SecretBytes`,
    /// and the vault_uuid read from the manifest.
    fn stage_golden_writable_and_password() -> (TempDir, PathBuf, SecretBytes, [u8; 16]) {
        let src = fixture_folder("golden_vault_001");
        let tmp = tempfile::tempdir().expect("tempdir");
        copy_dir_recursive(&src, tmp.path());
        let vault_folder = tmp.path().to_path_buf();
        // open core-side once to read vault_uuid (not exposed via the bridge manifest
        // handle); the second SecretBytes is what the test hands to sync_vault_in.
        let pw = SecretBytes::new(VAULT_001_PASSWORD.to_vec());
        let core_out =
            secretary_core::vault::open_vault(&vault_folder, Unlocker::Password(&pw), None)
                .expect("open writable golden copy to read vault_uuid");
        let vault_uuid = core_out.manifest.vault_uuid;
        let password = SecretBytes::new(VAULT_001_PASSWORD.to_vec());
        (tmp, vault_folder, password, vault_uuid)
    }

    #[test]
    fn sync_vault_in_fast_forwards_fresh_state() {
        let (_vault_tmp, vault_folder, password, vault_uuid) = stage_golden_writable_and_password();
        let state_dir = TempDir::new().unwrap();
        let outcome = sync_vault_in(state_dir.path(), &vault_folder, password, 0)
            .expect("sync_vault must succeed on a fresh golden vault");
        assert_eq!(outcome, SyncOutcomeDto::AppliedAutomatically);
        // state advanced + persisted → status now reports has_state
        let status =
            crate::sync::status::sync_status_in(state_dir.path(), vault_uuid).expect("status");
        assert!(status.has_state);
        assert!(!status.device_clocks.is_empty());
    }

    #[test]
    fn sync_vault_in_reports_in_progress_when_lock_held() {
        let (_vault_tmp, vault_folder, password, vault_uuid) = stage_golden_writable_and_password();
        let state_dir = TempDir::new().unwrap();
        let _guard = secretary_cli::state::LockfileGuard::acquire(state_dir.path(), vault_uuid)
            .expect("acquire lock");
        let err = sync_vault_in(state_dir.path(), &vault_folder, password, 0).unwrap_err();
        assert!(matches!(err, FfiVaultError::SyncInProgress));
    }

    #[test]
    fn sync_vault_in_wrong_password_is_typed_error() {
        let (_vault_tmp, vault_folder, _password, _uuid) = stage_golden_writable_and_password();
        let state_dir = TempDir::new().unwrap();
        let mut wrong = VAULT_001_PASSWORD.to_vec();
        wrong[0] = wrong[0].wrapping_add(1);
        let err =
            sync_vault_in(state_dir.path(), &vault_folder, SecretBytes::new(wrong), 0).unwrap_err();
        assert!(
            matches!(err, FfiVaultError::WrongPasswordOrCorrupt),
            "got {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // Commit-path (call-2) bridge-glue tests.
    //
    // The end-to-end happy path (ConflictsPending → commit decisions →
    // MergedClean) and the stale-token rejection are covered at the cli
    // layer (`cli/tests/sync_pass_integration.rs::
    // commit_decisions_keep_local_keeps_record_live` /
    // `commit_decisions_stale_token_is_rejected`), which has the 89-line
    // two-device-veto fixture builder. Reproducing that fixture in the
    // bridge test would duplicate it wholesale for no extra coverage of the
    // bridge-specific glue. So here we pin only what the bridge owns and the
    // cli tests do NOT exercise: the 32-byte manifest_hash reconstruction
    // guard, the per-decision hex-parse guard, and the un-collapsed
    // decision-error mapping. All three fail-fast before vault open, so no
    // fixture is needed.
    // -------------------------------------------------------------------

    #[test]
    fn commit_decisions_bad_manifest_hash_length_is_sync_failed() {
        let (_vault_tmp, vault_folder, password, _uuid) = stage_golden_writable_and_password();
        let state_dir = TempDir::new().unwrap();
        // 5 bytes ≠ 32 → token reconstruction fails before the vault is opened.
        let err = sync_commit_decisions_in(
            state_dir.path(),
            &vault_folder,
            password,
            vec![],
            vec![0u8; 5],
            0,
        )
        .unwrap_err();
        let FfiVaultError::SyncFailed { detail } = err else {
            panic!("expected SyncFailed, got {err:?}");
        };
        assert!(
            detail.contains("manifest_hash must be 32 bytes"),
            "got detail {detail:?}"
        );
    }

    #[test]
    fn commit_decisions_malformed_decision_hex_is_sync_failed() {
        let (_vault_tmp, vault_folder, password, _uuid) = stage_golden_writable_and_password();
        let state_dir = TempDir::new().unwrap();
        // Valid 32-byte token, but a decision whose record_uuid_hex is not
        // valid hex → VetoDecisionDto::to_core fails before the vault is opened.
        let decisions = vec![VetoDecisionDto {
            record_uuid_hex: "not-hex".into(),
            keep_local: true,
        }];
        let err = sync_commit_decisions_in(
            state_dir.path(),
            &vault_folder,
            password,
            decisions,
            vec![0u8; 32],
            0,
        )
        .unwrap_err();
        assert!(
            matches!(err, FfiVaultError::SyncFailed { .. }),
            "expected SyncFailed, got {err:?}"
        );
    }

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
