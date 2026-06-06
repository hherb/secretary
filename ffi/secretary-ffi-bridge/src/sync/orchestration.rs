//! `sync_vault` — one manual, pause-on-conflict sync pass. Opens a core
//! identity from the re-prompted password, holds the per-vault lockfile, runs
//! `secretary_cli::pipeline::sync_pass_pause_on_conflict`, persists `SyncState`
//! on the advancing arms, maps errors. The cli pass owns vault disk I/O; the
//! bridge owns identity lifetime + state persistence.

use std::path::Path;

use secretary_cli::pipeline::{sync_pass_pause_on_conflict, SyncPassOutcome};
use secretary_cli::state::{default_state_dir, load, save, LockfileGuard};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncError;
use secretary_core::vault::Unlocker;

use crate::error::FfiVaultError;
use crate::sync::status::map_state_error;

/// Result of one [`sync_vault`] pass. Mirrors `SyncPassOutcome` as a bridge DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcomeDto {
    /// No remote state to ingest; vault and state unchanged.
    NothingToDo,
    /// A fast-forward / single-writer advance was applied; state persisted.
    AppliedAutomatically,
    /// Concurrent but non-diverging copies merged silently; state persisted.
    SilentMerge,
    /// Concurrent diverging copies merged cleanly with no vetoes; state persisted.
    MergedClean,
    /// Concurrent diverging copies produced tombstone vetoes — the pass paused.
    /// Nothing was written to the vault or the state cache.
    ConflictsPending {
        /// Number of records whose tombstone resolution needs a human decision.
        veto_count: u32,
    },
    /// A would-be rollback was rejected; vault and state unchanged.
    RollbackRejected,
}

impl From<SyncPassOutcome> for SyncOutcomeDto {
    fn from(o: SyncPassOutcome) -> Self {
        match o {
            SyncPassOutcome::NothingToDo => SyncOutcomeDto::NothingToDo,
            SyncPassOutcome::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
            SyncPassOutcome::SilentMerge => SyncOutcomeDto::SilentMerge,
            SyncPassOutcome::MergedClean => SyncOutcomeDto::MergedClean,
            SyncPassOutcome::ConflictsPending { veto_count } => SyncOutcomeDto::ConflictsPending {
                veto_count: veto_count as u32,
            },
            SyncPassOutcome::RollbackRejected => SyncOutcomeDto::RollbackRejected,
        }
    }
}

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

/// Crate-internal seam taking an explicit state dir — used by the unit tests
/// and by [`sync_vault`]. Mirrors `sync::status::sync_status_in`.
pub(crate) fn sync_vault_in(
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

    // 4. Run the pause-on-conflict pass. It re-opens the vault commit-side, so
    //    it needs `&password` AND the by-ref identity.
    let outcome =
        sync_pass_pause_on_conflict(vault_folder, &identity, &password, &mut state, now_ms)
            .map_err(map_sync_error)?;

    // 5. Persist ONLY on the advancing arms. NothingToDo / RollbackRejected /
    //    ConflictsPending leave `state` byte-identical and write nothing.
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

    Ok(outcome.into())
    // `identity` (owned core::UnlockedIdentity) + `password` (SecretBytes) drop
    // here → ZeroizeOnDrop wipes both. `_guard` drops → lockfile released.
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
        // The remaining SyncError variants are internal-consistency guards the
        // caller cannot act on — they fold to the generic SyncFailed. Listed
        // EXHAUSTIVELY (no `_` catch-all) on purpose: when a future SyncError
        // variant is added, this match fails to compile, forcing a deliberate
        // triage decision (is the new variant caller-actionable → its own arm,
        // or another opaque guard → add it here) rather than silently folding
        // it to SyncFailed.
        SyncError::InvalidArgument { .. }
        | SyncError::ConflictCopyScanIoFailed { .. }
        | SyncError::UnknownVetoDecision { .. }
        | SyncError::MissingVetoDecision { .. }
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
}
