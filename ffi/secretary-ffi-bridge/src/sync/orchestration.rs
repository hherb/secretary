//! `sync_vault` — one manual, inspect-based sync pass. Opens a core
//! identity from the re-prompted password, then runs the shared
//! `run_locked_pass` (lockfile, state load, cli pass, persist on the
//! advancing arms) — the same body the session variants in
//! [`crate::sync::session`] run. The cli pass owns vault disk I/O; the bridge
//! owns identity lifetime + state persistence.

use std::path::Path;

use secretary_cli::pipeline::{sync_pass_commit_decisions, sync_pass_inspect};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::Unlocker;

use crate::error::FfiVaultError;
use crate::sync::dto::{SyncOutcomeDto, VetoDecisionDto};
use crate::sync::pass::{
    commit_advanced, commit_outcome_to_dto, default_state_dir_or_err, inspect_advanced,
    parse_commit_args, run_locked_pass,
};

/// Open `vault_folder` with `password` into an owned core identity plus its
/// `vault_uuid`. `?` on `VaultError` yields `WrongPasswordOrCorrupt` for a bad
/// password. Both secret fields move out of the `OpenVault` and stay
/// ZeroizeOnDrop.
fn open_identity(
    vault_folder: &Path,
    password: &SecretBytes,
) -> Result<(secretary_core::unlock::UnlockedIdentity, [u8; 16]), FfiVaultError> {
    let core_out =
        secretary_core::vault::open_vault(vault_folder, Unlocker::Password(password), None)?;
    let vault_uuid = core_out.manifest.vault_uuid;
    // NOTE: if `UnlockedIdentity` gains a field this struct literal fails to
    // compile — fail-loud is correct; do NOT paper over it with `..Default::default()`.
    let identity = secretary_core::unlock::UnlockedIdentity {
        identity_block_key: core_out.identity_block_key,
        identity: core_out.identity,
    };
    Ok((identity, vault_uuid))
}

/// Run one manual sync pass against `vault_folder`, unlocking with `password`.
/// `now_ms` is the caller's wall-clock (Unix ms) — used as the merge timestamp
/// when the pass commits a clean concurrent merge (`MergedClean`); D.1.14 passes
/// real time. `device_uuid` is this device's per-vault device UUID, the one
/// its writes pass: a merge ticks it on the merged block and manifest clocks
/// (crypto-design §10 / §11.2, #744). On advancing arms the new `SyncState` is
/// persisted; on
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
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let state_dir = default_state_dir_or_err()?;
    sync_vault_in(&state_dir, vault_folder, password, device_uuid, now_ms)
}

/// Public explicit-`state_dir` seam — the API the uniffi/pyo3 bindings project
/// (mobile passes its sandbox path; tests pass a tempdir). The param-free
/// [`sync_vault`] is the desktop default-dir convenience wrapper. Mirrors
/// [`crate::sync::status::sync_status_in`].
pub fn sync_vault_in(
    state_dir: &Path,
    vault_folder: &Path,
    password: SecretBytes,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let (identity, vault_uuid) = open_identity(vault_folder, &password)?;
    let locked = run_locked_pass(
        state_dir,
        vault_uuid,
        |state| sync_pass_inspect(vault_folder, &identity, state, device_uuid, now_ms),
        inspect_advanced,
    )?;
    Ok(locked.outcome.into())
    // `identity` + `password` drop here → ZeroizeOnDrop wipes both.
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
/// (Unix ms), used as the merge timestamp for the committed result, and
/// `device_uuid` is the merging device, as for [`sync_vault`].
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
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let state_dir = default_state_dir_or_err()?;
    sync_commit_decisions_in(
        &state_dir,
        vault_folder,
        password,
        decisions,
        manifest_hash,
        device_uuid,
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
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    // Both argument checks fail fast, before the vault is opened.
    let (expected, core_decisions) = parse_commit_args(&decisions, &manifest_hash)?;
    let (identity, vault_uuid) = open_identity(vault_folder, &password)?;
    let locked = run_locked_pass(
        state_dir,
        vault_uuid,
        |state| {
            sync_pass_commit_decisions(
                vault_folder,
                &identity,
                state,
                expected,
                core_decisions,
                device_uuid,
                now_ms,
            )
        },
        commit_advanced,
    )?;
    commit_outcome_to_dto(locked.outcome)
    // `identity` + `password` drop here → ZeroizeOnDrop wipes both.
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_cli::state::load;
    use std::path::PathBuf;
    use tempfile::TempDir;

    use secretary_test_utils::copy_dir_to_tempdir;

    use crate::test_support::{fixture_folder, TEST_DEVICE_UUID, VAULT_001_PASSWORD};

    /// Stage a writable copy of golden_vault_001, returning the tempdir guard
    /// (keep it alive), the vault folder path, a fresh password `SecretBytes`,
    /// and the vault_uuid read from the manifest.
    fn stage_golden_writable_and_password() -> (TempDir, PathBuf, SecretBytes, [u8; 16]) {
        let tmp = copy_dir_to_tempdir(&fixture_folder("golden_vault_001"));
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
        let outcome = sync_vault_in(
            state_dir.path(),
            &vault_folder,
            password,
            TEST_DEVICE_UUID,
            0,
        )
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
        let err = sync_vault_in(
            state_dir.path(),
            &vault_folder,
            password,
            TEST_DEVICE_UUID,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, FfiVaultError::SyncInProgress));
    }

    #[test]
    fn sync_vault_in_wrong_password_is_typed_error() {
        let (_vault_tmp, vault_folder, _password, _uuid) = stage_golden_writable_and_password();
        let state_dir = TempDir::new().unwrap();
        let mut wrong = VAULT_001_PASSWORD.to_vec();
        wrong[0] = wrong[0].wrapping_add(1);
        let err = sync_vault_in(
            state_dir.path(),
            &vault_folder,
            SecretBytes::new(wrong),
            TEST_DEVICE_UUID,
            0,
        )
        .unwrap_err();
        assert!(
            matches!(err, FfiVaultError::WrongPasswordOrCorrupt),
            "got {err:?}"
        );
    }

    /// Stage a writable copy of the committed `sync_collision_fixture` (#190):
    /// a two-device clean-collision divergence (`vault/`) plus a seeded
    /// Concurrent `SyncState` (`state/`). Returns both tempdir guards (keep
    /// alive), the vault folder, the state dir, a fresh password, the
    /// vault_uuid, and the divergent block's UUID — everything the
    /// `MergedClean` test needs to assert state advance + block rewrite.
    fn stage_collision_fixture_writable() -> (
        TempDir,
        TempDir,
        PathBuf,
        PathBuf,
        SecretBytes,
        [u8; 16],
        [u8; 16],
    ) {
        let src = fixture_folder("sync_collision_fixture");
        let vault_tmp = copy_dir_to_tempdir(&src.join("vault"));
        let state_tmp = copy_dir_to_tempdir(&src.join("state"));
        let vault_folder = vault_tmp.path().to_path_buf();
        let state_dir = state_tmp.path().to_path_buf();

        let pw = SecretBytes::new(VAULT_001_PASSWORD.to_vec());
        let core_out =
            secretary_core::vault::open_vault(&vault_folder, Unlocker::Password(&pw), None)
                .expect("open collision fixture to read vault_uuid + block_uuid");
        let vault_uuid = core_out.manifest.vault_uuid;
        // The collision fixture stages divergence on the single golden_vault_001
        // block, so `blocks[0]` IS unambiguously the divergent block. Pin that
        // invariant: if the fixture ever grows a second block where only a
        // non-first block diverges, the post-merge `block_after != block_before`
        // assertion would read an unchanged block and pass vacuously. Fail loudly
        // here instead.
        assert_eq!(
            core_out.manifest.blocks.len(),
            1,
            "collision fixture must have exactly one block so blocks[0] is the divergent block"
        );
        let block_uuid = core_out
            .manifest
            .blocks
            .first()
            .expect("collision fixture has >=1 block")
            .block_uuid;
        drop(core_out);

        let password = SecretBytes::new(VAULT_001_PASSWORD.to_vec());
        (
            vault_tmp,
            state_tmp,
            vault_folder,
            state_dir,
            password,
            vault_uuid,
            block_uuid,
        )
    }

    /// #190: the bridge `sync_vault_in` dispatch into a CLEAN concurrent merge
    /// (`MergedClean`) while the per-vault lockfile is held — the only seam the
    /// existing bridge tests (`AppliedAutomatically` / lock-held / wrong-pw) do
    /// not exercise. Asserts the three observable effects: the outcome is
    /// `MergedClean`, the persisted `SyncState` advanced (clock changed), and
    /// the merged block was rewritten on disk.
    ///
    /// The fixture is the committed `sync_collision_fixture` — both devices
    /// keep the record live and edit the same field, so the merge resolves
    /// with zero tombstone vetoes (→ MergedClean, not ConflictsPending). The
    /// underlying merge correctness is proven at the cli/core layer
    /// (`prepare_merge_populates_collisions_on_concurrent_field_edit`, #192);
    /// here we pin only the bridge glue.
    #[test]
    fn sync_vault_in_clean_concurrent_merge_commits_and_advances() {
        let (_vault_tmp, _state_tmp, vault_folder, state_dir, password, vault_uuid, block_uuid) =
            stage_collision_fixture_writable();

        let block_path = vault_folder.join("blocks").join(format!(
            "{}.cbor.enc",
            secretary_core::vault::format_uuid_hyphenated(&block_uuid)
        ));
        let block_before = std::fs::read(&block_path).expect("read canonical block pre-merge");
        let state_before = load(&state_dir, vault_uuid).expect("seeded state must load");

        let outcome = sync_vault_in(&state_dir, &vault_folder, password, TEST_DEVICE_UUID, 1)
            .expect("sync_vault_in on a clean-collision fixture must succeed");
        assert_eq!(outcome, SyncOutcomeDto::MergedClean, "got {outcome:?}");

        // State advanced + persisted: the merge folds the canonical + sibling
        // clocks into a strictly greater LUB. (Asserting the clock *changed*
        // is stronger than has_state here, since the fixture seeds a state file
        // before the pass runs.)
        let state_after = load(&state_dir, vault_uuid).expect("advanced state must persist");
        assert_ne!(
            state_after.highest_vector_clock_seen, state_before.highest_vector_clock_seen,
            "MergedClean must advance + persist the sync clock"
        );
        let status = crate::sync::status::sync_status_in(&state_dir, vault_uuid).expect("status");
        assert!(status.has_state);

        // The merged block was rewritten (re-encrypted with the merged record).
        let block_after = std::fs::read(&block_path).expect("read canonical block post-merge");
        assert_ne!(
            block_after, block_before,
            "MergedClean must rewrite the merged block on disk"
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
            TEST_DEVICE_UUID,
            0,
        )
        .unwrap_err();
        let FfiVaultError::SyncFailed { detail } = err else {
            panic!("expected SyncFailed, got {err:?}");
        };
        assert!(
            detail.as_str().contains("manifest_hash must be 32 bytes"),
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
            TEST_DEVICE_UUID,
            0,
        )
        .unwrap_err();
        assert!(
            matches!(err, FfiVaultError::SyncFailed { .. }),
            "expected SyncFailed, got {err:?}"
        );
    }
}
