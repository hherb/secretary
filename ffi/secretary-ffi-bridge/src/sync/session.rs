//! Sync through an open session, and refresh the session from disk (#101,
//! design spec §5.3).
//!
//! The session variants run the same locked pass as the password variants in
//! [`crate::sync::orchestration`], borrowing the session's core identity
//! instead of unlocking a new one. On a pass that leaves the disk in a state
//! this device accepts, they then re-verify the disk and adopt it into the
//! manifest handle, so the session's next write is not refused with
//! [`FfiVaultError::VaultChangedOnDisk`].
//!
//! # Lock order
//!
//! The manifest handle's lock is taken briefly to read the folder and
//! `vault_uuid`, and released. The identity handle's lock is then held across
//! the pass and the re-verify, with no other handle lock taken inside it. The
//! manifest lock is taken again, alone, to adopt the verified state. No two
//! handle locks are ever held together, which matches every other bridge op
//! taking both handles (each snapshots one, releases, then the other).

use std::path::{Path, PathBuf};

use secretary_cli::pipeline::{
    sync_pass_commit_decisions, sync_pass_inspect, InspectOutcome, SyncPassOutcome,
};
use secretary_core::sync::{SyncError, SyncState};
use secretary_core::vault::{verify_vault_state, VerifiedVaultState};

use crate::error::detail;
use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::repair::baseline_provider;
use crate::sync::dto::{SyncOutcomeDto, VetoDecisionDto};
use crate::sync::pass::{
    commit_advanced, commit_outcome_to_dto, default_state_dir_or_err, inspect_advanced,
    parse_commit_args, run_locked_pass,
};
use crate::vault::manifest::ReplaceManifestError;
use crate::vault::OpenVaultManifest;

type CoreIdentity = secretary_core::unlock::UnlockedIdentity;

/// Re-verify the vault folder with the session's identity and adopt it into
/// `manifest` (the default-state-dir wrapper of [`refresh_manifest_in`]).
pub fn refresh_manifest(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(), FfiVaultError> {
    refresh_manifest_in(&default_state_dir_or_err()?, identity, manifest)
}

/// Re-verify the vault folder with the session's identity and, only if that
/// succeeds, replace the handle's manifest, envelope and owner card with what
/// is on disk. Used after a password sync pass, and by a "Reload" after a
/// write was refused with [`FfiVaultError::VaultChangedOnDisk`].
///
/// The §10 rollback check runs against this device's highest-seen clock from
/// the sync state in `state_dir`. A missing or empty state means no baseline,
/// as on the open path. Any other state-load failure refuses the refresh: it
/// fails closed like the mutating repair path (#384), because a refresh
/// exists to enable later writes that re-sign the adopted manifest. On any
/// `Err` the handle is unchanged, and a retry is safe.
///
/// # Errors
/// - `CorruptVault` — either handle has been wiped, or the sync state in
///   `state_dir` exists but cannot be read, or the disk manifest is older
///   than this device has seen (`Rollback`), or it fails verification.
/// - Any other mapping of the disk re-verify's `VaultError` (e.g. a missing or
///   mismatched block file while a cloud drive is still delivering files).
pub fn refresh_manifest_in(
    state_dir: &Path,
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(), FfiVaultError> {
    let (folder, vault_uuid) = session_target(manifest)?;
    let baseline = baseline_provider(Some(state_dir))(&vault_uuid)?;
    let verified = identity
        .with_core(|id| verify_vault_state(&folder, id, baseline.as_deref()))
        .ok_or_else(handle_closed)??;
    adopt(manifest, verified)
}

/// Default-state-dir wrapper of [`sync_vault_with_session_in`].
pub fn sync_vault_with_session(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    sync_vault_with_session_in(&default_state_dir_or_err()?, identity, manifest, now_ms)
}

/// One sync pass through the open session, then a refresh of `manifest` on
/// `AppliedAutomatically`, `SilentMerge`, `MergedClean` and `NothingToDo`.
/// Never refreshes on `RollbackRejected` (that would adopt the rolled-back
/// manifest) or `ConflictsPending` (nothing was written; the commit call
/// refreshes). The refresh runs while the pass's lockfile is still held.
///
/// The refresh's §10 rollback baseline is the pass's post-pass in-memory clock,
/// which equals the disk clock the pass accepted or wrote (since #730 a
/// `SilentMerge` writes its merge too), so a cloud re-delivery of an older
/// manifest is refused.
///
/// The identity handle's lock is held across the pass and the refresh, so
/// other calls on that identity wait for it. A `save_block` queued behind the
/// pass never writes over the pass's result: if it reads the manifest handle
/// after the refresh adopted the disk, it writes on top of the merged state;
/// if it snapshotted the handle before the adopt, or the pass wrote and the
/// refresh failed, it finds the disk changed and gets `VaultChangedOnDisk`.
///
/// If the pass succeeds but the refresh fails (typically a block file the
/// cloud drive has not delivered yet), this returns the refresh's `Err` and
/// the handle is unchanged. Retrying is safe, in that nothing unverified is
/// ever adopted: the repeat pass is `NothingToDo` and refreshes.
///
/// # Errors
/// As [`crate::sync_vault_in`] (minus `WrongPasswordOrCorrupt`), plus
/// `CorruptVault` for a wiped handle (nothing is written) and any
/// [`refresh_manifest_in`] error.
pub fn sync_vault_with_session_in(
    state_dir: &Path,
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let outcome = run_session_pass(
        state_dir,
        identity,
        manifest,
        |folder, id, state| sync_pass_inspect(folder, id, state, now_ms),
        inspect_advanced,
        inspect_refreshes,
    )?;
    Ok(outcome.into())
}

/// Default-state-dir wrapper of [`sync_commit_decisions_with_session_in`].
pub fn sync_commit_decisions_with_session(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    sync_commit_decisions_with_session_in(
        &default_state_dir_or_err()?,
        identity,
        manifest,
        decisions,
        manifest_hash,
        now_ms,
    )
}

/// Commit veto `decisions` for a pass that paused on `ConflictsPending`,
/// through the open session (call-2 of [`sync_vault_with_session_in`]; see
/// [`crate::sync_commit_decisions_in`] for the token contract), then refresh
/// `manifest` on the same outcomes and with the same guarantees as
/// [`sync_vault_with_session_in`] (including the post-pass rollback baseline
/// and the identity lock held across the pass). A refresh failure leaves the
/// handle unchanged; retrying with [`sync_vault_with_session_in`] is safe.
///
/// # Errors
/// As [`crate::sync_commit_decisions_in`] (minus `WrongPasswordOrCorrupt`),
/// plus `CorruptVault` for a wiped handle and any [`refresh_manifest_in`]
/// error.
pub fn sync_commit_decisions_with_session_in(
    state_dir: &Path,
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, FfiVaultError> {
    let (expected, core_decisions) = parse_commit_args(&decisions, &manifest_hash)?;
    let outcome = run_session_pass(
        state_dir,
        identity,
        manifest,
        |folder, id, state| {
            sync_pass_commit_decisions(folder, id, state, expected, core_decisions, now_ms)
        },
        commit_advanced,
        commit_refreshes,
    )?;
    commit_outcome_to_dto(outcome)
}

/// Run `pass` under the lockfile with the session identity; if
/// `refreshes(&outcome)`, re-verify the disk (still under the lockfile)
/// against the post-pass clock (§10) and adopt it into `manifest`. See the module
/// docs for the lock order.
fn run_session_pass<O>(
    state_dir: &Path,
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    pass: impl FnOnce(&Path, &CoreIdentity, &mut SyncState) -> Result<O, SyncError>,
    advanced: impl FnOnce(&O) -> bool,
    refreshes: impl FnOnce(&O) -> bool,
) -> Result<O, FfiVaultError> {
    let (folder, vault_uuid) = session_target(manifest)?;
    let (locked, verified) = identity
        .with_core(|id| -> Result<_, FfiVaultError> {
            let locked =
                run_locked_pass(state_dir, vault_uuid, |s| pass(&folder, id, s), advanced)?;
            let verified = if refreshes(&locked.outcome) {
                let clock = locked.state.highest_vector_clock_seen.as_slice();
                Some(verify_vault_state(&folder, id, Some(clock))?)
            } else {
                None
            };
            Ok((locked, verified))
        })
        .ok_or_else(handle_closed)??;
    if let Some(v) = verified {
        adopt(manifest, v)?;
    }
    Ok(locked.outcome)
    // The rest of `locked` drops here → lockfile released after the adopt.
}

/// Whether an inspect arm refreshes the handle. Not on `RollbackRejected`
/// (that would adopt the rolled-back manifest) or `ConflictsPending` (nothing
/// was written).
fn inspect_refreshes(o: &InspectOutcome) -> bool {
    !matches!(
        o,
        InspectOutcome::RollbackRejected | InspectOutcome::ConflictsPending { .. }
    )
}

/// Whether a commit arm refreshes the handle; same rule as [`inspect_refreshes`].
fn commit_refreshes(o: &SyncPassOutcome) -> bool {
    !matches!(
        o,
        SyncPassOutcome::RollbackRejected | SyncPassOutcome::ConflictsPending { .. }
    )
}

/// The session's vault folder and `vault_uuid`, read under one manifest lock.
fn session_target(manifest: &OpenVaultManifest) -> Result<(PathBuf, [u8; 16]), FfiVaultError> {
    // shortcut: reuses the read-block snapshot (clones manifest + card) rather
    // than adding a dedicated accessor to the over-cap manifest.rs.
    let (body, _card, folder) = manifest
        .snapshot_for_read_block()
        .ok_or_else(handle_closed)?;
    Ok((folder, body.vault_uuid))
}

fn adopt(manifest: &OpenVaultManifest, verified: VerifiedVaultState) -> Result<(), FfiVaultError> {
    match manifest.replace_verified_state(verified) {
        Ok(()) => Ok(()),
        Err(ReplaceManifestError::HandleWiped) => Err(handle_closed()),
    }
}

fn handle_closed() -> FfiVaultError {
    FfiVaultError::CorruptVault {
        detail: detail::literal("vault handle has been closed"),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod silent_merge_tests;
