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
/// the sync state in `state_dir`; an unreadable state means no baseline,
/// mirroring the open path. On any `Err` the handle is unchanged, and a retry
/// is safe.
///
/// # Errors
/// - `CorruptVault` — either handle has been wiped, or the disk manifest is
///   older than this device has seen (`Rollback`), or it fails verification.
/// - Any other mapping of the disk re-verify's `VaultError` (e.g. a missing or
///   mismatched block file while a cloud drive is still delivering files).
pub fn refresh_manifest_in(
    state_dir: &Path,
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(), FfiVaultError> {
    let (folder, vault_uuid) = session_target(manifest)?;
    let baseline = secretary_cli::state::load(state_dir, vault_uuid).ok();
    let clock = baseline
        .as_ref()
        .map(|s| s.highest_vector_clock_seen.as_slice());
    let verified = identity
        .with_core(|id| verify_vault_state(&folder, id, clock))
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
/// The refresh's §10 rollback baseline depends on the arm. On
/// `AppliedAutomatically`, `MergedClean` and `NothingToDo` it is the pass's
/// post-pass in-memory clock, which equals the disk clock the pass accepted or
/// wrote, so a cloud re-delivery of an older manifest is refused. On
/// `SilentMerge` it is the PRE-pass clock, the baseline the pass itself
/// checked the disk against: the post-pass clock is the LUB of disk, the
/// conflict copies and the prior clock, so it dominates the disk and would
/// refuse the very manifest the pass just accepted.
///
/// The identity handle's lock is held across the pass and the refresh, so
/// other calls on that identity wait for it; a `save_block` queued behind the
/// pass then finds the disk changed and gets `VaultChangedOnDisk` instead of
/// writing over the pass's result.
///
/// If the pass succeeds but the refresh fails (typically a block file the
/// cloud drive has not delivered yet), this returns the refresh's `Err` and
/// the handle is unchanged. Retrying is safe, in that nothing unverified is
/// ever adopted: after `AppliedAutomatically` or `MergedClean` the repeat pass
/// is `NothingToDo` and refreshes. After `SilentMerge` the persisted LUB clock
/// dominates the disk, so the repeat pass reports `RollbackRejected` and does
/// not refresh until the disk clock catches up.
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
        inspect_baseline,
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
/// [`sync_vault_with_session_in`] (including the per-arm rollback baseline and
/// the identity lock held across the pass). A refresh failure leaves the
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
        commit_baseline,
    )?;
    commit_outcome_to_dto(outcome)
}

/// Which clock a session refresh checks the disk against (§10), per arm.
enum Baseline {
    /// The state clock loaded before the pass ran.
    PrePass,
    /// The pass's in-memory state clock after it ran.
    PostPass,
}

/// Run `pass` under the lockfile with the session identity; if
/// `baseline(&outcome)` is `Some`, re-verify the disk (still under the
/// lockfile) against that clock and adopt it into `manifest`. See the module
/// docs for the lock order.
fn run_session_pass<O>(
    state_dir: &Path,
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    pass: impl FnOnce(&Path, &CoreIdentity, &mut SyncState) -> Result<O, SyncError>,
    advanced: impl FnOnce(&O) -> bool,
    baseline: impl FnOnce(&O) -> Option<Baseline>,
) -> Result<O, FfiVaultError> {
    let (folder, vault_uuid) = session_target(manifest)?;
    let (locked, verified) = identity
        .with_core(|id| -> Result<_, FfiVaultError> {
            let mut pre_pass = Vec::new();
            let locked = run_locked_pass(
                state_dir,
                vault_uuid,
                |s| {
                    pre_pass = s.highest_vector_clock_seen.clone();
                    pass(&folder, id, s)
                },
                advanced,
            )?;
            let clock = match baseline(&locked.outcome) {
                Some(Baseline::PrePass) => Some(pre_pass.as_slice()),
                Some(Baseline::PostPass) => Some(locked.state.highest_vector_clock_seen.as_slice()),
                None => None,
            };
            let verified = match clock {
                Some(c) => Some(verify_vault_state(&folder, id, Some(c))?),
                None => None,
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

/// Refresh baseline per inspect arm; `None` = do not refresh. See
/// [`sync_vault_with_session_in`] for why `SilentMerge` uses the pre-pass clock.
fn inspect_baseline(o: &InspectOutcome) -> Option<Baseline> {
    match o {
        InspectOutcome::AppliedAutomatically
        | InspectOutcome::MergedClean
        | InspectOutcome::NothingToDo => Some(Baseline::PostPass),
        InspectOutcome::SilentMerge => Some(Baseline::PrePass),
        InspectOutcome::RollbackRejected | InspectOutcome::ConflictsPending { .. } => None,
    }
}

/// Refresh baseline per commit arm; same rule as [`inspect_baseline`].
fn commit_baseline(o: &SyncPassOutcome) -> Option<Baseline> {
    match o {
        SyncPassOutcome::AppliedAutomatically
        | SyncPassOutcome::MergedClean
        | SyncPassOutcome::NothingToDo => Some(Baseline::PostPass),
        SyncPassOutcome::SilentMerge => Some(Baseline::PrePass),
        SyncPassOutcome::RollbackRejected | SyncPassOutcome::ConflictsPending { .. } => None,
    }
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
