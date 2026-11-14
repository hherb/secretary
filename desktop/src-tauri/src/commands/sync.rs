//! Sync IPC commands (D.1.14): `sync_status` (read) + `sync_now` /
//! `sync_commit_decisions` (mutations). Thin delegates to the bridge, in the
//! same `#[tauri::command]` + testable `*_impl` split as the other command
//! modules. Both mutations sync through the unlocked session (#732): no
//! password per pass, and the bridge refreshes the session's manifest handle
//! from disk after every arm that wrote or accepted a manifest, so the next
//! write is not refused as stale. The renderer gates both behind the write
//! re-auth prompt (`writeCommands.ts`).

use std::path::Path;
use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::{
    sync_commit_decisions_with_session as bridge_sync_commit_decisions,
    sync_commit_decisions_with_session_in as bridge_sync_commit_decisions_in,
    sync_status as bridge_sync_status, sync_vault_with_session as bridge_sync_vault,
    sync_vault_with_session_in as bridge_sync_vault_in,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::{lock_session, vault_uuid_bytes_16};
use crate::dtos::{SyncOutcomeDto, SyncStatusDto, VetoDecisionDto};
use crate::errors::{map_ffi_error, AppError};
use crate::session::VaultSession;

#[tauri::command]
pub async fn sync_status(state: State<'_, Mutex<VaultSession>>) -> Result<SyncStatusDto, AppError> {
    sync_status_impl(state.inner())
}

/// Testable core for `sync_status`. Read-only: projects the bridge status for
/// the unlocked vault's uuid. `NotUnlocked` when locked (via `with_unlocked`).
pub fn sync_status_impl(state: &Mutex<VaultSession>) -> Result<SyncStatusDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let vault_uuid = vault_uuid_bytes_16(&u.manifest.vault_uuid())?;
        let dto = bridge_sync_status(vault_uuid).map_err(map_ffi_error)?;
        Ok(SyncStatusDto::from(dto))
    })
}

#[tauri::command]
pub async fn sync_now(state: State<'_, Mutex<VaultSession>>) -> Result<SyncOutcomeDto, AppError> {
    sync_now_impl(state.inner(), now_ms())
}

/// Testable core for `sync_now`. Runs the bridge inspect pass through the
/// unlocked session, then the bridge refreshes the session's manifest handle.
/// `now_ms` is supplied by the command wrapper (deterministic in tests); it
/// only affects the merge timestamp on the committing arms (`MergedClean` /
/// `SilentMerge`). Strict: every bridge error is mapped, nothing swallowed.
pub fn sync_now_impl(state: &Mutex<VaultSession>, now_ms: u64) -> Result<SyncOutcomeDto, AppError> {
    sync_now_core(state, None, now_ms)
}

/// [`sync_now_impl`] against an explicit sync-state directory (hermetic tests).
pub fn sync_now_in_impl(
    state: &Mutex<VaultSession>,
    state_dir: &Path,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    sync_now_core(state, Some(state_dir), now_ms)
}

fn sync_now_core(
    state: &Mutex<VaultSession>,
    state_dir: Option<&Path>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let outcome = match state_dir {
            Some(d) => bridge_sync_vault_in(d, &u.identity, &u.manifest, now_ms),
            None => bridge_sync_vault(&u.identity, &u.manifest, now_ms),
        }
        .map_err(map_ffi_error)?;
        Ok(SyncOutcomeDto::from(outcome))
    })
}

#[tauri::command]
pub async fn sync_commit_decisions(
    state: State<'_, Mutex<VaultSession>>,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
) -> Result<SyncOutcomeDto, AppError> {
    sync_commit_decisions_impl(state.inner(), decisions, manifest_hash, now_ms())
}

/// Testable core for `sync_commit_decisions` (call-2 of interactive resolution).
/// Converts the renderer's decisions to the bridge DTO and commits through the
/// unlocked session; the bridge then refreshes the session's manifest handle.
/// `now_ms` is supplied by the wrapper (deterministic in tests). Strict: every
/// bridge error is mapped, nothing swallowed.
pub fn sync_commit_decisions_impl(
    state: &Mutex<VaultSession>,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    sync_commit_core(state, None, decisions, manifest_hash, now_ms)
}

/// [`sync_commit_decisions_impl`] against an explicit sync-state directory.
pub fn sync_commit_decisions_in_impl(
    state: &Mutex<VaultSession>,
    state_dir: &Path,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    sync_commit_core(state, Some(state_dir), decisions, manifest_hash, now_ms)
}

fn sync_commit_core(
    state: &Mutex<VaultSession>,
    state_dir: Option<&Path>,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    let bridge_decisions: Vec<secretary_ffi_bridge::VetoDecisionDto> = decisions
        .into_iter()
        .map(|d| secretary_ffi_bridge::VetoDecisionDto {
            record_uuid_hex: d.record_uuid_hex,
            keep_local: d.keep_local,
        })
        .collect();
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let outcome = match state_dir {
            Some(d) => bridge_sync_commit_decisions_in(
                d,
                &u.identity,
                &u.manifest,
                bridge_decisions,
                manifest_hash,
                now_ms,
            ),
            None => bridge_sync_commit_decisions(
                &u.identity,
                &u.manifest,
                bridge_decisions,
                manifest_hash,
                now_ms,
            ),
        }
        .map_err(map_ffi_error)?;
        Ok(SyncOutcomeDto::from(outcome))
    })
}
