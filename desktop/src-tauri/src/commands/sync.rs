//! Sync IPC commands (D.1.14): `sync_status` (read) + `sync_now` (mutation).
//! Thin delegates to the bridge `sync_status` / `sync_vault` (D.1.13), in the
//! same `#[tauri::command]` + testable `*_impl` split as the other command
//! modules. `sync_now` re-opens a core identity from a fresh password (the
//! bridge surface takes a password, not the session identity) — the password
//! rides the zeroize-typed `Password` and is dropped at `_impl` end.

use std::path::Path;
use std::sync::Mutex;

use tauri::State;

use secretary_core::crypto::secret::SecretBytes;
use secretary_ffi_bridge::{
    refresh_manifest as bridge_refresh_manifest, refresh_manifest_in as bridge_refresh_manifest_in,
    sync_commit_decisions as bridge_sync_commit_decisions,
    sync_commit_decisions_in as bridge_sync_commit_decisions_in, sync_status as bridge_sync_status,
    sync_vault as bridge_sync_vault, sync_vault_in as bridge_sync_vault_in,
    SyncOutcomeDto as BridgeOutcome,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::{lock_session, vault_uuid_bytes_16};
use crate::dtos::{SyncOutcomeDto, SyncStatusDto, VetoDecisionDto};
use crate::errors::{map_ffi_error, AppError};
use crate::secret_arg::Password;
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
pub async fn sync_now(
    state: State<'_, Mutex<VaultSession>>,
    password: Password,
) -> Result<SyncOutcomeDto, AppError> {
    sync_now_impl(state.inner(), &password, now_ms())
}

/// Testable core for `sync_now`. Runs the bridge pause-on-conflict sync pass
/// over the session's retained vault folder, re-opening an identity from
/// `password`. `now_ms` is supplied by the command wrapper (deterministic in
/// tests); it only affects the merge timestamp on the committing arms
/// (`MergedClean` / `SilentMerge`). Strict: every bridge error is mapped,
/// nothing swallowed.
pub fn sync_now_impl(
    state: &Mutex<VaultSession>,
    password: &Password,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    sync_now_core(state, None, password, now_ms)
}

/// [`sync_now_impl`] against an explicit sync-state directory (hermetic tests).
pub fn sync_now_in_impl(
    state: &Mutex<VaultSession>,
    state_dir: &Path,
    password: &Password,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    sync_now_core(state, Some(state_dir), password, now_ms)
}

/// Whether the session's handle must be re-read after a pass with this outcome.
/// Not after `SilentMerge`: the password pass persists a clock that always
/// dominates the disk (#730), so a refresh there would fail as a rollback.
fn needs_refresh(outcome: &BridgeOutcome) -> bool {
    matches!(
        outcome,
        BridgeOutcome::NothingToDo
            | BridgeOutcome::AppliedAutomatically
            | BridgeOutcome::MergedClean
    )
}

fn sync_now_core(
    state: &Mutex<VaultSession>,
    state_dir: Option<&Path>,
    password: &Password,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let pw = SecretBytes::from(password.expose());
        let outcome = match state_dir {
            Some(d) => bridge_sync_vault_in(d, &u.vault_folder, pw, now_ms),
            None => bridge_sync_vault(&u.vault_folder, pw, now_ms),
        }
        .map_err(map_ffi_error)?;
        if needs_refresh(&outcome) {
            // The pass wrote through its own open; re-read so our next write is not refused.
            match state_dir {
                Some(d) => bridge_refresh_manifest_in(d, &u.identity, &u.manifest),
                None => bridge_refresh_manifest(&u.identity, &u.manifest),
            }
            .map_err(map_ffi_error)?;
        }
        Ok(SyncOutcomeDto::from(outcome))
    })
}

#[tauri::command]
pub async fn sync_commit_decisions(
    state: State<'_, Mutex<VaultSession>>,
    password: Password,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
) -> Result<SyncOutcomeDto, AppError> {
    sync_commit_decisions_impl(state.inner(), &password, decisions, manifest_hash, now_ms())
}

/// Testable core for `sync_commit_decisions` (call-2 of interactive resolution).
/// Converts the renderer's decisions to the bridge DTO, re-opens an identity
/// from `password`, and commits over the session's retained vault folder.
/// `now_ms` is supplied by the wrapper (deterministic in tests). Strict: every
/// bridge error is mapped, nothing swallowed.
pub fn sync_commit_decisions_impl(
    state: &Mutex<VaultSession>,
    password: &Password,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    sync_commit_core(state, None, password, decisions, manifest_hash, now_ms)
}

/// [`sync_commit_decisions_impl`] against an explicit sync-state directory.
pub fn sync_commit_decisions_in_impl(
    state: &Mutex<VaultSession>,
    state_dir: &Path,
    password: &Password,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    sync_commit_core(
        state,
        Some(state_dir),
        password,
        decisions,
        manifest_hash,
        now_ms,
    )
}

fn sync_commit_core(
    state: &Mutex<VaultSession>,
    state_dir: Option<&Path>,
    password: &Password,
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
        let pw = SecretBytes::from(password.expose());
        let outcome = match state_dir {
            Some(d) => bridge_sync_commit_decisions_in(
                d,
                &u.vault_folder,
                pw,
                bridge_decisions,
                manifest_hash,
                now_ms,
            ),
            None => bridge_sync_commit_decisions(
                &u.vault_folder,
                pw,
                bridge_decisions,
                manifest_hash,
                now_ms,
            ),
        }
        .map_err(map_ffi_error)?;
        if needs_refresh(&outcome) {
            // Same rule as `sync_now_core` (#730).
            match state_dir {
                Some(d) => bridge_refresh_manifest_in(d, &u.identity, &u.manifest),
                None => bridge_refresh_manifest(&u.identity, &u.manifest),
            }
            .map_err(map_ffi_error)?;
        }
        Ok(SyncOutcomeDto::from(outcome))
    })
}
