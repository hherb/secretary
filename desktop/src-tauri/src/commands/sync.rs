//! Sync IPC commands (D.1.14): `sync_status` (read) + `sync_now` (mutation).
//! Thin delegates to the bridge `sync_status` / `sync_vault` (D.1.13), in the
//! same `#[tauri::command]` + testable `*_impl` split as the other command
//! modules. `sync_now` re-opens a core identity from a fresh password (the
//! bridge surface takes a password, not the session identity) — the password
//! rides the zeroize-typed `Password` and is dropped at `_impl` end.

use std::sync::Mutex;

use tauri::State;

use secretary_core::crypto::secret::SecretBytes;
use secretary_ffi_bridge::{
    sync_commit_decisions as bridge_sync_commit_decisions, sync_status as bridge_sync_status,
    sync_vault as bridge_sync_vault,
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
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let outcome = bridge_sync_vault(
            &u.vault_folder,
            SecretBytes::from(password.expose()),
            now_ms,
        )
        .map_err(map_ffi_error)?;
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
    let bridge_decisions: Vec<secretary_ffi_bridge::VetoDecisionDto> = decisions
        .into_iter()
        .map(|d| secretary_ffi_bridge::VetoDecisionDto {
            record_uuid_hex: d.record_uuid_hex,
            keep_local: d.keep_local,
        })
        .collect();
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let outcome = bridge_sync_commit_decisions(
            &u.vault_folder,
            SecretBytes::from(password.expose()),
            bridge_decisions,
            manifest_hash,
            now_ms,
        )
        .map_err(map_ffi_error)?;
        Ok(SyncOutcomeDto::from(outcome))
    })
}
