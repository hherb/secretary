//! `preview_retention` / `run_retention` / `purge_block` commands. Retention
//! reads its window from the vault settings (default 90 days); the commits
//! follow the `delete::trash_block` shape — snapshot under one lock, one
//! bridge call, typed error via `map_ffi_error`. No new `FfiVaultError`
//! variant: retention/purge surface only `CorruptVault` / `FolderInvalid` /
//! `SaveCryptoFailure` (plus `purge_block`'s `BlockNotInTrash`), all already
//! mapped in `errors::mapping`.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::{
    auto_purge_expired as bridge_auto_purge, expired_trash_entries as bridge_expired_entries,
    purge_block as bridge_purge_block,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::{lock_session, parse_uuid_16};
use crate::dtos::{PurgeReportDto, RetentionPreviewDto, RetentionReportDto};
use crate::errors::{map_ffi_error, AppError};
use crate::session::VaultSession;

#[tauri::command]
pub async fn preview_retention(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<RetentionPreviewDto, AppError> {
    preview_retention_impl(state.inner())
}

#[tauri::command]
pub async fn run_retention(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<RetentionReportDto, AppError> {
    run_retention_impl(state.inner())
}

#[tauri::command]
pub async fn purge_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<PurgeReportDto, AppError> {
    purge_block_impl(state.inner(), &block_uuid_hex)
}

/// Preview which trashed blocks are past the configured window. Read-only,
/// infallible at the bridge; the `Result` carries only the locked / poisoned
/// session paths.
pub fn preview_retention_impl(
    state: &Mutex<VaultSession>,
) -> Result<RetentionPreviewDto, AppError> {
    let session = lock_session(state)?;
    let window_ms = session.current_settings().retention_window_ms;
    session.with_unlocked(|u| {
        let entries = bridge_expired_entries(&u.manifest, window_ms, now_ms());
        Ok(RetentionPreviewDto::from_entries(entries, window_ms))
    })
}

/// Commit a retention purge: permanently delete every trashed block past the
/// configured window.
pub fn run_retention_impl(state: &Mutex<VaultSession>) -> Result<RetentionReportDto, AppError> {
    let session = lock_session(state)?;
    let window_ms = session.current_settings().retention_window_ms;
    session.with_unlocked(|u| {
        // NOTE arg order: `bridge_auto_purge` takes `window_ms` BEFORE
        // `now_ms` — both are `u64`, so a swap compiles silently. Verified
        // against `ffi/secretary-ffi-bridge/src/retention/orchestration.rs`.
        let report =
            bridge_auto_purge(&u.identity, &u.manifest, window_ms, now_ms(), u.device_uuid)
                .map_err(map_ffi_error)?;
        Ok(RetentionReportDto::from(&report))
    })
}

/// Permanently delete one trashed block ("delete forever").
pub fn purge_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
) -> Result<PurgeReportDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        // NOTE arg order: `bridge_purge_block` takes `block_uuid` BEFORE
        // `device_uuid` — both are `[u8; 16]`, so a swap compiles silently.
        let report = bridge_purge_block(
            &u.identity,
            &u.manifest,
            block_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_ffi_error)?;
        Ok(PurgeReportDto::from(&report))
    })
}
