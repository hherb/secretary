//! D.1.5 delete/trash commands: `tombstone_record`, `resurrect_record`,
//! `trash_block`, `restore_block`, `list_trashed_blocks`. Thin
//! `#[tauri::command]` shells + testable `*_impl` over the bridge's
//! soft-delete / trash primitives. Same pattern as [`super::edit`]: the
//! command extracts state + args and delegates; the `*_impl` resolves UUIDs,
//! locks the session, and runs the bridge call inside
//! [`VaultSession::with_unlocked`].
//!
//! Error mapping is split by primitive class:
//! - record tombstone/resurrect use a local [`map_record_delete_error`]
//!   mirroring `edit::map_save_error` (BlockNotFound / RecordNotFound stay
//!   typed; everything else folds to `RecordSaveFailed`),
//! - block trash/restore/list use the shared [`map_ffi_error`], which already
//!   routes the trash-precondition variants (`BlockUuidAlreadyLive` →
//!   `BlockRestoreConflict`, `BlockNotInTrash` → `TrashEntryNotFound`).

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::error::FfiVaultError;
use secretary_ffi_bridge::{
    list_trashed_blocks as bridge_list_trashed_blocks, restore_block as bridge_restore_block,
    resurrect_record as bridge_resurrect_record, tombstone_record as bridge_tombstone_record,
    trash_block as bridge_trash_block,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::{lock_session, parse_uuid_16};
use crate::commands::vault::block_summary_for;
use crate::dtos::{BlockSummaryDto, RecordRefDto, TrashedBlockDto};
use crate::errors::{map_ffi_error, AppError};
use crate::session::VaultSession;

/// Map a bridge record-delete error to a typed `AppError`. Mirrors
/// `edit::map_save_error`: `BlockNotFound` / `RecordNotFound` surface
/// precisely so the editor can react (e.g. the record was deleted under it);
/// everything else (crypto / IO / save-tail) folds to `RecordSaveFailed`
/// after a `tracing::warn!`.
fn map_record_delete_error(e: FfiVaultError) -> AppError {
    match e {
        FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
            block_uuid_hex: uuid_hex,
        },
        FfiVaultError::RecordNotFound { uuid_hex } => AppError::RecordNotFound {
            record_uuid_hex: uuid_hex,
        },
        other => {
            tracing::warn!(?other, "record tombstone/resurrect failed");
            AppError::RecordSaveFailed {
                detail: format!("{other:?}"),
            }
        }
    }
}

#[tauri::command]
pub async fn tombstone_record(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record_uuid_hex: String,
) -> Result<RecordRefDto, AppError> {
    tombstone_record_impl(state.inner(), &block_uuid_hex, &record_uuid_hex)
}

pub fn tombstone_record_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record_uuid_hex: &str,
) -> Result<RecordRefDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let record_uuid = parse_uuid_16(record_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_tombstone_record(
            &u.identity,
            &u.manifest,
            block_uuid,
            record_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_record_delete_error)?;
        Ok(RecordRefDto {
            block_uuid_hex: block_uuid_hex.to_string(),
            record_uuid_hex: record_uuid_hex.to_string(),
        })
    })
}

#[tauri::command]
pub async fn resurrect_record(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record_uuid_hex: String,
) -> Result<RecordRefDto, AppError> {
    resurrect_record_impl(state.inner(), &block_uuid_hex, &record_uuid_hex)
}

pub fn resurrect_record_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record_uuid_hex: &str,
) -> Result<RecordRefDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let record_uuid = parse_uuid_16(record_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_resurrect_record(
            &u.identity,
            &u.manifest,
            block_uuid,
            record_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_record_delete_error)?;
        Ok(RecordRefDto {
            block_uuid_hex: block_uuid_hex.to_string(),
            record_uuid_hex: record_uuid_hex.to_string(),
        })
    })
}

#[tauri::command]
pub async fn trash_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<(), AppError> {
    trash_block_impl(state.inner(), &block_uuid_hex)
}

pub fn trash_block_impl(state: &Mutex<VaultSession>, block_uuid_hex: &str) -> Result<(), AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_trash_block(
            &u.identity,
            &u.manifest,
            block_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_ffi_error)?;
        Ok(())
    })
}

#[tauri::command]
pub async fn restore_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<BlockSummaryDto, AppError> {
    restore_block_impl(state.inner(), &block_uuid_hex)
}

pub fn restore_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
) -> Result<BlockSummaryDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_restore_block(
            &u.identity,
            &u.manifest,
            block_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_ffi_error)?;
        // Project the now-live block from the refreshed manifest. Sound: the
        // bridge restore refreshes the in-memory manifest before returning, so
        // the block is present in `block_summaries()`. A miss here would be a
        // bridge invariant violation, not a user-reachable state.
        block_summary_for(&u.manifest, block_uuid).ok_or_else(|| AppError::Internal {
            detail: "restored block missing from manifest".into(),
        })
    })
}

#[tauri::command]
pub async fn list_trashed_blocks(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Vec<TrashedBlockDto>, AppError> {
    list_trashed_blocks_impl(state.inner())
}

pub fn list_trashed_blocks_impl(
    state: &Mutex<VaultSession>,
) -> Result<Vec<TrashedBlockDto>, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let trashed =
            bridge_list_trashed_blocks(&u.identity, &u.manifest).map_err(map_ffi_error)?;
        Ok(trashed
            .into_iter()
            .map(|t| TrashedBlockDto {
                block_uuid_hex: hex::encode(t.block_uuid),
                block_name: t.block_name,
                tombstoned_at_ms: t.tombstoned_at_ms,
                tombstoned_by_hex: hex::encode(t.tombstoned_by),
            })
            .collect())
    })
}
