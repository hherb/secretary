//! `list_blocks` + `get_manifest` commands. Read-only projections of the
//! unlocked manifest. Both require the session to be unlocked; both
//! return `AppError::NotUnlocked` otherwise (via [`VaultSession::with_unlocked`]).
//!
//! `get_manifest` returns an empty `warnings` vec — pending warnings are
//! delivered only at unlock time (via `unlock_with_password`) since
//! re-surfacing them on every manifest refresh would produce a duplicate
//! banner with each `list_blocks` poll. Frontend caches the unlock-time
//! warnings; `get_manifest` is for fresh-manifest reads, not warnings.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::vault::OpenVaultManifest;

use crate::commands::shared::lock_session;
use crate::dtos::{BlockSummaryDto, ManifestDto};
use crate::errors::AppError;
use crate::session::VaultSession;

/// Project the [`BlockSummaryDto`] for one live block out of a refreshed
/// manifest, by UUID. Returns `None` when the block is not in
/// `manifest.block_summaries()` (e.g. trashed, never created, or a stale
/// UUID). Shared by `create_block_impl` and `restore_block_impl`, both of
/// which need to surface the just-mutated block to the frontend — sound
/// because the bridge mutators refresh the in-memory manifest before
/// returning.
pub(crate) fn block_summary_for(
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
) -> Option<BlockSummaryDto> {
    manifest
        .block_summaries()
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .map(BlockSummaryDto::from)
}

#[tauri::command]
pub async fn list_blocks(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Vec<BlockSummaryDto>, AppError> {
    list_blocks_impl(state.inner())
}

#[tauri::command]
pub async fn get_manifest(state: State<'_, Mutex<VaultSession>>) -> Result<ManifestDto, AppError> {
    get_manifest_impl(state.inner())
}

/// Testable core for `list_blocks`. Projects each [`BlockSummary`] through
/// [`BlockSummaryDto`] without touching any secret state — `BlockSummary`'s
/// fields are plaintext within the encrypted manifest.
///
/// [`BlockSummary`]: secretary_ffi_bridge::vault::BlockSummary
pub fn list_blocks_impl(state: &Mutex<VaultSession>) -> Result<Vec<BlockSummaryDto>, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let summaries = u.manifest.block_summaries();
        Ok(summaries.iter().map(BlockSummaryDto::from).collect())
    })
}

/// Testable core for `get_manifest`. Returns a fresh [`ManifestDto`] with
/// no warnings — see module-level docs for rationale.
pub fn get_manifest_impl(state: &Mutex<VaultSession>) -> Result<ManifestDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(
            &u.manifest,
            vec![],
        ))
    })
}
