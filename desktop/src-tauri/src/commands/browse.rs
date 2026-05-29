//! D.1.2 browse commands: `read_block` (metadata-only projection) and
//! `reveal_field` (stateless per-field secret pull — added in Task 3). Both
//! require an unlocked session and route through `VaultSession::with_unlocked`.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::error::FfiVaultError;
use secretary_ffi_bridge::read_block as bridge_read_block;

use crate::dtos::BlockDetailDto;
use crate::errors::AppError;
use crate::reveal::project_block_detail;
use crate::session::VaultSession;

/// Parse a 32-char hex string into a 16-byte UUID. Bad hex folds to
/// `Internal` — the frontend only ever passes hex it received from a DTO.
fn parse_uuid_16(hex_str: &str) -> Result<[u8; 16], AppError> {
    let bytes = hex::decode(hex_str).map_err(|e| AppError::Internal {
        detail: format!("invalid uuid hex {hex_str:?}: {e}"),
    })?;
    bytes.try_into().map_err(|_| AppError::Internal {
        detail: format!("uuid hex {hex_str:?} is not 16 bytes"),
    })
}

#[tauri::command]
pub async fn read_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<BlockDetailDto, AppError> {
    read_block_impl(state.inner(), &block_uuid_hex)
}

/// Testable core for `read_block`. Decrypts the block, projects records +
/// field metadata (tombstone-filtered, no secrets), wipes the handle.
pub fn read_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
) -> Result<BlockDetailDto, AppError> {
    let uuid = parse_uuid_16(block_uuid_hex)?;
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        let output = bridge_read_block(&u.identity, &u.manifest, &uuid).map_err(|e| match e {
            // Now user-reachable (any block card click) — surface a typed
            // BlockNotFound rather than the generic Internal that the shared
            // map_ffi_error uses (it can't know the caller's hex).
            FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
                block_uuid_hex: uuid_hex,
            },
            other => AppError::from(other),
        })?;
        let dto = project_block_detail(block_uuid_hex.to_string(), &output);
        output.wipe();
        Ok(dto)
    })
}
