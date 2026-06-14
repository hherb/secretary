//! D.1.2 browse commands: `read_block` (metadata-only projection) and
//! `reveal_field` (stateless per-field secret pull — added in Task 3). Both
//! require an unlocked session and route through `VaultSession::with_unlocked`.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::error::FfiVaultError;
use secretary_ffi_bridge::read_block as bridge_read_block;

use crate::commands::shared::{lock_session, parse_uuid_16};
use crate::dtos::{BlockDetailDto, RevealedFieldDto};
use crate::errors::AppError;
use crate::reveal::{encode_revealed_bytes, locate_record, project_block_detail};
use crate::session::VaultSession;

#[tauri::command]
pub async fn read_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    include_deleted: bool,
) -> Result<BlockDetailDto, AppError> {
    read_block_impl(state.inner(), &block_uuid_hex, include_deleted)
}

/// Testable core for `read_block`. Decrypts the block, projects records +
/// field metadata (no secrets), wipes the handle. The `include_deleted` gate
/// decides whether tombstoned records cross the IPC seam (Rust gates
/// visibility): `false` = live-only; `true` = emit tombstoned records flagged.
pub fn read_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    include_deleted: bool,
) -> Result<BlockDetailDto, AppError> {
    let uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let output = bridge_read_block(&u.identity, &u.manifest, &uuid, include_deleted).map_err(
            |e| match e {
                // Now user-reachable (any block card click) — surface a typed
                // BlockNotFound rather than the generic Internal that the shared
                // map_ffi_error uses (it can't know the caller's hex).
                FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
                    block_uuid_hex: uuid_hex,
                },
                other => AppError::from(other),
            },
        )?;
        let dto = project_block_detail(block_uuid_hex.to_string(), &output, include_deleted);
        output.wipe();
        Ok(dto)
    })
}

#[tauri::command]
pub async fn reveal_field(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record_uuid_hex: String,
    field_name: String,
) -> Result<RevealedFieldDto, AppError> {
    reveal_field_impl(
        state.inner(),
        &block_uuid_hex,
        &record_uuid_hex,
        &field_name,
    )
}

/// Testable core for `reveal_field`. STATELESS: re-decrypts the block,
/// locates the record + field, pulls exactly one secret via the FFI expose
/// boundary, base64-encodes bytes (zeroizing the intermediate), wipes the
/// handle, returns the single plaintext. No decrypted block is retained.
pub fn reveal_field_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record_uuid_hex: &str,
    field_name: &str,
) -> Result<RevealedFieldDto, AppError> {
    let uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let output =
            bridge_read_block(&u.identity, &u.manifest, &uuid, false).map_err(|e| match e {
                FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
                    block_uuid_hex: uuid_hex,
                },
                other => AppError::from(other),
            })?;

        // Locate record + field; on any miss, wipe before returning the error.
        let record = match locate_record(&output, record_uuid_hex) {
            Some(r) => r,
            None => {
                output.wipe();
                return Err(AppError::RecordNotFound {
                    record_uuid_hex: record_uuid_hex.to_string(),
                });
            }
        };
        let field = match record.field_by_name(field_name) {
            Some(f) => f,
            None => {
                output.wipe();
                return Err(AppError::FieldNotFound {
                    field_name: field_name.to_string(),
                });
            }
        };

        let dto = if field.is_text() {
            match field.expose_text() {
                Some(value) => RevealedFieldDto {
                    is_text: true,
                    value,
                },
                None => {
                    output.wipe();
                    return Err(AppError::Internal {
                        detail: "expose_text returned None on is_text field".to_string(),
                    });
                }
            }
        } else {
            match field.expose_bytes() {
                Some(bytes) => RevealedFieldDto {
                    is_text: false,
                    value: encode_revealed_bytes(bytes),
                },
                None => {
                    output.wipe();
                    return Err(AppError::Internal {
                        detail: "expose_bytes returned None on bytes field".to_string(),
                    });
                }
            }
        };

        output.wipe(); // zeroizes all FieldHandles' SecretString/SecretBytes
        Ok(dto)
    })
}
