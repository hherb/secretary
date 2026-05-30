//! D.1.4 edit commands: `create_block`, `save_record`, `save_record_edit`,
//! `reveal_record`. Thin `#[tauri::command]` shells + testable `*_impl`.
//!
//! All four require an unlocked session (route through
//! `VaultSession::with_unlocked`) and call the bridge's native-BlockPlaintext
//! edit primitives, which confine the whole-block plaintext to Rust — the
//! frontend only ever sends/receives ONE record's fields.

use std::sync::Mutex;

use base64::Engine as _;
use tauri::State;

use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_ffi_bridge::error::FfiVaultError;
use secretary_ffi_bridge::{
    append_record as bridge_append_record, create_block as bridge_create_block,
    edit_record as bridge_edit_record, read_block as bridge_read_block, FieldInput,
    FieldInputValue, RecordContent,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::parse_uuid_16;
use crate::dtos::{
    BlockSummaryDto, FieldValueDto, RecordInputDto, RecordRefDto, RecordRevealDto,
    RevealedFieldWithNameDto,
};
use crate::errors::AppError;
use crate::reveal::locate_record;
use crate::session::VaultSession;

/// Fresh random 16-byte UUID for a new block/record.
/// Uses `rand_core::OsRng.fill_bytes`, which panics on OS RNG failure — that
/// is catastrophic and acceptable here (consistent with core's CSPRNG usage).
fn new_uuid_16() -> [u8; 16] {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b
}

/// Validate field names (required + unique) and decode `RecordInputDto`'s
/// `FieldValueDto`s into the bridge's zeroize-typed `FieldInput`s. Base64
/// decode failure / empty / duplicate name → typed `InvalidFieldValue`.
fn dto_to_record_content(dto: RecordInputDto) -> Result<RecordContent, AppError> {
    let mut seen = std::collections::HashSet::new();
    let mut fields = Vec::with_capacity(dto.fields.len());
    for f in dto.fields {
        if f.name.trim().is_empty() || !seen.insert(f.name.clone()) {
            return Err(AppError::InvalidFieldValue { field_name: f.name });
        }
        let value = match f.value {
            FieldValueDto::Text { text } => FieldInputValue::Text(SecretString::from(text)),
            FieldValueDto::Bytes { base64 } => {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(base64.as_bytes())
                    .map_err(|_| AppError::InvalidFieldValue {
                        field_name: f.name.clone(),
                    })?;
                FieldInputValue::Bytes(SecretBytes::from(raw.as_slice()))
            }
        };
        fields.push(FieldInput {
            name: f.name,
            value,
        });
    }
    Ok(RecordContent {
        record_type: dto.record_type,
        tags: dto.tags,
        fields,
    })
}

/// Map a bridge save error to a typed `AppError`. `BlockNotFound`/`RecordNotFound`
/// surface precisely; everything else (crypto/IO) is `RecordSaveFailed`.
fn map_save_error(e: FfiVaultError) -> AppError {
    match e {
        FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
            block_uuid_hex: uuid_hex,
        },
        FfiVaultError::RecordNotFound { uuid_hex } => AppError::RecordNotFound {
            record_uuid_hex: uuid_hex,
        },
        other => {
            tracing::warn!(?other, "record save failed");
            AppError::RecordSaveFailed {
                detail: format!("{other:?}"),
            }
        }
    }
}

#[tauri::command]
pub async fn create_block(
    state: State<'_, Mutex<VaultSession>>,
    block_name: String,
) -> Result<BlockSummaryDto, AppError> {
    create_block_impl(state.inner(), &block_name)
}

pub fn create_block_impl(
    state: &Mutex<VaultSession>,
    block_name: &str,
) -> Result<BlockSummaryDto, AppError> {
    let block_uuid = new_uuid_16();
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        bridge_create_block(
            &u.identity,
            &u.manifest,
            block_uuid,
            block_name.to_string(),
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_save_error)?;
        // Project the new block from the refreshed manifest so the list can refresh.
        // Sound: bridge_create_block → save_plaintext → replace_manifest_and_file
        // updates the in-memory manifest before returning.
        let summary = u
            .manifest
            .block_summaries()
            .iter()
            .find(|b| b.block_uuid == block_uuid)
            .map(BlockSummaryDto::from)
            .ok_or_else(|| AppError::Internal {
                detail: "created block missing from manifest".into(),
            })?;
        Ok(summary)
    })
}

#[tauri::command]
pub async fn save_record(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record: RecordInputDto,
) -> Result<RecordRefDto, AppError> {
    save_record_impl(state.inner(), &block_uuid_hex, record)
}

pub fn save_record_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record: RecordInputDto,
) -> Result<RecordRefDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let content = dto_to_record_content(record)?;
    let record_uuid = new_uuid_16();
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        bridge_append_record(
            &u.identity,
            &u.manifest,
            block_uuid,
            record_uuid,
            content,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_save_error)?;
        Ok(RecordRefDto {
            block_uuid_hex: block_uuid_hex.to_string(),
            record_uuid_hex: hex::encode(record_uuid),
        })
    })
}

#[tauri::command]
pub async fn save_record_edit(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record_uuid_hex: String,
    record: RecordInputDto,
) -> Result<RecordRefDto, AppError> {
    save_record_edit_impl(state.inner(), &block_uuid_hex, &record_uuid_hex, record)
}

pub fn save_record_edit_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record_uuid_hex: &str,
    record: RecordInputDto,
) -> Result<RecordRefDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let record_uuid = parse_uuid_16(record_uuid_hex)?;
    let content = dto_to_record_content(record)?;
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        bridge_edit_record(
            &u.identity,
            &u.manifest,
            block_uuid,
            record_uuid,
            content,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_save_error)?;
        Ok(RecordRefDto {
            block_uuid_hex: block_uuid_hex.to_string(),
            record_uuid_hex: record_uuid_hex.to_string(),
        })
    })
}

#[tauri::command]
pub async fn reveal_record(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record_uuid_hex: String,
) -> Result<RecordRevealDto, AppError> {
    reveal_record_impl(state.inner(), &block_uuid_hex, &record_uuid_hex)
}

/// Reveal ONE record's fields for edit prefill. Decrypts the block, locates
/// the record, exposes only ITS fields (siblings never exposed to JS), wipes
/// the handle. Mirrors `reveal_field_impl` but for a whole record.
pub fn reveal_record_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record_uuid_hex: &str,
) -> Result<RecordRevealDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        let output =
            bridge_read_block(&u.identity, &u.manifest, &block_uuid).map_err(|e| match e {
                FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
                    block_uuid_hex: uuid_hex,
                },
                other => AppError::from(other),
            })?;
        let record = match locate_record(&output, record_uuid_hex) {
            Some(r) => r,
            None => {
                output.wipe();
                return Err(AppError::RecordNotFound {
                    record_uuid_hex: record_uuid_hex.to_string(),
                });
            }
        };
        let mut fields = Vec::with_capacity(record.field_count());
        for i in 0..record.field_count() {
            let Some(h) = record.field_at(i) else {
                continue;
            };
            let (is_text, value) = if h.is_text() {
                match h.expose_text() {
                    Some(v) => (true, v),
                    None => {
                        output.wipe();
                        return Err(AppError::Internal {
                            detail: "expose_text returned None on is_text field".to_string(),
                        });
                    }
                }
            } else {
                // base64 the bytes; encode_revealed_bytes zeroizes the raw Vec.
                match h.expose_bytes() {
                    Some(bytes) => (false, crate::reveal::encode_revealed_bytes(bytes)),
                    None => {
                        output.wipe();
                        return Err(AppError::Internal {
                            detail: "expose_bytes returned None on bytes field".to_string(),
                        });
                    }
                }
            };
            fields.push(RevealedFieldWithNameDto {
                name: h.name(),
                is_text,
                value,
            });
        }
        output.wipe();
        Ok(RecordRevealDto { fields })
    })
}
