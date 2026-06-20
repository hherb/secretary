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
    edit_record as bridge_edit_record, move_record as bridge_move_record,
    read_block as bridge_read_block, rename_block as bridge_rename_block, FieldInput,
    FieldInputValue, RecordContent,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::{lock_session, parse_uuid_16};
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
///
/// Field names are trimmed before the empty-check, the uniqueness check, AND
/// storage — matching the frontend's `draftToRecordInputDto`. Doing all three
/// on the trimmed name keeps this command layer self-consistent (the dedup set
/// and the stored CBOR key agree) and is the validation point a future
/// non-desktop caller of the bridge primitives (uniffi/pyo3, #167) would rely
/// on, since the bridge primitives themselves do no name validation.
fn dto_to_record_content(dto: RecordInputDto) -> Result<RecordContent, AppError> {
    let mut seen = std::collections::HashSet::new();
    let mut fields = Vec::with_capacity(dto.fields.len());
    for f in dto.fields {
        let name = f.name.trim().to_string();
        if name.is_empty() || !seen.insert(name.clone()) {
            return Err(AppError::InvalidFieldValue { field_name: name });
        }
        let value = match f.value {
            FieldValueDto::Text { text } => FieldInputValue::Text(SecretString::from(text)),
            FieldValueDto::Bytes { base64 } => {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(base64.as_bytes())
                    .map_err(|_| AppError::InvalidFieldValue {
                        field_name: name.clone(),
                    })?;
                FieldInputValue::Bytes(SecretBytes::from(raw.as_slice()))
            }
        };
        fields.push(FieldInput { name, value });
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
    let session = lock_session(state)?;
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
        let summary = crate::commands::vault::block_summary_for(&u.manifest, block_uuid)
            .ok_or_else(|| AppError::Internal {
                detail: "created block missing from manifest".into(),
            })?;
        Ok(summary)
    })
}

#[tauri::command]
pub async fn rename_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    new_name: String,
) -> Result<BlockSummaryDto, AppError> {
    rename_block_impl(state.inner(), &block_uuid_hex, &new_name)
}

/// Rename a block to `new_name`, preserving every record. Blank/whitespace
/// `new_name` is rejected here as `InvalidArgument` (a desktop UI policy;
/// the bridge/spec permit empty names). Returns the updated summary so the
/// block list can refresh with the new name.
pub fn rename_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    new_name: &str,
) -> Result<BlockSummaryDto, AppError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(AppError::InvalidArgument {
            detail: "block name must not be blank".to_string(),
        });
    }
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_rename_block(
            &u.identity,
            &u.manifest,
            block_uuid,
            new_name.to_string(),
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_save_error)?;
        let summary = crate::commands::vault::block_summary_for(&u.manifest, block_uuid)
            .ok_or_else(|| AppError::Internal {
                detail: "renamed block missing from manifest".into(),
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
    let session = lock_session(state)?;
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
    let session = lock_session(state)?;
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
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let output = bridge_read_block(&u.identity, &u.manifest, &block_uuid, false).map_err(
            |e| match e {
                FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
                    block_uuid_hex: uuid_hex,
                },
                other => AppError::from(other),
            },
        )?;
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

#[tauri::command]
pub async fn move_record(
    state: State<'_, Mutex<VaultSession>>,
    source_block_uuid_hex: String,
    target_block_uuid_hex: String,
    source_record_uuid_hex: String,
) -> Result<RecordRefDto, AppError> {
    move_record_impl(
        state.inner(),
        &source_block_uuid_hex,
        &target_block_uuid_hex,
        &source_record_uuid_hex,
    )
}

/// Move a live record from `source` to `target` under a fresh UUID
/// (copy-before-delete). Same-block moves are rejected here as
/// `InvalidArgument` (the bridge trusts its caller and does not check).
/// Returns the target block uuid + the record's fresh uuid.
pub fn move_record_impl(
    state: &Mutex<VaultSession>,
    source_block_uuid_hex: &str,
    target_block_uuid_hex: &str,
    source_record_uuid_hex: &str,
) -> Result<RecordRefDto, AppError> {
    if source_block_uuid_hex == target_block_uuid_hex {
        return Err(AppError::InvalidArgument {
            detail: "source and target block must differ".to_string(),
        });
    }
    let source_block_uuid = parse_uuid_16(source_block_uuid_hex)?;
    let target_block_uuid = parse_uuid_16(target_block_uuid_hex)?;
    let source_record_uuid = parse_uuid_16(source_record_uuid_hex)?;
    let new_record_uuid = new_uuid_16();
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_move_record(
            &u.identity,
            &u.manifest,
            source_block_uuid,
            target_block_uuid,
            source_record_uuid,
            new_record_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_save_error)?;
        Ok(RecordRefDto {
            block_uuid_hex: target_block_uuid_hex.to_string(),
            record_uuid_hex: hex::encode(new_record_uuid),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtos::FieldInputDto;

    fn text_field(name: &str, text: &str) -> FieldInputDto {
        FieldInputDto {
            name: name.to_string(),
            value: FieldValueDto::Text {
                text: text.to_string(),
            },
        }
    }

    #[test]
    fn dto_to_record_content_trims_field_names_for_storage() {
        let content = dto_to_record_content(RecordInputDto {
            record_type: "login".into(),
            tags: vec![],
            fields: vec![text_field("  user  ", "alice")],
        })
        .expect("valid draft");
        assert_eq!(content.fields.len(), 1);
        assert_eq!(content.fields[0].name, "user", "stored name is trimmed");
    }

    #[test]
    fn dto_to_record_content_rejects_names_that_collide_after_trim() {
        // "user" and " user " are distinct strings but the same field once
        // trimmed — the dedup must catch them so they can't both reach core.
        let err = dto_to_record_content(RecordInputDto {
            record_type: String::new(),
            tags: vec![],
            fields: vec![text_field("user", "a"), text_field(" user ", "b")],
        })
        .expect_err("duplicate-after-trim must be rejected");
        match err {
            AppError::InvalidFieldValue { field_name } => assert_eq!(field_name, "user"),
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    #[test]
    fn dto_to_record_content_rejects_whitespace_only_name() {
        let err = dto_to_record_content(RecordInputDto {
            record_type: String::new(),
            tags: vec![],
            fields: vec![text_field("   ", "v")],
        })
        .expect_err("whitespace-only name must be rejected");
        match err {
            AppError::InvalidFieldValue { field_name } => assert!(field_name.is_empty()),
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }
}
