//! Contacts IPC commands (D.1.6 – D.1.9): list_contacts / import_contact /
//! share_block / export_contact_card / delete_contact_card / block_recipients /
//! list_contact_blocks.
//! Thin shells over the bridge primitives (spec §6). `import_contact` reads the
//! user-chosen `.card` file at the desktop edge; the bridge takes bytes.
//!
//! Same split as [`super::delete`]: each `#[tauri::command]` wrapper extracts
//! state + args and delegates to a testable `*_impl` that locks the session and
//! runs the bridge call inside [`VaultSession::with_unlocked`]. `lock_session`
//! is defined locally here, mirroring the local copy in `delete.rs` (it is not
//! yet hoisted into `commands::shared`; see issue #170).

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::{
    block_recipients as bridge_block_recipients, contact_blocks as bridge_contact_blocks,
    delete_contact_card as bridge_delete, enumerate_contact_cards as bridge_enumerate,
    import_contact_card as bridge_import, owner_card_export as bridge_owner_card_export,
    share_block_to as bridge_share_block_to,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::parse_uuid_16;
use crate::dtos::{
    BlockSummaryDto, ContactSummaryDto, ExportedCardDto, ListContactsDto, RecipientDto,
};
use crate::errors::{map_ffi_error, AppError};
use crate::session::VaultSession;

/// Lock the session mutex, folding poison to `Internal`. Shared by every
/// `*_impl` below. Local copy of the `delete.rs` helper (not yet hoisted into
/// `commands::shared`; issue #170).
fn lock_session(
    state: &Mutex<VaultSession>,
) -> Result<std::sync::MutexGuard<'_, VaultSession>, AppError> {
    state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })
}

#[tauri::command]
pub async fn list_contacts(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<ListContactsDto, AppError> {
    list_contacts_impl(state.inner())
}

pub fn list_contacts_impl(state: &Mutex<VaultSession>) -> Result<ListContactsDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let (summaries, unreadable) = bridge_enumerate(&u.manifest).map_err(map_ffi_error)?;
        Ok(ListContactsDto {
            contacts: summaries.iter().map(ContactSummaryDto::from).collect(),
            unreadable_count: unreadable as u32,
        })
    })
}

#[tauri::command]
pub async fn import_contact(
    state: State<'_, Mutex<VaultSession>>,
    card_path: String,
) -> Result<ContactSummaryDto, AppError> {
    import_contact_impl(state.inner(), &card_path)
}

pub fn import_contact_impl(
    state: &Mutex<VaultSession>,
    card_path: &str,
) -> Result<ContactSummaryDto, AppError> {
    let bytes = std::fs::read(card_path).map_err(|e| AppError::Io {
        detail: format!("read contact card file {card_path:?}: {e}"),
    })?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let summary = bridge_import(&u.manifest, &bytes).map_err(map_ffi_error)?;
        Ok(ContactSummaryDto::from(&summary))
    })
}

#[tauri::command]
pub async fn share_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    recipient_uuid_hex: String,
) -> Result<(), AppError> {
    share_block_impl(state.inner(), &block_uuid_hex, &recipient_uuid_hex)
}

pub fn share_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    recipient_uuid_hex: &str,
) -> Result<(), AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let recipient_uuid = parse_uuid_16(recipient_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_share_block_to(
            &u.identity,
            &u.manifest,
            block_uuid,
            recipient_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_ffi_error)?;
        Ok(())
    })
}

#[tauri::command]
pub async fn export_contact_card(
    state: State<'_, Mutex<VaultSession>>,
    dest_dir: String,
) -> Result<ExportedCardDto, AppError> {
    export_contact_card_impl(state.inner(), &dest_dir)
}

pub fn export_contact_card_impl(
    state: &Mutex<VaultSession>,
    dest_dir: &str,
) -> Result<ExportedCardDto, AppError> {
    // Collect the (public) card bytes under the lock, then release it before
    // the external write — mirroring import_contact_impl, which keeps host
    // filesystem I/O outside the session lock so a slow destination can't
    // block other commands (incl. the auto-lock timer).
    let (file_name, bytes) = {
        let session = lock_session(state)?;
        session.with_unlocked(|u| bridge_owner_card_export(&u.manifest).map_err(map_ffi_error))?
    };
    let path = std::path::Path::new(dest_dir).join(&file_name);
    // The owner card is PUBLIC material; the destination is a user-chosen
    // external folder. Overwriting a prior export of the same card is benign
    // (idempotent self-card). Native Rust write — no JS fs capability needed.
    std::fs::write(&path, &bytes).map_err(|e| AppError::Io {
        detail: format!("write exported card to {path:?}: {e}"),
    })?;
    Ok(ExportedCardDto {
        path: path.to_string_lossy().into_owned(),
    })
}

#[tauri::command]
pub async fn delete_contact_card(
    state: State<'_, Mutex<VaultSession>>,
    contact_uuid_hex: String,
) -> Result<(), AppError> {
    delete_contact_card_impl(state.inner(), &contact_uuid_hex)
}

pub fn delete_contact_card_impl(
    state: &Mutex<VaultSession>,
    contact_uuid_hex: &str,
) -> Result<(), AppError> {
    let contact_uuid = parse_uuid_16(contact_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_delete(&u.manifest, contact_uuid).map_err(map_ffi_error)?;
        Ok(())
    })
}

#[tauri::command]
pub async fn block_recipients(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<Vec<RecipientDto>, AppError> {
    block_recipients_impl(state.inner(), &block_uuid_hex)
}

pub fn block_recipients_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
) -> Result<Vec<RecipientDto>, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let rs = bridge_block_recipients(&u.manifest, block_uuid).map_err(map_ffi_error)?;
        Ok(rs.iter().map(RecipientDto::from).collect())
    })
}

#[tauri::command]
pub async fn list_contact_blocks(
    state: State<'_, Mutex<VaultSession>>,
    contact_uuid_hex: String,
) -> Result<Vec<BlockSummaryDto>, AppError> {
    list_contact_blocks_impl(state.inner(), &contact_uuid_hex)
}

pub fn list_contact_blocks_impl(
    state: &Mutex<VaultSession>,
    contact_uuid_hex: &str,
) -> Result<Vec<BlockSummaryDto>, AppError> {
    let contact_uuid = parse_uuid_16(contact_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let blocks = bridge_contact_blocks(&u.manifest, contact_uuid).map_err(map_ffi_error)?;
        Ok(blocks.iter().map(BlockSummaryDto::from).collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_contacts_locked_session_is_not_unlocked() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = list_contacts_impl(&state).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked));
    }

    #[test]
    fn share_block_locked_session_is_not_unlocked() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        // 16-byte hex UUIDs so parse_uuid_16 succeeds and we reach the lock path.
        let uuid_hex = "00112233445566778899aabbccddeeff";
        let err = share_block_impl(&state, uuid_hex, uuid_hex).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked));
    }

    #[test]
    fn block_recipients_locked_session_is_not_unlocked() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        // 16-byte hex UUID so parse_uuid_16 succeeds and we reach the lock path.
        let uuid_hex = "00112233445566778899aabbccddeeff";
        let err = block_recipients_impl(&state, uuid_hex).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked));
    }

    #[test]
    fn list_contact_blocks_locked_session_is_not_unlocked() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        // 16-byte hex UUID so parse_uuid_16 succeeds and we reach the lock path.
        let uuid_hex = "00112233445566778899aabbccddeeff";
        let err = list_contact_blocks_impl(&state, uuid_hex).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked));
    }
}
