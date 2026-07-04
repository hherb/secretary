//! Backend-mediated file/folder pickers (#353).
//!
//! The webview no longer opens dialogs (its `dialog:allow-open` capability is
//! removed). Instead it calls these commands; each opens a native dialog from
//! the Rust side, canonicalizes the chosen path, and records it in the
//! matching `PathPurpose` slot on `VaultSession`. The path-taking commands
//! then validate their argument against that slot. The native dialog call is
//! isolated in the thin `#[tauri::command]` shells; the canonicalize-and-store
//! core (`pick_into_slot_impl`) is unit-tested.

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::State;
use tauri_plugin_dialog::DialogExt;

use crate::commands::shared::lock_session;
use crate::errors::AppError;
use crate::path_auth::{canonicalize_for_auth, PathPurpose};
use crate::session::VaultSession;

/// Canonicalize the picked path, store it in `purpose`'s slot, and return the
/// canonical display string. `None` (user cancelled) leaves state untouched.
pub fn pick_into_slot_impl(
    state: &Mutex<VaultSession>,
    purpose: PathPurpose,
    picked: Option<PathBuf>,
) -> Result<Option<String>, AppError> {
    let Some(path) = picked else {
        return Ok(None);
    };
    let canonical = canonicalize_for_auth(&path).ok_or_else(|| AppError::Io {
        detail: format!("could not canonicalize picked path {path:?}"),
    })?;
    let display = canonical.to_string_lossy().into_owned();
    let mut session = lock_session(state)?;
    session.approve_path(purpose, canonical);
    Ok(Some(display))
}

/// Native folder picker for the vault folder (unlock). Stores the choice in
/// the `VaultFolder` slot. Vault creation uses [`pick_create_folder`] — a
/// distinct purpose, so an unlock pick never authorizes a create (#378).
#[tauri::command]
pub async fn pick_vault_folder(
    app: tauri::AppHandle,
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .set_title("Choose vault folder")
        .blocking_pick_folder()
        .and_then(|fp| fp.into_path().ok());
    pick_into_slot_impl(state.inner(), PathPurpose::VaultFolder, picked)
}

/// Native folder picker for the create wizard (#378). Stores the choice in
/// the `CreateParent` slot, which `create_vault` / `probe_create_target`
/// consult with `Containment` (the wizard may create a subfolder inside it).
/// Deliberately NOT the `VaultFolder` slot: sharing it would let a pick made
/// to *unlock* a vault authorize a *create* in one of its subfolders.
#[tauri::command]
pub async fn pick_create_folder(
    app: tauri::AppHandle,
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .set_title("Choose a folder to create your vault in")
        .blocking_pick_folder()
        .and_then(|fp| fp.into_path().ok());
    pick_into_slot_impl(state.inner(), PathPurpose::CreateParent, picked)
}

/// Native file picker (`.card` filter) for contact-card import. Stores the
/// choice in the `ContactCard` slot.
#[tauri::command]
pub async fn pick_contact_card(
    app: tauri::AppHandle,
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .add_filter("Contact card", &["card"])
        .set_title("Import a contact card")
        .blocking_pick_file()
        .and_then(|fp| fp.into_path().ok());
    pick_into_slot_impl(state.inner(), PathPurpose::ContactCard, picked)
}

/// Native folder picker for owner-card export. Stores the choice in the
/// `ExportDir` slot.
#[tauri::command]
pub async fn pick_export_dir(
    app: tauri::AppHandle,
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .set_title("Choose a folder to export your card to")
        .blocking_pick_folder()
        .and_then(|fp| fp.into_path().ok());
    pick_into_slot_impl(state.inner(), PathPurpose::ExportDir, picked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_auth::MatchMode;
    use tempfile::tempdir;

    #[test]
    fn cancel_returns_none_and_stores_nothing() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let out = pick_into_slot_impl(&state, PathPurpose::VaultFolder, None).unwrap();
        assert!(out.is_none());
        // "stores nothing": the cancel path must not have mutated any slot.
        let session = state.lock().unwrap();
        assert!(!session.is_path_approved(
            PathPurpose::VaultFolder,
            std::path::Path::new("/tmp"),
            MatchMode::Exact,
        ));
    }

    #[test]
    fn pick_stores_canonical_path_in_the_slot() {
        let dir = tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let out = pick_into_slot_impl(
            &state,
            PathPurpose::ContactCard,
            Some(dir.path().to_path_buf()),
        )
        .unwrap();
        assert!(out.is_some());
        let session = state.lock().unwrap();
        assert!(session.is_path_approved(PathPurpose::ContactCard, dir.path(), MatchMode::Exact));
        // Isolation: it did not authorize a different purpose.
        assert!(!session.is_path_approved(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }
}
