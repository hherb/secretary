//! `get_settings` + `set_settings` commands. The actual bounds validation
//! and atomic write live in [`crate::settings::save_to_vault`] (Task 3);
//! these handlers just bridge IPC types to/from the bridge call.
//!
//! Both require the session to be unlocked — `get_settings` returns
//! `AppError::NotUnlocked` rather than handing back `Settings::default()`
//! to make the contract explicit at the wire format. (The session's own
//! `current_settings()` returns defaults defensively while locked; that's
//! a Rust-internal affordance, not a UI contract.)

use std::sync::Mutex;

use tauri::State;

use crate::commands::shared::lock_session;
use crate::dtos::{SettingsDto, SettingsInput};
use crate::errors::AppError;
use crate::session::VaultSession;
use crate::settings::Settings;

#[tauri::command]
pub async fn get_settings(state: State<'_, Mutex<VaultSession>>) -> Result<SettingsDto, AppError> {
    get_settings_impl(state.inner())
}

#[tauri::command]
pub async fn set_settings(
    state: State<'_, Mutex<VaultSession>>,
    settings: SettingsInput,
) -> Result<(), AppError> {
    set_settings_impl(state.inner(), &settings)
}

/// Testable core for `get_settings`. Explicit `NotUnlocked` error on the
/// locked path rather than silently returning defaults.
pub fn get_settings_impl(state: &Mutex<VaultSession>) -> Result<SettingsDto, AppError> {
    let session = lock_session(state)?;
    if !session.is_unlocked() {
        return Err(AppError::NotUnlocked);
    }
    Ok(SettingsDto::from(&session.current_settings()))
}

/// Testable core for `set_settings`. Delegates to
/// [`VaultSession::set_settings`] which validates bounds (returning
/// `AppError::SettingsOutOfRange` on out-of-range input) before writing
/// the settings block atomically.
pub fn set_settings_impl(
    state: &Mutex<VaultSession>,
    input: &SettingsInput,
) -> Result<(), AppError> {
    let mut session = lock_session(state)?;
    let new_settings = Settings::from(input);
    session.set_settings(&new_settings)
}
