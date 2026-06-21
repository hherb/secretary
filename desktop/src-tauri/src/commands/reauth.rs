//! `verify_password` command — write re-auth presence proof.
//!
//! Re-runs `open_vault_with_password` against the currently-open vault's
//! folder and immediately drops the handle. Returns `Ok(())` if the password
//! opens the vault, `AppError::WrongPassword` if not (the bridge's
//! decryption-failure collapse already maps to that), `AppError::NotUnlocked`
//! if no vault is open. No new crypto: this is the same authoritative check
//! the unlock path performs. The transient handle's `Drop` runs the bridge's
//! zeroize-on-drop discipline.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::vault::open_vault_with_password;

use crate::commands::shared::lock_session;
use crate::errors::AppError;
use crate::secret_arg::Password;
use crate::session::VaultSession;

/// Tauri entry point. Thin shell; logic in [`verify_password_impl`].
/// `password.expose()` feeds the `&[u8]`; `Password` zeroizes on return.
#[tauri::command]
pub async fn verify_password(
    state: State<'_, Mutex<VaultSession>>,
    password: Password,
) -> Result<(), AppError> {
    verify_password_impl(state.inner(), password.expose())
}

/// Testable core. Resolves the open vault's folder (NotUnlocked if locked),
/// then re-opens it with the supplied password and drops the handle.
///
/// The session mutex is released BEFORE the ~1-2 s Argon2id so a concurrent
/// write or auto-lock is not blocked for the duration of the verify.
pub fn verify_password_impl(state: &Mutex<VaultSession>, password: &[u8]) -> Result<(), AppError> {
    let folder = {
        let session = lock_session(state)?;
        session.vault_folder().ok_or(AppError::NotUnlocked)?
    }; // ← mutex dropped here, before Argon2id

    // open_vault_with_password performs the full Argon2id + unlock + manifest
    // verify. We discard the handles — a successful open IS the proof. The
    // bridge's From<FfiVaultError> collapses any decryption failure to
    // AppError::WrongPassword (threat-model §13 info-leak prevention).
    let _handle = open_vault_with_password(&folder, password).map_err(AppError::from)?;
    Ok(())
    // _handle drops here → bridge zeroize-on-drop wipes identity + manifest.
}
