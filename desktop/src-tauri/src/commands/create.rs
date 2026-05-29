//! `create_vault` + `probe_create_target` commands.
//!
//! The first WRITE path in Sub-project D (spec §6). `create_vault` wraps
//! core's atomic orchestrator (`vault::orchestrators::create_vault`), which
//! writes the four canonical files atomically and returns the 24-word
//! recovery `Mnemonic`. The command is session-stateless: it neither reads
//! nor mutates the unlocked session. After create the frontend returns to
//! Unlock (no auto-open), so no live identity/manifest handle is retained.
//!
//! `probe_create_target` is a read-only helper that drives the wizard's
//! empty-folder check + "create a subfolder" offer without granting the
//! WebView raw filesystem-read capability.

use std::path::Path;

use rand_core::{CryptoRng, OsRng, RngCore};

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault;

use crate::auto_lock::now_ms;
use crate::dtos::{CreateTargetProbeDto, CreateVaultDto};
use crate::errors::AppError;
use crate::secret_arg::Password;

/// Tauri-side entry point for vault creation. Thin shell; logic in
/// [`create_vault_impl`]. Uses `OsRng` + the wall-clock `now_ms()`.
#[tauri::command]
pub async fn create_vault(
    folder_path: String,
    display_name: String,
    password: Password,
) -> Result<CreateVaultDto, AppError> {
    create_vault_impl(
        &folder_path,
        &display_name,
        password.as_secret_bytes(),
        now_ms(),
        &mut OsRng,
    )
}

/// Testable core. `created_at_ms` + `rng` are injected so integration tests
/// are hermetic (runtime-random `OsRng`, no hardcoded crypto value).
///
/// Steps (spec §6):
/// 1. `create_dir_all` the target (idempotent; supports the subfolder flow).
/// 2. Own empty-check → typed [`AppError::VaultFolderNotEmpty`] BEFORE any
///    core call (never string-match core's `Io`).
/// 3. `orchestrators::create_vault` with the hardcoded v1 KDF default; any
///    `VaultError` → [`AppError::VaultCreateFailed`] (detail logged, stripped
///    at the seam).
/// 4. Copy the phrase into the DTO; the `Mnemonic` zeroizes on drop.
pub fn create_vault_impl(
    folder_path: &str,
    display_name: &str,
    password: &SecretBytes,
    created_at_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreateVaultDto, AppError> {
    let folder = Path::new(folder_path);

    std::fs::create_dir_all(folder).map_err(|e| AppError::Io {
        detail: format!("failed to create vault folder {folder_path}: {e}"),
    })?;

    let non_empty = std::fs::read_dir(folder)
        .map_err(|e| AppError::Io {
            detail: format!("failed to read vault folder {folder_path}: {e}"),
        })?
        .next()
        .is_some();
    if non_empty {
        return Err(AppError::VaultFolderNotEmpty {
            path: folder_path.to_string(),
        });
    }

    let mnemonic = vault::create_vault(
        folder,
        password,
        display_name,
        Argon2idParams::V1_DEFAULT,
        created_at_ms,
        rng,
    )
    .map_err(|e| {
        tracing::warn!(?e, "vault create failed");
        AppError::VaultCreateFailed {
            detail: format!("{e}"),
        }
    })?;

    Ok(CreateVaultDto {
        mnemonic: mnemonic.phrase().to_string(),
    })
    // `mnemonic` drops here → core `Mnemonic` zeroizes phrase + entropy.
}

/// Tauri-side entry point for the read-only create-target probe.
#[tauri::command]
pub async fn probe_create_target(folder_path: String) -> Result<CreateTargetProbeDto, AppError> {
    Ok(probe_create_target_impl(&folder_path))
}

/// Pure probe: does the path exist, and (if a directory) is it empty? A
/// non-existent path reports `exists:false, is_empty:false`; the wizard treats
/// "will be created fresh" separately. Read-only; no secrets.
pub fn probe_create_target_impl(folder_path: &str) -> CreateTargetProbeDto {
    let folder = Path::new(folder_path);
    let exists = folder.exists();
    let is_empty = exists
        && folder.is_dir()
        && std::fs::read_dir(folder)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false);
    CreateTargetProbeDto { exists, is_empty }
}
