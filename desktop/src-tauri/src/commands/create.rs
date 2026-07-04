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
use std::sync::Mutex;

use rand_core::{CryptoRng, OsRng, RngCore};
use tauri::State;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault;

use crate::auto_lock::now_ms;
use crate::commands::shared::lock_session;
use crate::dtos::{CreateTargetProbeDto, CreateVaultDto};
use crate::errors::AppError;
use crate::path_auth::{canonicalize_for_auth, MatchMode, PathPurpose};
use crate::secret_arg::Password;
use crate::session::VaultSession;

/// Tauri-side entry point for vault creation. Thin shell; logic in
/// [`create_vault_impl`]. Uses `OsRng` + the wall-clock `now_ms()`.
#[tauri::command]
pub async fn create_vault(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    display_name: String,
    password: Password,
) -> Result<CreateVaultDto, AppError> {
    create_vault_impl(
        state.inner(),
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
    state: &Mutex<VaultSession>,
    folder_path: &str,
    display_name: &str,
    password: &SecretBytes,
    created_at_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreateVaultDto, AppError> {
    let folder = Path::new(folder_path);
    // #353/#378: the target must be the folder the user picked FOR CREATION
    // (via `pick_create_folder` → the `CreateParent` slot) or a subfolder of
    // it. Deliberately not the `VaultFolder` slot: an unlock pick must never
    // authorize a create.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::CreateParent, folder, MatchMode::Containment) {
            return Err(AppError::PathNotApproved {
                path: folder_path.to_string(),
            });
        }
    }

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

    // #353/#378: bind the just-created folder as the approved VaultFolder so
    // the follow-on unlock passes its `Exact`-match gate. The create wizard
    // auto-navigates to Unlock pre-filled with THIS path; since #378 the
    // create pick lives in the separate `CreateParent` slot, so without this
    // backend-initiated approval the `Exact` unlock of the created folder
    // would fail `PathNotApproved`. Approving exactly the created vault (not
    // the picked parent) keeps the unlock slot least-privilege until the
    // session locks. `folder` now exists (create succeeded) and the
    // top-of-fn Containment gate already proved it canonicalizes, so `Some`
    // is guaranteed here.
    if let Some(canonical) = canonicalize_for_auth(folder) {
        lock_session(state)?.approve_path(PathPurpose::VaultFolder, canonical);
    }

    Ok(CreateVaultDto {
        mnemonic: mnemonic.phrase().to_string(),
    })
    // `mnemonic` drops here → core `Mnemonic` zeroizes phrase + entropy.
}

/// Tauri-side entry point for the read-only create-target probe.
#[tauri::command]
pub async fn probe_create_target(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
) -> Result<CreateTargetProbeDto, AppError> {
    probe_create_target_impl(state.inner(), &folder_path)
}

/// Pure probe: does the path exist, and (if a directory) is it empty? A
/// non-existent path reports `exists:false, is_empty:false`; the wizard treats
/// "will be created fresh" separately. Read-only; no secrets.
pub fn probe_create_target_impl(
    state: &Mutex<VaultSession>,
    folder_path: &str,
) -> Result<CreateTargetProbeDto, AppError> {
    let folder = Path::new(folder_path);
    // #353/#378: only probe a path the user picked for creation (or a
    // subfolder of it). Same `CreateParent` gate as `create_vault_impl`.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::CreateParent, folder, MatchMode::Containment) {
            return Err(AppError::PathNotApproved {
                path: folder_path.to_string(),
            });
        }
    }
    let exists = folder.exists();
    let is_empty = exists
        && folder.is_dir()
        && std::fs::read_dir(folder)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false);
    Ok(CreateTargetProbeDto { exists, is_empty })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_auth::{canonicalize_for_auth, PathPurpose};
    use crate::session::VaultSession;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Random throwaway password bytes for gate-rejection tests where the
    /// password is never reached (the approval / empty-folder check rejects
    /// before any crypto). A literal here trips CodeQL's hardcoded-credential
    /// heuristic.
    fn any_password() -> [u8; 16] {
        let mut pw = [0u8; 16];
        OsRng.fill_bytes(&mut pw);
        pw
    }

    #[test]
    fn probe_rejects_unapproved_path() {
        let temp = tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = probe_create_target_impl(&state, temp.path().to_str().unwrap())
            .expect_err("unapproved");
        assert!(
            matches!(err, AppError::PathNotApproved { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn probe_allows_approved_path() {
        let temp = tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        state.lock().unwrap().approve_path(
            PathPurpose::CreateParent,
            canonicalize_for_auth(temp.path()).unwrap(),
        );
        let dto = probe_create_target_impl(&state, temp.path().to_str().unwrap()).unwrap();
        assert!(dto.exists && dto.is_empty);
    }

    /// #378 regression: an *unlock* pick (`VaultFolder` slot) must not
    /// authorize create/probe — they consult the `CreateParent` slot only.
    #[test]
    fn unlock_approval_does_not_authorize_create_or_probe() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("sub-vault");
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        state.lock().unwrap().approve_path(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(temp.path()).unwrap(),
        );

        let err = probe_create_target_impl(&state, target.to_str().unwrap())
            .expect_err("probe must not ride an unlock approval");
        assert!(
            matches!(err, AppError::PathNotApproved { .. }),
            "got {err:?}"
        );

        let err = create_vault_impl(
            &state,
            target.to_str().unwrap(),
            "My Vault",
            &secretary_core::crypto::secret::SecretBytes::from(any_password().to_vec()),
            0,
            &mut rand_core::OsRng,
        )
        .expect_err("create must not ride an unlock approval");
        assert!(
            matches!(err, AppError::PathNotApproved { .. }),
            "got {err:?}"
        );
        assert!(
            !target.exists(),
            "must not create the folder for an unapproved path"
        );
    }

    #[test]
    fn create_rejects_unapproved_path_and_creates_nothing() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("new-vault");
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = create_vault_impl(
            &state,
            target.to_str().unwrap(),
            "My Vault",
            &secretary_core::crypto::secret::SecretBytes::from(any_password().to_vec()),
            0,
            &mut rand_core::OsRng,
        )
        .expect_err("unapproved");
        assert!(
            matches!(err, AppError::PathNotApproved { .. }),
            "got {err:?}"
        );
        assert!(
            !target.exists(),
            "must not create the folder for an unapproved path"
        );
    }

    #[test]
    fn create_allows_approved_subfolder_then_reaches_empty_check() {
        // Approve the PARENT; the create target is a SUBFOLDER (Containment).
        // Only Containment (not Exact) will authorize the subfolder.
        // The subfolder is non-empty so create hits VaultFolderNotEmpty
        // (proving the gate passed without crypto) rather than PathNotApproved.
        let parent = tempdir().unwrap();
        let subfolder = parent.path().join("sub");
        std::fs::create_dir(&subfolder).unwrap();
        // Make the subfolder non-empty so the impl fails at the empty-check
        // (proving the Containment gate passed without doing crypto).
        std::fs::write(subfolder.join("marker"), b"x").unwrap();

        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        state.lock().unwrap().approve_path(
            PathPurpose::CreateParent,
            canonicalize_for_auth(parent.path()).unwrap(),
        );

        let err = create_vault_impl(
            &state,
            subfolder.to_str().unwrap(),
            "My Vault",
            &secretary_core::crypto::secret::SecretBytes::from(any_password().to_vec()),
            0,
            &mut rand_core::OsRng,
        )
        .expect_err("subfolder not empty");
        assert!(
            matches!(err, AppError::VaultFolderNotEmpty { .. }),
            "got {err:?}"
        );
    }
}
