//! `unlock_with_password` command.
//!
//! Constructs path-aware `AppError::VaultPathNotFound` /
//! `AppError::VaultPathNotAVault` at the IPC boundary rather than relying
//! on the bridge's `FolderInvalid` → generic `Io` fallback. This is the
//! whole reason the two variants exist on `AppError`: they carry the
//! user-picked path so the UI can render the path-specific affordance
//! ("'/Users/h/Foo' doesn't exist" vs "'/Users/h/Foo' isn't a vault").
//!
//! Spec §6 (vault unlock) + §9 (error mapping).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tauri::State;

use crate::commands::shared::lock_session;
use crate::dtos::ManifestDto;
use crate::errors::AppError;
use crate::path_auth::{MatchMode, PathPurpose};
use crate::secret_arg::Password;
use crate::session::VaultSession;

/// Canonical files expected at the root of a vault folder. Their presence
/// is a necessary (not sufficient) condition — the bridge's
/// `open_vault_with_password` does the cryptographic check that proves
/// the folder is a real vault. Both must exist; missing either is a
/// `VaultPathNotAVault` from the IPC layer's perspective.
///
/// Pinned by the constants module's freshness tripwire if/when the on-disk
/// layout changes: these strings duplicate `secretary_core::vault`'s
/// canonical filenames, which is intentional — the desktop crate must NOT
/// re-export bridge internals, so duplication is the lesser evil compared
/// to a circular dep.
const VAULT_TOML_FILENAME: &str = "vault.toml";
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";

/// Tauri-side entry point. Thin delegating shell; logic lives in
/// [`unlock_with_password_impl`].
///
/// `password: Password` is the zeroize-typed IPC boundary (D.1.3 closed the
/// D.1.1 plain-`String` carry-forward). We hand `password.expose()` to the
/// `&[u8]`-taking impl; the `Password` (and its inner `SecretBytes`) zeroizes
/// when this shell returns.
#[tauri::command]
pub async fn unlock_with_password(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    password: Password,
) -> Result<ManifestDto, AppError> {
    unlock_with_password_impl(state.inner(), &folder_path, password.expose())
}

/// Testable core. Synchronous, no Tauri runtime needed. Validates the
/// folder path up front (so the UI gets a path-aware error before the
/// bridge spends Argon2id time on a hopeless input), then delegates to
/// `VaultSession::unlock` under the session mutex.
///
/// Returns the populated [`ManifestDto`] with `UnlockedSession::pending_warnings`
/// threaded through — the frontend uses these to render a banner alongside
/// the manifest view without an extra IPC round trip.
pub fn unlock_with_password_impl(
    state: &Mutex<VaultSession>,
    folder_path: &str,
    password: &[u8],
) -> Result<ManifestDto, AppError> {
    let folder = PathBuf::from(folder_path);
    // #353: the folder must be one the user picked via pick_vault_folder.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::VaultFolder, &folder, MatchMode::Exact) {
            return Err(AppError::PathNotApproved {
                path: folder_path.to_string(),
            });
        }
    }
    validate_vault_path(&folder, folder_path)?;

    let mut session = lock_session(state)?;

    session.unlock(&folder, password)?;

    session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(
            &u.manifest,
            u.pending_warnings.clone(),
        ))
    })
}

/// Pre-bridge sanity check on the user-picked folder path. Distinguishes
/// "path is unreachable" (`VaultPathNotFound`) from "path exists but
/// isn't a vault folder" (`VaultPathNotAVault`) so the UI affordance is
/// precise. The bridge would otherwise fold both into the generic
/// `FolderInvalid` → `Io` bucket.
///
/// UX rule: `VaultPathNotFound` means the OS can't see the path at all
/// (filesystem layer returned "no such file"). Anything that exists but
/// isn't openable as a vault folder — a regular file, a folder without
/// the canonical filenames — maps to `VaultPathNotAVault`. Otherwise the
/// frontend renders a misleading "doesn't exist" message for a path the
/// user just clicked in their file picker.
pub(crate) fn validate_vault_path(folder: &Path, folder_path_str: &str) -> Result<(), AppError> {
    if !folder.exists() {
        return Err(AppError::VaultPathNotFound {
            path: folder_path_str.to_string(),
        });
    }
    if !folder.is_dir() {
        return Err(AppError::VaultPathNotAVault {
            path: folder_path_str.to_string(),
        });
    }
    let has_vault_toml = folder.join(VAULT_TOML_FILENAME).is_file();
    let has_identity = folder.join(IDENTITY_BUNDLE_FILENAME).is_file();
    if !has_vault_toml || !has_identity {
        return Err(AppError::VaultPathNotAVault {
            path: folder_path_str.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Path-validation unit tests. The cryptographic unlock path is covered
    //! by `tests/ipc_integration.rs` against the golden vault.

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn nonexistent_folder_yields_vault_path_not_found() {
        let temp = tempdir().expect("tempdir");
        let missing = temp.path().join("does-not-exist");
        let err = validate_vault_path(&missing, missing.to_str().expect("utf8")).unwrap_err();
        match err {
            AppError::VaultPathNotFound { path } => {
                assert_eq!(path, missing.to_str().expect("utf8"));
            }
            other => panic!("expected VaultPathNotFound, got {other:?}"),
        }
    }

    #[test]
    fn regular_file_path_yields_vault_path_not_a_vault() {
        let temp = tempdir().expect("tempdir");
        let file_path = temp.path().join("not-a-folder.txt");
        std::fs::write(&file_path, b"hi").expect("write fixture");
        let err = validate_vault_path(&file_path, file_path.to_str().expect("utf8")).unwrap_err();
        // The path exists — the OS can see it — so `VaultPathNotFound`
        // would render a misleading "doesn't exist" message. The file
        // simply isn't a vault folder, which maps to `VaultPathNotAVault`.
        match err {
            AppError::VaultPathNotAVault { path } => {
                assert_eq!(path, file_path.to_str().expect("utf8"));
            }
            other => panic!("expected VaultPathNotAVault, got {other:?}"),
        }
    }

    #[test]
    fn empty_folder_yields_vault_path_not_a_vault() {
        let temp = tempdir().expect("tempdir");
        let err =
            validate_vault_path(temp.path(), temp.path().to_str().expect("utf8")).unwrap_err();
        match err {
            AppError::VaultPathNotAVault { path } => {
                assert_eq!(path, temp.path().to_str().expect("utf8"));
            }
            other => panic!("expected VaultPathNotAVault, got {other:?}"),
        }
    }

    #[test]
    fn folder_with_only_vault_toml_yields_not_a_vault() {
        // Half a vault is not a vault — identity.bundle.enc is also required.
        let temp = tempdir().expect("tempdir");
        std::fs::write(temp.path().join(VAULT_TOML_FILENAME), b"[v1]\n").expect("write");
        let err =
            validate_vault_path(temp.path(), temp.path().to_str().expect("utf8")).unwrap_err();
        assert!(
            matches!(err, AppError::VaultPathNotAVault { .. }),
            "expected VaultPathNotAVault, got {err:?}"
        );
    }

    #[test]
    fn folder_with_both_files_passes_validation() {
        let temp = tempdir().expect("tempdir");
        std::fs::write(temp.path().join(VAULT_TOML_FILENAME), b"[v1]\n").expect("write");
        std::fs::write(temp.path().join(IDENTITY_BUNDLE_FILENAME), b"sealed").expect("write");
        validate_vault_path(temp.path(), temp.path().to_str().expect("utf8"))
            .expect("validation passes when both canonical files exist");
    }

    #[test]
    fn unapproved_folder_is_rejected_before_validation() {
        let temp = tempdir().expect("tempdir");
        let state = std::sync::Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = unlock_with_password_impl(&state, temp.path().to_str().unwrap(), b"pw")
            .expect_err("unapproved");
        assert!(
            matches!(err, AppError::PathNotApproved { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn approved_folder_passes_the_gate_and_reaches_validation() {
        use crate::path_auth::{canonicalize_for_auth, PathPurpose};
        // An empty temp dir is approved but is not a vault: passing the gate
        // means we reach validate_vault_path, which returns VaultPathNotAVault.
        let temp = tempdir().expect("tempdir");
        let state = std::sync::Mutex::new(VaultSession::new(std::env::temp_dir()));
        state.lock().unwrap().approve_path(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(temp.path()).unwrap(),
        );
        let err = unlock_with_password_impl(&state, temp.path().to_str().unwrap(), b"pw")
            .expect_err("not a vault");
        assert!(
            matches!(err, AppError::VaultPathNotAVault { .. }),
            "got {err:?}"
        );
    }
}
