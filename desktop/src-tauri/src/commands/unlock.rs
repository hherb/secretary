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

use crate::dtos::ManifestDto;
use crate::errors::AppError;
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
#[tauri::command]
pub async fn unlock_with_password(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    password: String,
) -> Result<ManifestDto, AppError> {
    // NOTE (D.1.1 deferred hardening): `password: String` is not
    // zeroize-typed. Tauri's IPC layer deserializes incoming string
    // arguments into a plain `String`, and we hand `password.as_bytes()`
    // to the bridge below. A future hardening pass should:
    //   1. Switch this argument to a `SecretString`-equivalent wrapper
    //      with a `Deserialize` impl that overwrites the source bytes.
    //   2. Audit the Tauri-side IPC buffer for residual password copies.
    // Logged here as a marker comment rather than #-issue because the
    // bridge surface that would consume the wrapper doesn't yet exist;
    // the change is co-dependent with a bridge-side API addition.
    unlock_with_password_impl(state.inner(), &folder_path, password.as_bytes())
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
    validate_vault_path(&folder, folder_path)?;

    let mut session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;

    session.unlock(&folder, password)?;

    session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(
            &u.manifest,
            u.pending_warnings.clone(),
        ))
    })
}

/// Pre-bridge sanity check on the user-picked folder path. Distinguishes
/// "folder is unreachable" (`VaultPathNotFound`) from "folder exists but
/// is empty / lacks vault files" (`VaultPathNotAVault`) so the UI affordance
/// is precise. The bridge would otherwise fold both into the generic
/// `FolderInvalid` → `Io` bucket.
fn validate_vault_path(folder: &Path, folder_path_str: &str) -> Result<(), AppError> {
    if !folder.exists() || !folder.is_dir() {
        return Err(AppError::VaultPathNotFound {
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
    fn regular_file_path_yields_vault_path_not_found() {
        let temp = tempdir().expect("tempdir");
        let file_path = temp.path().join("not-a-folder.txt");
        std::fs::write(&file_path, b"hi").expect("write fixture");
        let err = validate_vault_path(&file_path, file_path.to_str().expect("utf8")).unwrap_err();
        // A regular file is "not a vault folder" — the spec maps this to
        // VaultPathNotFound (the variant covers "does not exist or is not
        // readable as a folder"), not VaultPathNotAVault (which is reserved
        // for the "folder exists but is empty" case).
        assert!(
            matches!(err, AppError::VaultPathNotFound { .. }),
            "expected VaultPathNotFound, got {err:?}"
        );
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
}
