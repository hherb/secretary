//! uniffi namespace fns for this device's sync-state directory (#746):
//! `set_platform_state_dir` and `reset_sync_state_and_open_with_password`.
//! The logic lives in `secretary-ffi-bridge`; this layer adapts argument
//! types and translates bridge errors.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::errors::VaultError;
use crate::wrappers::identity::UnlockedIdentity;
use crate::wrappers::vault::{OpenVaultManifest, OpenVaultOutput};

/// Make `state_dir` the directory the bridge's opens read this device's §10
/// baseline from. Android calls it once at startup with the dir it passes to
/// every sync call; desktop and iOS keep the default. uniffi-projected (#746).
///
/// # Errors
/// [`VaultError::SyncFailed`] if a different directory is already set.
pub fn set_platform_state_dir(state_dir: String) -> Result<(), VaultError> {
    secretary_ffi_bridge::set_platform_state_dir(Path::new(&state_dir)).map_err(VaultError::from)
}

/// Open with the master password after deleting this vault's sync state in
/// `state_dir`, so the on-disk manifest is accepted. The apps offer it only
/// from `VaultError::RollbackDetected`, after the user confirms.
/// uniffi-projected (#746).
///
/// `password` is a zero-copy borrow of the foreign buffer (`[ByRef] bytes`,
/// #307); the bridge wraps its one copy in `SecretBytes`.
///
/// # Errors
/// [`VaultError::FolderInvalid`] for a non-UTF-8 `folder_path`, else the
/// bridge `reset_sync_state_and_open_with_password_in` errors.
pub fn reset_sync_state_and_open_with_password(
    state_dir: String,
    folder_path: Vec<u8>,
    password: &[u8],
) -> Result<OpenVaultOutput, VaultError> {
    let folder = std::str::from_utf8(&folder_path)
        .map(PathBuf::from)
        .map_err(|_| VaultError::FolderInvalid {
            detail: "folder path contained invalid UTF-8".to_string(),
        })?;
    let out = secretary_ffi_bridge::reset_sync_state_and_open_with_password_in(
        Path::new(&state_dir),
        &folder,
        password,
    )
    .map_err(VaultError::from)?;
    Ok(OpenVaultOutput {
        identity: Arc::new(UnlockedIdentity(out.identity)),
        manifest: Arc::new(OpenVaultManifest(out.manifest)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_with_an_invalid_utf8_path_is_folder_invalid() {
        match reset_sync_state_and_open_with_password(
            "/nonexistent".to_string(),
            b"\xff\xfe".to_vec(),
            b"pw",
        ) {
            Err(VaultError::FolderInvalid { .. }) => {}
            Err(other) => panic!("expected FolderInvalid, got {other:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }
}
