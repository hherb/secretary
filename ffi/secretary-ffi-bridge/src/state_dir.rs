//! The directory this platform keeps per-vault sync state in (#746).
//!
//! Every bridge path that reads or writes this device's §10 baseline without
//! an explicit `state_dir` (the open-time rollback check, repair's clock gate,
//! the password sync passes, `sync_status`) resolves it here. By default that
//! is [`secretary_cli::state::default_state_dir`], which is right on desktop
//! and iOS (both apps keep their state in `<data dir>/secretary/sync`).
//!
//! Android has no such data dir (`$HOME` is not the app's storage), and its
//! app keeps sync state under `filesDir/sync-state`. Until #746 the open check
//! therefore read a directory Android never wrote, and §10 was inactive at
//! open there. The app now calls [`set_platform_state_dir`] once at startup.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::error::detail;
use crate::error::FfiVaultError;

/// Set at most once per process, by a platform whose state dir is not the
/// `dirs` default.
static OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Make `dir` this process's sync-state directory. Call it before the first
/// open. Setting the same path again is a no-op (an Android activity can be
/// recreated); setting a different one is refused, since paths already
/// resolved would disagree with later ones.
///
/// # Errors
///
/// [`FfiVaultError::SyncFailed`] if a different directory is already set.
pub fn set_platform_state_dir(dir: &Path) -> Result<(), FfiVaultError> {
    if OVERRIDE.get_or_init(|| dir.to_path_buf()) == dir {
        Ok(())
    } else {
        Err(FfiVaultError::SyncFailed {
            detail: detail::literal("the sync state directory is already set to a different path"),
        })
    }
}

/// The override if one was set, else the `dirs` default. `None` only on a
/// platform with neither, where the open check is skipped (see
/// [`crate::vault`]'s rollback-resistance docs).
pub(crate) fn platform_state_dir() -> Option<PathBuf> {
    OVERRIDE
        .get()
        .cloned()
        .or_else(secretary_cli::state::default_state_dir)
}
