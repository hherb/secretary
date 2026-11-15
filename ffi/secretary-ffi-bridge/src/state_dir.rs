//! The directory this platform keeps per-vault sync state in (#746).
//!
//! Every bridge function that reads or writes this device's §10 baseline
//! without an explicit `state_dir` resolves it here: the opens' rollback
//! check, repair and its preview, every sync pass (password and
//! `*_with_session`), `refresh_manifest`, `sync_status` and the reset. By
//! default that is [`secretary_cli::state::default_state_dir`], which is
//! where the desktop app keeps its state (`<data dir>/secretary/sync`). The
//! iOS and macOS apps set it at startup to the directory they pass to their
//! own sync calls, so the two cannot drift apart.
//!
//! Android has no such data dir (`$HOME` is not the app's storage), and its
//! app keeps sync state under `filesDir/sync-state`. Until #746 the open check
//! therefore read a directory Android never wrote, and §10 was inactive at
//! open there. The app now calls [`set_platform_state_dir`] once at startup.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::error::detail;
use crate::error::FfiVaultError;

/// This process's sync-state dir, fixed by the first of
/// [`set_platform_state_dir`] or [`platform_state_dir`]. Fixing it on the first
/// READ too is what makes a late set fail loudly: an open that ran before the
/// set has already used the default.
static RESOLVED: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Make `dir` this process's sync-state directory. Call it before the first
/// open. Setting the same path again is a no-op (an Android activity can be
/// recreated). A different path is refused, and so is any set after a bridge
/// path has already resolved the default, since paths already resolved would
/// disagree with later ones.
///
/// # Errors
///
/// [`FfiVaultError::SyncFailed`] if `dir` is relative, or if the directory is
/// already fixed to a different path.
pub fn set_platform_state_dir(dir: &Path) -> Result<(), FfiVaultError> {
    if !dir.is_absolute() {
        return Err(FfiVaultError::SyncFailed {
            detail: detail::literal("the sync state directory must be an absolute path"),
        });
    }
    if RESOLVED.get_or_init(|| Some(dir.to_path_buf())).as_deref() == Some(dir) {
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
    RESOLVED
        .get_or_init(secretary_cli::state::default_state_dir)
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No lib test sets the override, so the first read here (or in any other
    /// test) fixes the default; a later set to another path must then fail.
    #[test]
    fn a_set_after_the_first_read_is_refused() {
        let _ = platform_state_dir();
        let elsewhere = std::env::temp_dir().join("secretary-late-set-must-fail");
        assert!(matches!(
            set_platform_state_dir(&elsewhere),
            Err(FfiVaultError::SyncFailed { .. })
        ));
    }

    #[test]
    fn a_relative_dir_is_refused() {
        assert!(matches!(
            set_platform_state_dir(Path::new("sync-state")),
            Err(FfiVaultError::SyncFailed { .. })
        ));
    }

    /// #746: every implicit-dir path must go through [`platform_state_dir`]; a
    /// direct `default_state_dir()` call reads `dirs`' path, which Android
    /// never writes, and silently skips §10 there (on repair, the re-signing
    /// path). Scans this crate's source text.
    #[test]
    fn no_bridge_path_reads_the_dirs_default_directly() {
        fn walk(dir: &Path, scanned: &mut usize, hits: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, scanned, hits);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && !path.ends_with("state_dir.rs")
                {
                    *scanned += 1;
                    let text = std::fs::read_to_string(&path).unwrap();
                    if text.contains("default_state_dir()")
                        || text.contains("state::default_state_dir")
                    {
                        hits.push(path);
                    }
                }
            }
        }
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let (mut scanned, mut hits) = (0, Vec::new());
        walk(&src, &mut scanned, &mut hits);
        assert!(scanned > 20, "scanned only {scanned} files under {src:?}");
        assert!(
            hits.is_empty(),
            "call platform_state_dir() instead in {hits:?}"
        );
    }
}
