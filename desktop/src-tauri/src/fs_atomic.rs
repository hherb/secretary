//! Shared atomic write for the desktop-local state files (presence prefs
//! #277, recent-vault record #446): `create_dir_all` the parent, write to a
//! sibling tempfile, `persist` (rename(2) semantics) over the target. One
//! copy of the sequence so a durability fix (e.g. a parent-dir fsync) lands
//! everywhere at once. Uses the same exact-pinned `tempfile` as the vault
//! core's `write_atomic`.
//!
//! The `settings::io` device-UUID writer intentionally does NOT use this
//! helper — it needs `persist_noclobber` (first-writer-wins) semantics.

use std::path::Path;

use crate::errors::AppError;

/// Atomically replace `path` with `bytes`, creating parent directories as
/// needed. On failure the previous file content (if any) is left intact.
pub fn persist_atomically(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let dir = path.parent().ok_or_else(|| AppError::Io {
        detail: format!("no parent directory for {}", path.display()),
    })?;
    std::fs::create_dir_all(dir).map_err(|e| AppError::Io {
        detail: format!("mkdir -p {}: {}", dir.display(), e),
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| AppError::Io {
        detail: format!("tempfile new_in {}: {}", dir.display(), e),
    })?;
    std::io::Write::write_all(&mut tmp, bytes).map_err(|e| AppError::Io {
        detail: format!(
            "write {} (tempfile for {}): {}",
            tmp.path().display(),
            path.display(),
            e
        ),
    })?;
    tmp.persist(path).map_err(|e| AppError::Io {
        detail: format!("atomic persist of {}: {}", path.display(), e.error),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_missing_parents_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a").join("b").join("state.json");
        persist_atomically(&target, b"first").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
    }

    #[test]
    fn replaces_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state.json");
        persist_atomically(&target, b"first").unwrap();
        persist_atomically(&target, b"second").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second");
    }
}
