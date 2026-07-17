//! Desktop-local "most recently opened vault" record (#446). This-device
//! scoped UX state: the folder path of the last vault that unlocked
//! successfully on THIS machine, used to pre-fill the unlock dialog. Stored
//! at `<data_dir>/secretary-desktop/recent.json`, a sibling of the
//! `devices/` and `presence/` subtrees. NOT a vault setting — the vault is
//! locked when this is read, and it never syncs.
//!
//! Not a secret: the vault *path* already sits in plaintext in the per-vault
//! sync-state dir. Still, callers record it only after a *successful* unlock
//! (`VaultSession::populate_unlocked`) so failed guesses are never logged.
//!
//! Pure/IO split (mirrors `presence_pref`): `parse_recent` / `serialize_recent`
//! are pure; `load_recent_in` / `save_recent_in` are the thin atomic-IO edge.
//! Absent or corrupt file → `None` (fail-safe toward the fresh-install
//! behavior: an empty unlock dialog).

use std::path::{Path, PathBuf};

use crate::constants::RECENT_VAULT_FILENAME;
use crate::errors::AppError;

/// The persisted record. `vault_folder` is the display/canonical path string
/// of the last successfully opened vault (paths are stored lossily as UTF-8 —
/// the same representation the picker hands the frontend).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct RecentVault {
    vault_folder: String,
}

/// Parse the on-disk JSON. Malformed, partial, or empty-path content yields
/// `None` — the unlock dialog then behaves exactly like a fresh install
/// (fail-safe: a corrupt UX nicety must never block or distort the unlock
/// path). Pure.
pub fn parse_recent(bytes: &[u8]) -> Option<PathBuf> {
    let recent = serde_json::from_slice::<RecentVault>(bytes).ok()?;
    if recent.vault_folder.is_empty() {
        return None;
    }
    Some(PathBuf::from(recent.vault_folder))
}

/// Serialize `folder` to bytes for atomic write. Non-UTF-8 path components
/// are stored lossily (same `to_string_lossy` representation the pickers
/// return to the frontend). Pure.
pub fn serialize_recent(folder: &Path) -> Vec<u8> {
    let recent = RecentVault {
        vault_folder: folder.to_string_lossy().into_owned(),
    };
    // Infallible for this fixed struct; `.expect` documents that.
    serde_json::to_vec_pretty(&recent).expect("RecentVault serializes")
}

/// Absolute path of the recent-vault file under `data_dir`.
pub fn recent_path_in(data_dir: &Path) -> PathBuf {
    data_dir
        .join("secretary-desktop")
        .join(RECENT_VAULT_FILENAME)
}

/// Load the recorded recent vault folder, or `None` if the file is absent or
/// corrupt (see `parse_recent`). IO edge.
pub fn load_recent_in(data_dir: &Path) -> Option<PathBuf> {
    let bytes = std::fs::read(recent_path_in(data_dir)).ok()?;
    parse_recent(&bytes)
}

/// Atomically persist `folder` as the most recently opened vault. Creates the
/// `secretary-desktop/` subtree on first write. IO edge.
pub fn save_recent_in(data_dir: &Path, folder: &Path) -> Result<(), AppError> {
    crate::fs_atomic::persist_atomically(&recent_path_in(data_dir), &serialize_recent(folder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let folder = Path::new("/home/alice/vault");
        assert_eq!(
            parse_recent(&serialize_recent(folder)),
            Some(folder.to_path_buf())
        );
    }

    #[test]
    fn corrupt_or_empty_bytes_yield_none() {
        assert_eq!(parse_recent(b"not json"), None);
        assert_eq!(parse_recent(b""), None);
        assert_eq!(parse_recent(b"{}"), None);
    }

    /// An empty stored path is as useless as no file: it must not pre-fill.
    #[test]
    fn empty_path_string_yields_none() {
        assert_eq!(parse_recent(br#"{"vault_folder": ""}"#), None);
    }

    #[test]
    fn path_is_recent_json_under_secretary_desktop() {
        let p = recent_path_in(Path::new("/tmp/dd"));
        assert!(p.ends_with("secretary-desktop/recent.json"), "got {p:?}");
    }

    #[test]
    fn absent_file_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_recent_in(dir.path()), None);
    }

    #[test]
    fn save_then_load_round_trips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let folder = Path::new("/home/alice/vault");
        save_recent_in(dir.path(), folder).unwrap();
        assert_eq!(load_recent_in(dir.path()), Some(folder.to_path_buf()));
    }

    #[test]
    fn corrupt_file_on_disk_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = recent_path_in(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(load_recent_in(dir.path()), None);
    }

    /// A second save replaces the first — last successful unlock wins.
    #[test]
    fn resave_replaces_previous_path() {
        let dir = tempfile::tempdir().unwrap();
        save_recent_in(dir.path(), Path::new("/vaults/a")).unwrap();
        save_recent_in(dir.path(), Path::new("/vaults/b")).unwrap();
        assert_eq!(load_recent_in(dir.path()), Some(PathBuf::from("/vaults/b")));
    }
}
