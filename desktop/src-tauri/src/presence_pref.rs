//! Desktop-local, per-vault biometric preference (#277). This-device scoped:
//! whether Touch ID may satisfy write re-auth on THIS machine. Stored under
//! `<data_dir>/secretary-desktop/presence/<vault_uuid_hex>.json`, a sibling of
//! the per-vault device-UUID files. NOT a vault setting — it never syncs, and
//! biometric trust is inherently per-device.
//!
//! Pure/IO split (mirrors `settings::parse` vs `settings::io`): `parse_pref` /
//! `serialize_pref` are pure; `load_pref_in` / `save_pref_in` are the thin
//! atomic-IO edge. Absent or corrupt file → default enabled.

use std::path::{Path, PathBuf};

use crate::constants::{PRESENCE_BIOMETRIC_ENABLED_DEFAULT, PRESENCE_PREF_SUBDIR};
use crate::errors::AppError;

/// The persisted preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PresencePref {
    pub biometric_reauth_enabled: bool,
}

impl Default for PresencePref {
    fn default() -> Self {
        Self {
            biometric_reauth_enabled: PRESENCE_BIOMETRIC_ENABLED_DEFAULT,
        }
    }
}

/// Parse the on-disk JSON. A malformed / partial file falls back to default
/// (lenient load — mirrors settings load). Pure.
pub fn parse_pref(bytes: &[u8]) -> PresencePref {
    serde_json::from_slice::<PresencePref>(bytes).unwrap_or_default()
}

/// Serialize to bytes for atomic write. Pure.
pub fn serialize_pref(pref: &PresencePref) -> Vec<u8> {
    // Infallible for this fixed struct; `.expect` documents that.
    serde_json::to_vec_pretty(pref).expect("PresencePref serializes")
}

/// Absolute path of the pref file for `vault_uuid_hex` under `data_dir`.
pub fn pref_path_in(data_dir: &Path, vault_uuid_hex: &str) -> PathBuf {
    data_dir
        .join("secretary-desktop")
        .join(PRESENCE_PREF_SUBDIR)
        .join(format!("{vault_uuid_hex}.json"))
}

/// Load the pref for `vault_uuid_hex`, or `Default` if the file is absent.
/// Corrupt content is lenient (default). IO edge.
pub fn load_pref_in(data_dir: &Path, vault_uuid_hex: &str) -> PresencePref {
    let path = pref_path_in(data_dir, vault_uuid_hex);
    match std::fs::read(&path) {
        Ok(bytes) => parse_pref(&bytes),
        Err(_) => PresencePref::default(),
    }
}

/// Atomically persist the pref for `vault_uuid_hex`. Creates the
/// `secretary-desktop/presence/` subtree on first write. Uses the same
/// exact-pinned `tempfile` persist as the settings device-UUID path.
pub fn save_pref_in(
    data_dir: &Path,
    vault_uuid_hex: &str,
    pref: &PresencePref,
) -> Result<(), AppError> {
    let path = pref_path_in(data_dir, vault_uuid_hex);
    let dir = path.parent().expect("pref path has a parent");
    std::fs::create_dir_all(dir).map_err(|e| AppError::Io {
        detail: format!("mkdir -p {}: {}", dir.display(), e),
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| AppError::Io {
        detail: format!("tempfile new_in {}: {}", dir.display(), e),
    })?;
    std::io::Write::write_all(&mut tmp, &serialize_pref(pref)).map_err(|e| AppError::Io {
        detail: format!(
            "write {} (tempfile for {}): {}",
            tmp.path().display(),
            path.display(),
            e
        ),
    })?;
    tmp.persist(&path).map_err(|e| AppError::Io {
        detail: format!(
            "atomic persist of presence pref file {}: {}",
            path.display(),
            e.error
        ),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_enabled() {
        assert!(PresencePref::default().biometric_reauth_enabled);
    }

    #[test]
    fn round_trips() {
        let pref = PresencePref {
            biometric_reauth_enabled: false,
        };
        assert_eq!(parse_pref(&serialize_pref(&pref)), pref);
    }

    #[test]
    fn corrupt_bytes_fall_back_to_default() {
        assert_eq!(parse_pref(b"not json"), PresencePref::default());
        assert_eq!(parse_pref(b""), PresencePref::default());
        assert_eq!(parse_pref(b"{}"), PresencePref::default());
    }

    #[test]
    fn path_uses_presence_subdir() {
        let p = pref_path_in(Path::new("/tmp/dd"), "abcd");
        assert!(p.ends_with("secretary-desktop/presence/abcd.json"));
    }

    #[test]
    fn save_then_load_round_trips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let uuid_hex = "00112233445566778899aabbccddeeff";
        // Absent → default.
        assert_eq!(load_pref_in(dir.path(), uuid_hex), PresencePref::default());
        // Persist disabled, read it back.
        let pref = PresencePref {
            biometric_reauth_enabled: false,
        };
        save_pref_in(dir.path(), uuid_hex, &pref).unwrap();
        assert_eq!(load_pref_in(dir.path(), uuid_hex), pref);
    }
}
