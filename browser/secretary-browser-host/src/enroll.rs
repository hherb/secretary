//! Dev-time enrollment: mint a browser-helper device slot on the **casual**
//! vault and write the helper-local config + the dev secret file.
//!
//! This is the consume-side counterpart of the design's native-app enrollment
//! (§4): the desktop app is the real place a user clicks "let this browser fill
//! from my casual vault". D.4.2 ships only this small, CI-testable enroller so
//! the per-fill open path can be exercised end to end; the Tauri UI is a later
//! slice.
//!
//! **Development-only.** It calls the genuine ADR 0009
//! [`add_device_slot`](secretary_core::vault::device_slot::add_device_slot) (so
//! the enrolled slot is real), but it then writes the 32-byte device secret to
//! a **cleartext file** for the
//! [`DevFileSecretSource`](crate::secret_source::DevFileSecretSource). That is not a
//! production key-storage path — see the loud warning on
//! [`crate::secret_source::DevFileSecretSource`].

use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::VaultError;

use crate::config::{HostConfig, SecretSourceConfig};

/// Why enrollment failed.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    /// The vault enroll (recover IBK + write wrap file) failed — most commonly
    /// a wrong master password.
    #[error("vault enroll failed: {0}")]
    Vault(#[from] VaultError),
    /// Writing the config or the dev secret file failed.
    #[error("enroll I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Mint a device slot on `vault_path` using `password`, write the dev secret to
/// `secret_path` and the helper config to `config_path`, and return the config.
///
/// On a wrong password,
/// [`add_device_slot`](secretary_core::vault::device_slot::add_device_slot) fails **before** any file is
/// written (and before any config/secret file is touched here).
pub fn enroll(
    vault_path: &Path,
    password: &[u8],
    config_path: &Path,
    secret_path: &Path,
) -> Result<HostConfig, EnrollError> {
    let pw = SecretBytes::from(password);
    let mut rng = rand_core::OsRng;
    let enrolled = secretary_core::vault::device_slot::add_device_slot(vault_path, &pw, &mut rng)?;
    // pw drops here → zeroized.

    // Stash the device secret as hex for the dev provider. `hex::encode` of the
    // exposed bytes is the cleartext secret; scrub the transient String after
    // writing. (The on-disk copy is the dev-only weakness, by design.)
    let mut secret_hex = hex::encode(enrolled.device_secret.expose());
    let write_res = write_secret_file(secret_path, secret_hex.as_bytes());
    scrub_string(&mut secret_hex);
    write_res?;

    let config = HostConfig {
        vault_path: vault_path.to_path_buf(),
        device_uuid: hex::encode(enrolled.device_uuid),
        secret_source: SecretSourceConfig::DevFile {
            path: secret_path.to_path_buf(),
        },
    };
    write_config_file(config_path, &config)?;
    Ok(config)
}

/// Default config path: the located helper config (env override or per-user dir).
pub fn default_config_path() -> Option<PathBuf> {
    HostConfig::locate()
}

/// Default dev secret path: a sibling of the config file.
pub fn default_secret_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("browser-host-secret.hex")
}

fn write_config_file(path: &Path, config: &HostConfig) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, config.to_json())
}

/// Write the dev secret file, `0600` on Unix (best-effort; not a security
/// boundary, the file holds the secret in cleartext regardless).
fn write_secret_file(path: &Path, hex_bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, hex_bytes)?;
    set_owner_only(path)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Scrub a secret-bearing `String`: move its (same-allocation) buffer out,
/// overwrite every byte, and free it. Leaves `s` empty. No `unsafe` needed —
/// `String::as_bytes_mut` would require it, so we go through the owned `Vec`.
fn scrub_string(s: &mut String) {
    let mut buf = std::mem::take(s).into_bytes();
    for b in buf.iter_mut() {
        *b = 0;
    }
    // buf (the original heap allocation) is freed here, zeroed.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{copy_dir_recursive, golden_password, golden_vault_dir};
    use crate::vault::per_fill_count;

    fn tmp_casual() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("casual");
        copy_dir_recursive(&golden_vault_dir(), &vault);
        (tmp, vault)
    }

    #[test]
    fn enroll_writes_config_and_secret_and_opens() {
        let (tmp, vault) = tmp_casual();
        let config_path = tmp.path().join("cfg/browser-host.json");
        let secret_path = tmp.path().join("cfg/secret.hex");

        let config = enroll(&vault, &golden_password(), &config_path, &secret_path).unwrap();

        // Files exist.
        assert!(config_path.exists());
        assert!(secret_path.exists());

        // Secret file is 64 hex chars (32 bytes).
        let hexed = std::fs::read_to_string(&secret_path).unwrap();
        assert_eq!(hexed.trim().len(), 64);

        // The written config opens the vault and counts blocks via the same
        // per-fill path the host uses at runtime.
        let loaded = HostConfig::load(&config_path).unwrap();
        assert_eq!(loaded, config);
        let source = loaded.build_secret_source();
        let count = per_fill_count(&loaded, source.as_ref()).unwrap();
        // Golden vault has at least one block; just assert the open succeeded.
        let _ = count;
    }

    #[test]
    fn enroll_wrong_password_writes_nothing() {
        let (tmp, vault) = tmp_casual();
        let config_path = tmp.path().join("cfg/browser-host.json");
        let secret_path = tmp.path().join("cfg/secret.hex");

        // Doubled password — derived purely from the runtime fixture, differs
        // from the real one, so enroll must be rejected (no hard-coded value).
        let wrong = [golden_password(), golden_password()].concat();
        let err = enroll(&vault, &wrong, &config_path, &secret_path).unwrap_err();
        assert!(matches!(err, EnrollError::Vault(_)), "got {err:?}");

        // add_device_slot fails before we write anything.
        assert!(!config_path.exists(), "no config on wrong password");
        assert!(!secret_path.exists(), "no secret on wrong password");
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (tmp, vault) = tmp_casual();
        let config_path = tmp.path().join("browser-host.json");
        let secret_path = tmp.path().join("secret.hex");
        enroll(&vault, &golden_password(), &config_path, &secret_path).unwrap();
        let mode = std::fs::metadata(&secret_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
