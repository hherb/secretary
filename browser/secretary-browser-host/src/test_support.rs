//! Shared, in-crate test fixtures (`#[cfg(test)]` only — never compiled into
//! the shipped binary). Used by the `vault` and top-level loop unit tests so
//! the "enroll a real device slot on a temp golden vault" helper lives once.

use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::SecretBytes;

use crate::config::{HostConfig, SecretSourceConfig};
use crate::secret_source::{DeviceSecretSource, SecretSourceError, DEVICE_SECRET_LEN};

/// A non-file fake secret source built straight from bytes.
pub(crate) struct FakeSource(pub Vec<u8>);

impl DeviceSecretSource for FakeSource {
    fn device_secret(&self) -> Result<SecretBytes, SecretSourceError> {
        if self.0.len() != DEVICE_SECRET_LEN {
            return Err(SecretSourceError::WrongLength(self.0.len()));
        }
        Ok(SecretBytes::from(self.0.as_slice()))
    }
}

pub(crate) fn golden_vault_dir() -> PathBuf {
    secretary_test_utils::core_test_data_dir().join("golden_vault_001")
}

pub(crate) fn golden_password() -> Vec<u8> {
    secretary_test_utils::golden_vault_001_password()
}

pub(crate) use secretary_test_utils::copy_dir_recursive;

/// Copy the golden vault to a tempdir, enroll a fresh device slot, and return
/// (tempdir, vault_path, device_uuid, device_secret_bytes).
pub(crate) fn enrolled_golden() -> (tempfile::TempDir, PathBuf, [u8; 16], Vec<u8>) {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("casual");
    copy_dir_recursive(&golden_vault_dir(), &vault);

    let pw = SecretBytes::from(golden_password().as_slice());
    let mut rng = rand_core::OsRng;
    let enrolled =
        secretary_core::vault::device_slot::add_device_slot(&vault, &pw, &mut rng).unwrap();
    let uuid = enrolled.device_uuid;
    let secret = enrolled.device_secret.expose().to_vec();
    (tmp, vault, uuid, secret)
}

/// A config naming `vault` + `uuid` with a placeholder dev-file secret source
/// (the loop/vault tests inject a [`FakeSource`] directly, so the descriptor's
/// path is unused).
pub(crate) fn config_for(vault: &Path, uuid: &[u8; 16]) -> HostConfig {
    HostConfig {
        vault_path: vault.to_path_buf(),
        device_uuid: hex::encode(uuid),
        secret_source: SecretSourceConfig::DevFile {
            path: PathBuf::from("/unused"),
        },
    }
}
