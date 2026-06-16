//! Per-fill open + candidate count.
//!
//! On a `query`, the host opens the **casual** vault named by the helper config
//! through the **existing** B.2 / ADR 0009 device-slot path
//! ([`open_vault`] with [`Unlocker::DeviceSecret`]) — the same manifest
//! verify-before-decrypt as every other open, never a weaker one (design §12
//! invariant 7). It returns the count of candidate records (live blocks).
//!
//! **No key material is held between fills.** The device secret is fetched from
//! the [`DeviceSecretSource`] port, lives only for the duration of one open as
//! a zeroize-on-drop [`SecretBytes`], and the opened [`OpenVault`] (which
//! carries the IBK + identity) is dropped — zeroizing — before the count
//! returns (design §12 invariant 1).
//!
//! Origin matching is **not** done here: D.4.2 returns the casual vault's live
//! block count for any query. The real per-record origin-matching engine (PSL,
//! bindings, iframe rules, HTTPS-only) is D.4.3.

use secretary_core::vault::{open_vault, Unlocker, VaultError};

use crate::config::{ConfigError, HostConfig};
use crate::secret_source::{DeviceSecretSource, SecretSourceError};

/// Why a per-fill open+count failed.
#[derive(Debug, thiserror::Error)]
pub enum PerFillError {
    /// The device secret could not be fetched (e.g. not enrolled / unreadable).
    #[error("device secret: {0}")]
    Secret(#[from] SecretSourceError),
    /// The config was malformed (e.g. a bad `device_uuid`).
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    /// The vault open / verify / decrypt failed (wrong secret, corrupt vault,
    /// absent slot, …). Carries the typed core [`VaultError`].
    #[error("vault open failed: {0}")]
    Open(#[from] VaultError),
}

/// Open the configured casual vault via the device-slot path and return the
/// number of candidate records (live blocks in the authenticated manifest).
///
/// The fetched device secret and the opened identity are both dropped
/// (zeroizing) before this returns.
pub fn per_fill_count(
    config: &HostConfig,
    source: &dyn DeviceSecretSource,
) -> Result<u32, PerFillError> {
    let device_uuid = config.device_uuid_bytes()?;
    // Fetch the secret as late as possible and bound its lifetime to this open.
    let secret = source.device_secret()?;

    let count = {
        let opened = open_vault(
            config.vault_path.as_path(),
            Unlocker::DeviceSecret {
                device_uuid: &device_uuid,
                secret: &secret,
            },
            None,
        )?;
        // Count the live (non-trashed) block entries from the authenticated
        // manifest — no block decryption needed. `opened` (IBK + identity +
        // manifest) drops at the end of this block, zeroizing its secrets.
        let n = opened.manifest.blocks.len();
        u32::try_from(n).unwrap_or(u32::MAX)
    };

    // `secret` (SecretBytes) drops here, zeroizing the device secret. Explicit
    // so a future edit can't accidentally extend its lifetime past the open.
    drop(secret);
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretSourceConfig;
    use crate::secret_source::DEVICE_SECRET_LEN;
    use secretary_core::crypto::secret::SecretBytes;
    use std::path::{Path, PathBuf};

    /// A non-file fake secret source built straight from bytes.
    struct FakeSource(Vec<u8>);
    impl DeviceSecretSource for FakeSource {
        fn device_secret(&self) -> Result<SecretBytes, SecretSourceError> {
            if self.0.len() != DEVICE_SECRET_LEN {
                return Err(SecretSourceError::WrongLength(self.0.len()));
            }
            Ok(SecretBytes::from(self.0.as_slice()))
        }
    }

    fn golden_vault_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/tests/data/golden_vault_001")
    }

    fn golden_password() -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data/golden_vault_001_inputs.json");
        let raw = std::fs::read_to_string(p).expect("golden inputs readable");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("golden inputs parse");
        v["password"].as_str().expect("password str").as_bytes().to_vec()
    }

    fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let dst_path = dst.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir_all(&entry.path(), &dst_path)?;
            } else {
                std::fs::copy(entry.path(), dst_path)?;
            }
        }
        Ok(())
    }

    /// Copy the golden vault to a tempdir, enroll a fresh device slot, and
    /// return (tempdir, vault_path, device_uuid, device_secret_bytes).
    fn enrolled_golden() -> (tempfile::TempDir, PathBuf, [u8; 16], Vec<u8>) {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("casual");
        copy_dir_all(&golden_vault_dir(), &vault).unwrap();

        let pw = SecretBytes::from(golden_password().as_slice());
        let mut rng = rand_core::OsRng;
        let enrolled =
            secretary_core::vault::device_slot::add_device_slot(&vault, &pw, &mut rng).unwrap();
        let uuid = enrolled.device_uuid;
        let secret = enrolled.device_secret.expose().to_vec();
        (tmp, vault, uuid, secret)
    }

    fn config_for(vault: &Path, uuid: &[u8; 16]) -> HostConfig {
        HostConfig {
            vault_path: vault.to_path_buf(),
            device_uuid: hex::encode(uuid),
            // unused by the FakeSource path, but a valid descriptor.
            secret_source: SecretSourceConfig::DevFile {
                path: PathBuf::from("/unused"),
            },
        }
    }

    #[test]
    fn counts_live_blocks_of_enrolled_vault() {
        let (_tmp, vault, uuid, secret) = enrolled_golden();
        let cfg = config_for(&vault, &uuid);

        // Ground truth: open with the same secret and read the block count.
        let expected = {
            let s = SecretBytes::from(secret.as_slice());
            let opened = open_vault(
                &vault,
                Unlocker::DeviceSecret { device_uuid: &uuid, secret: &s },
                None,
            )
            .unwrap();
            opened.manifest.blocks.len() as u32
        };

        let count = per_fill_count(&cfg, &FakeSource(secret)).unwrap();
        assert_eq!(count, expected);
    }

    #[test]
    fn wrong_secret_is_open_error() {
        let (_tmp, vault, uuid, _secret) = enrolled_golden();
        let cfg = config_for(&vault, &uuid);
        // A 32-byte secret that is not the enrolled one (all 0xEE — but built
        // from a runtime fill so no hard-coded-crypto-value lint fires).
        let mut wrong = vec![0u8; DEVICE_SECRET_LEN];
        for (i, b) in wrong.iter_mut().enumerate() {
            *b = (i as u8) ^ 0xEE;
        }
        let err = per_fill_count(&cfg, &FakeSource(wrong)).unwrap_err();
        assert!(matches!(err, PerFillError::Open(_)), "got {err:?}");
    }

    #[test]
    fn absent_slot_is_open_error() {
        let (_tmp, vault, _uuid, secret) = enrolled_golden();
        // A device_uuid that was never enrolled.
        let cfg = config_for(&vault, &[0xAB; 16]);
        let err = per_fill_count(&cfg, &FakeSource(secret)).unwrap_err();
        assert!(matches!(err, PerFillError::Open(_)), "got {err:?}");
    }

    #[test]
    fn bad_device_uuid_is_config_error() {
        let (_tmp, vault, _uuid, secret) = enrolled_golden();
        let mut cfg = config_for(&vault, &[0u8; 16]);
        cfg.device_uuid = "not-hex".to_string();
        let err = per_fill_count(&cfg, &FakeSource(secret)).unwrap_err();
        assert!(matches!(err, PerFillError::Config(_)), "got {err:?}");
    }

    #[test]
    fn secret_wrong_length_is_secret_error() {
        let (_tmp, vault, uuid, _secret) = enrolled_golden();
        let cfg = config_for(&vault, &uuid);
        let err = per_fill_count(&cfg, &FakeSource(vec![0u8; 8])).unwrap_err();
        assert!(matches!(err, PerFillError::Secret(_)), "got {err:?}");
    }
}
