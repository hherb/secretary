//! Helper-local host configuration.
//!
//! The host learns *which* casual vault to open, *which* device slot to use,
//! and *where* to fetch the device secret from a per-user, **non-syncing**
//! config file — a per-install posture choice (design §6 / §10.1.1), not vault
//! data. An **absent** config means "this browser is not enrolled": the host
//! answers every `query` with `count: 0` rather than failing.
//!
//! Location precedence:
//! 1. `$SECRETARY_BROWSER_HOST_CONFIG` (absolute path) — override, used by tests
//!    and by the enroll tool.
//! 2. `dirs::config_dir()/secretary/browser-host.json` — the default per-user path.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::secret_source::{DevFileSecretSource, DeviceSecretSource};

/// Environment variable overriding the config-file location.
pub const CONFIG_ENV: &str = "SECRETARY_BROWSER_HOST_CONFIG";

/// Length of a device UUID, in bytes.
pub const DEVICE_UUID_LEN: usize = 16;

/// Errors loading or interpreting the host config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("config I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The config file was not valid JSON for [`HostConfig`].
    #[error("config at {path} is malformed: {source}")]
    Malformed {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// `device_uuid` was not 16 bytes of lowercase hex.
    #[error("config device_uuid must be {DEVICE_UUID_LEN} bytes of hex: {0}")]
    BadDeviceUuid(String),
}

/// Where the host fetches the device secret. Tagged on `type` so future
/// OS-keystore variants slot in behind the same [`DeviceSecretSource`] port
/// without breaking existing configs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretSourceConfig {
    /// **DEV ONLY** — the secret is stored as hex in a cleartext file.
    DevFile { path: PathBuf },
    // Real OS-keystore variants (keychain / secret_service), optionally
    // biometric-gated, land here in a follow-up — behind the same port.
}

/// Helper-local configuration binding the host to one casual vault + slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostConfig {
    /// Absolute path to the casual vault folder (`vault.toml` lives here).
    pub vault_path: PathBuf,
    /// 16-byte device UUID of the browser-helper slot, as 32 lowercase hex chars.
    pub device_uuid: String,
    /// How to obtain the device secret for the per-fill open.
    pub secret_source: SecretSourceConfig,
}

impl HostConfig {
    /// Resolve the config-file path from the environment override or the
    /// default per-user location. `None` if neither is determinable (e.g. no
    /// home directory and no override).
    pub fn locate() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os(CONFIG_ENV) {
            return Some(PathBuf::from(p));
        }
        dirs::config_dir().map(|d| d.join("secretary").join("browser-host.json"))
    }

    /// Load the config from `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        serde_json::from_str(&raw).map_err(|e| ConfigError::Malformed {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Load the config from the located path, returning `Ok(None)` when no
    /// config exists (the "not enrolled" state — not an error).
    pub fn load_default() -> Result<Option<Self>, ConfigError> {
        let Some(path) = Self::locate() else {
            return Ok(None);
        };
        match std::fs::metadata(&path) {
            Ok(_) => Self::load(&path).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ConfigError::Io { path, source: e }),
        }
    }

    /// Serialize to pretty JSON (used by the enroll tool).
    pub fn to_json(&self) -> String {
        // `HostConfig` always serializes (only owned, serde-derived fields).
        serde_json::to_string_pretty(self).expect("HostConfig serialization is infallible")
    }

    /// Decode `device_uuid` to its 16 raw bytes.
    pub fn device_uuid_bytes(&self) -> Result<[u8; DEVICE_UUID_LEN], ConfigError> {
        let bytes =
            hex::decode(&self.device_uuid).map_err(|e| ConfigError::BadDeviceUuid(e.to_string()))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::BadDeviceUuid(format!("expected 16 bytes, got {}", bytes.len())))
    }

    /// Build the concrete [`DeviceSecretSource`] this config describes.
    pub fn build_secret_source(&self) -> Box<dyn DeviceSecretSource> {
        match &self.secret_source {
            SecretSourceConfig::DevFile { path } => {
                Box::new(DevFileSecretSource::new(path.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(uuid_hex: &str) -> HostConfig {
        HostConfig {
            vault_path: PathBuf::from("/tmp/casual-vault"),
            device_uuid: uuid_hex.to_string(),
            secret_source: SecretSourceConfig::DevFile {
                path: PathBuf::from("/tmp/secret.hex"),
            },
        }
    }

    #[test]
    fn json_round_trips() {
        let cfg = sample(&"ab".repeat(16));
        let json = cfg.to_json();
        let back: HostConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn device_uuid_decodes_to_16_bytes() {
        let cfg = sample(&"0a".repeat(16));
        let bytes = cfg.device_uuid_bytes().unwrap();
        assert_eq!(bytes, [0x0a; 16]);
    }

    #[test]
    fn bad_device_uuid_length_is_rejected() {
        let cfg = sample("0a0b0c"); // 3 bytes
        assert!(matches!(
            cfg.device_uuid_bytes(),
            Err(ConfigError::BadDeviceUuid(_))
        ));
    }

    #[test]
    fn non_hex_device_uuid_is_rejected() {
        let cfg = sample(&"zz".repeat(16));
        assert!(matches!(
            cfg.device_uuid_bytes(),
            Err(ConfigError::BadDeviceUuid(_))
        ));
    }

    #[test]
    fn load_explicit_path_round_trips() {
        // `load(path)` is env-free, so it is race-free under parallel tests.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("browser-host.json");
        let cfg = sample(&"cd".repeat(16));
        std::fs::write(&path, cfg.to_json()).unwrap();
        assert_eq!(HostConfig::load(&path).unwrap(), cfg);
    }

    #[test]
    fn load_default_env_override_present_and_absent() {
        // Both env-touching assertions live in ONE test so they cannot race
        // another test over the process-global `CONFIG_ENV` var.
        let dir = tempfile::tempdir().unwrap();

        // Absent file under the override → Ok(None) ("not enrolled").
        let missing = dir.path().join("nope.json");
        std::env::set_var(CONFIG_ENV, &missing);
        assert!(HostConfig::load_default().unwrap().is_none());

        // Written file under the override → Ok(Some(cfg)).
        let path = dir.path().join("browser-host.json");
        let cfg = sample(&"cd".repeat(16));
        std::fs::write(&path, cfg.to_json()).unwrap();
        std::env::set_var(CONFIG_ENV, &path);
        assert_eq!(HostConfig::load_default().unwrap(), Some(cfg));

        std::env::remove_var(CONFIG_ENV);
    }

    #[test]
    fn secret_source_tag_is_snake_case() {
        let cfg = sample(&"ab".repeat(16));
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["secret_source"]["type"], "dev_file");
    }
}
