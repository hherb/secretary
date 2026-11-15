//! This CLI's per-vault device UUID (#744).
//!
//! A sync merge ticks the merging device's vector-clock entry (crypto-design
//! §10 / §11.2), so the CLI needs a stable device identity per vault, the way
//! each app has one. It lives beside the sync state as
//! `<state-dir>/<vault_uuid_hex>.device`: 16 raw bytes, created from OS
//! randomness on first use. `--device-uuid` overrides it.
//!
//! The file is only touched while the per-vault lockfile is held, so two CLI
//! processes cannot race to create it. The desktop and mobile apps keep their
//! own device UUIDs elsewhere and never read this file.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::state::{canonical_hex, create_dir_secure};

/// Width of a device UUID, as everywhere in the vault format.
pub const DEVICE_UUID_LEN: usize = 16;
const DEVICE_FILE_EXTENSION: &str = "device";
const DEVICE_UUID_HEX_LEN: usize = DEVICE_UUID_LEN * 2;

#[derive(Debug, Error)]
pub enum DeviceUuidError {
    #[error("I/O error on device UUID file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "device UUID file {} holds {len} bytes, expected {DEVICE_UUID_LEN}; \
         restore it from a backup, or delete it to mint a new device UUID",
        path.display()
    )]
    Malformed { path: PathBuf, len: usize },
}

/// `<state-dir>/<vault_uuid_hex>.device`.
#[must_use]
pub fn device_file_path(state_dir: &Path, vault_uuid: [u8; 16]) -> PathBuf {
    state_dir.join(format!(
        "{}.{}",
        canonical_hex(vault_uuid),
        DEVICE_FILE_EXTENSION
    ))
}

/// Read this CLI's device UUID for `vault_uuid`, creating and persisting a
/// random one on first use. Call it with the vault's lockfile held.
pub fn load_or_create(
    state_dir: &Path,
    vault_uuid: [u8; 16],
) -> Result<[u8; DEVICE_UUID_LEN], DeviceUuidError> {
    let path = device_file_path(state_dir, vault_uuid);
    match fs::read(&path) {
        Ok(bytes) => {
            return <[u8; DEVICE_UUID_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
                DeviceUuidError::Malformed {
                    path,
                    len: bytes.len(),
                }
            })
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(source) => return Err(DeviceUuidError::Io { path, source }),
    }
    let mut uuid = [0u8; DEVICE_UUID_LEN];
    OsRng.fill_bytes(&mut uuid);
    let io = |source| DeviceUuidError::Io {
        path: path.clone(),
        source,
    };
    create_dir_secure(state_dir).map_err(io)?;
    let mut tmp = NamedTempFile::new_in(state_dir).map_err(io)?;
    tmp.write_all(&uuid).map_err(io)?;
    // Durable before the rename, so a power loss cannot leave a short file.
    tmp.as_file().sync_all().map_err(io)?;
    tmp.persist_noclobber(&path).map_err(|e| io(e.error))?;
    Ok(uuid)
}

/// Parse a `--device-uuid` value: 32 hex digits, no separators.
pub fn parse_device_uuid_hex(s: &str) -> Result<[u8; DEVICE_UUID_LEN], String> {
    if s.len() != DEVICE_UUID_HEX_LEN || !s.is_ascii() {
        return Err(format!(
            "expected {DEVICE_UUID_HEX_LEN} hex digits, got {:?}",
            s
        ));
    }
    let mut out = [0u8; DEVICE_UUID_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("not a hex string: {s:?}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn device_file_path_layout() {
        let path = device_file_path(Path::new("/tmp/sync"), [0xab; 16]);
        assert_eq!(
            path,
            Path::new("/tmp/sync/abababababababababababababababab.device")
        );
    }

    /// First call creates the file; later calls return the same bytes.
    #[test]
    fn load_or_create_is_stable() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("sync");
        let first = load_or_create(&state_dir, [1; 16]).unwrap();
        assert!(device_file_path(&state_dir, [1; 16]).exists());
        assert_eq!(load_or_create(&state_dir, [1; 16]).unwrap(), first);
    }

    /// Each vault gets its own device UUID.
    #[test]
    fn vaults_get_distinct_device_uuids() {
        let dir = TempDir::new().unwrap();
        let a = load_or_create(dir.path(), [1; 16]).unwrap();
        let b = load_or_create(dir.path(), [2; 16]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_wrong_length_file_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = device_file_path(dir.path(), [1; 16]);
        fs::write(&path, [0u8; 3]).unwrap();
        let err = load_or_create(dir.path(), [1; 16]).unwrap_err();
        assert!(matches!(err, DeviceUuidError::Malformed { len: 3, .. }));
        assert_eq!(fs::read(&path).unwrap(), [0u8; 3], "never overwritten");
    }

    #[test]
    fn parse_device_uuid_hex_round_trips() {
        let hex = canonical_hex([0x5e; 16]);
        assert_eq!(parse_device_uuid_hex(&hex).unwrap(), [0x5e; 16]);
    }

    #[test]
    fn parse_device_uuid_hex_rejects_bad_input() {
        assert!(parse_device_uuid_hex("abcd").is_err());
        assert!(parse_device_uuid_hex(&"zz".repeat(16)).is_err());
        assert!(parse_device_uuid_hex(&"é".repeat(16)).is_err());
    }
}
