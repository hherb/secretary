//! Per-vault `SyncState` persistence + host-local lockfile.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"State persistence" and §D7 (single-process-per-vault lockfile).
//!
//! The state file is `<state-dir>/<vault_uuid_hex>.state.cbor` — `SyncState`
//! encoded via `core::sync::SyncState::to_canonical_cbor`. Atomic write via
//! `tempfile::NamedTempFile::persist`, sharing the `=3.27.0` exact pin
//! discipline with the vault format layer (see `cli/Cargo.toml` and the
//! `CLAUDE.md` "exact pins on security-critical paths" note).
//!
//! The lockfile is `<state-dir>/<vault_uuid_hex>.lock`, locked via
//! `fs4::FileExt::try_lock` — the exclusive non-blocking lock
//! (flock(LOCK_EX | LOCK_NB) on Unix, LockFileEx on Windows). Kernel
//! auto-releases on process death; no stale-PID handling required.
//!
//! fs4 1.x API note: the trait is `fs4::FileExt` (re-exported at the
//! crate root; no `fs_std` module in v1, unlike the early plan draft).
//! The exclusive try-variant is `try_lock()` and returns
//! `Result<(), fs4::TryLockError>` — `Err(TryLockError::WouldBlock)`
//! signals another process holds the lock; `Err(TryLockError::Error(io))`
//! is a genuine I/O failure.
//!
//! MSRV note: stdlib stabilized an inherent `File::try_lock` in Rust
//! 1.89 that would otherwise shadow the fs4 trait method. The workspace
//! MSRV is 1.87 (`Cargo.toml` `rust-version`), so we keep the fs4 dep
//! and explicitly invoke the trait via the `Fs4FileExt::try_lock(&file)`
//! UFCS form to make the call site unambiguous on any toolchain ≥ 1.87.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs4::{FileExt as Fs4FileExt, TryLockError};
use tempfile::NamedTempFile;
use thiserror::Error;

use secretary_core::sync::{SyncError, SyncState};

const STATE_FILE_EXTENSION: &str = "state.cbor";
const LOCK_FILE_EXTENSION: &str = "lock";
const VAULT_UUID_HEX_LEN: usize = 32;

#[allow(dead_code)] // TODO(#113): consumed when Task 5 pipeline wires state load/save + lockfile acquire.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("I/O error reading or writing state file: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file vault_uuid mismatch (file is for vault {file_uuid_hex}, expected {expected_uuid_hex})")]
    VaultUuidMismatch {
        file_uuid_hex: String,
        expected_uuid_hex: String,
    },
    #[error("CBOR decode failed: {0}")]
    Decode(SyncError),
    #[error("CBOR encode failed: {0}")]
    Encode(SyncError),
    #[error("lockfile {0} already held by another secretary-sync process")]
    LockfileHeld(PathBuf),
}

/// 16-byte vault UUID → lowercase hex string (32 chars, no separator).
#[must_use]
pub fn canonical_hex(vault_uuid: [u8; 16]) -> String {
    let mut out = String::with_capacity(VAULT_UUID_HEX_LEN);
    for byte in vault_uuid {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Compute `<state-dir>/<vault_uuid_hex>.state.cbor`.
#[must_use]
pub fn state_file_path(state_dir: &Path, vault_uuid: [u8; 16]) -> PathBuf {
    state_dir.join(format!(
        "{}.{}",
        canonical_hex(vault_uuid),
        STATE_FILE_EXTENSION
    ))
}

/// Compute `<state-dir>/<vault_uuid_hex>.lock`.
#[must_use]
pub fn lock_file_path(state_dir: &Path, vault_uuid: [u8; 16]) -> PathBuf {
    state_dir.join(format!(
        "{}.{}",
        canonical_hex(vault_uuid),
        LOCK_FILE_EXTENSION
    ))
}

/// Resolve the default state dir via the `dirs` crate.
///
/// - Linux: `$XDG_DATA_HOME/secretary/sync/` (typically `~/.local/share/...`)
/// - macOS: `~/Library/Application Support/secretary/sync/`
/// - Windows: `%LOCALAPPDATA%\secretary\sync\`
///
/// Returns `None` if no platform data dir is available (very rare — minimal
/// headless installs without `$HOME`).
#[must_use]
pub fn default_state_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|p| p.join("secretary").join("sync"))
}

/// Load `SyncState` from `<state-dir>/<vault_uuid_hex>.state.cbor`. If the
/// file does not exist, return `SyncState::empty(vault_uuid)`. Validates
/// that any decoded state's `vault_uuid` matches the expected one.
#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
pub fn load(state_dir: &Path, vault_uuid: [u8; 16]) -> Result<SyncState, StateError> {
    let path = state_file_path(state_dir, vault_uuid);
    if !path.exists() {
        return Ok(SyncState::empty(vault_uuid));
    }
    let bytes = fs::read(&path)?;
    let state = SyncState::from_canonical_cbor(&bytes).map_err(StateError::Decode)?;
    if state.vault_uuid != vault_uuid {
        return Err(StateError::VaultUuidMismatch {
            file_uuid_hex: canonical_hex(state.vault_uuid),
            expected_uuid_hex: canonical_hex(vault_uuid),
        });
    }
    Ok(state)
}

/// Atomically persist `SyncState` to `<state-dir>/<vault_uuid_hex>.state.cbor`.
/// Uses `tempfile::NamedTempFile::persist` for rename(2) / MoveFileExW
/// semantics — same `=3.27.0` exact pin as the vault format layer.
#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
pub fn save(state_dir: &Path, state: &SyncState) -> Result<(), StateError> {
    fs::create_dir_all(state_dir)?;
    let final_path = state_file_path(state_dir, state.vault_uuid);
    let bytes = state.to_canonical_cbor().map_err(StateError::Encode)?;

    let mut tmp = NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&bytes)?;
    tmp.persist(&final_path)
        .map_err(|e| StateError::Io(e.error))?;
    Ok(())
}

/// RAII guard for the per-vault exclusive lockfile. Holds the locked file
/// handle; releases on drop (kernel auto-releases flock when fd closes).
#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
#[derive(Debug)]
pub struct LockfileGuard {
    _file: File,
    path: PathBuf,
}

#[allow(dead_code)] // TODO(#113): consumed by Task 5 pipeline.
impl LockfileGuard {
    /// Acquire the exclusive lock on `<state-dir>/<vault_uuid_hex>.lock`.
    /// Returns `Err(StateError::LockfileHeld)` if another process already
    /// holds it.
    pub fn acquire(state_dir: &Path, vault_uuid: [u8; 16]) -> Result<Self, StateError> {
        fs::create_dir_all(state_dir)?;
        let path = lock_file_path(state_dir, vault_uuid);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        match Fs4FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { _file: file, path }),
            Err(TryLockError::WouldBlock) => Err(StateError::LockfileHeld(path)),
            Err(TryLockError::Error(io)) => Err(StateError::Io(io)),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// `canonical_hex` produces 32-char lowercase hex with no separator.
    #[test]
    fn canonical_hex_format() {
        let uuid = [0xab; 16];
        let hex = canonical_hex(uuid);
        assert_eq!(hex.len(), VAULT_UUID_HEX_LEN);
        assert_eq!(hex, "abababababababababababababababab");
    }

    /// `state_file_path` composes `<state-dir>/<hex>.state.cbor`.
    #[test]
    fn state_file_path_layout() {
        let dir = Path::new("/tmp/sync");
        let path = state_file_path(dir, [1; 16]);
        assert_eq!(
            path,
            PathBuf::from("/tmp/sync/01010101010101010101010101010101.state.cbor")
        );
    }

    /// `lock_file_path` composes `<state-dir>/<hex>.lock`.
    #[test]
    fn lock_file_path_layout() {
        let dir = Path::new("/tmp/sync");
        let path = lock_file_path(dir, [1; 16]);
        assert_eq!(
            path,
            PathBuf::from("/tmp/sync/01010101010101010101010101010101.lock")
        );
    }

    /// Load returns `SyncState::empty` when no file exists for the vault.
    #[test]
    fn load_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let loaded = load(dir.path(), [9; 16]).unwrap();
        assert_eq!(loaded.vault_uuid, [9; 16]);
        assert!(loaded.highest_vector_clock_seen.is_empty());
    }

    /// Save + load round-trips byte-identically.
    #[test]
    fn save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let state = SyncState::empty([7; 16]);
        save(dir.path(), &state).unwrap();
        let loaded = load(dir.path(), [7; 16]).unwrap();
        assert_eq!(loaded, state);
    }

    /// Loading a file whose internal vault_uuid mismatches the expected one
    /// (e.g. operator copied a state file from a different vault) returns
    /// the typed mismatch error.
    #[test]
    fn load_wrong_uuid_returns_mismatch_error() {
        let dir = TempDir::new().unwrap();
        let state = SyncState::empty([7; 16]);
        save(dir.path(), &state).unwrap();
        // Rename the file to make it look like the file for vault [9; 16].
        let from = state_file_path(dir.path(), [7; 16]);
        let to = state_file_path(dir.path(), [9; 16]);
        std::fs::rename(&from, &to).unwrap();
        let err = load(dir.path(), [9; 16]).unwrap_err();
        match err {
            StateError::VaultUuidMismatch {
                file_uuid_hex,
                expected_uuid_hex,
            } => {
                assert_eq!(file_uuid_hex, canonical_hex([7; 16]));
                assert_eq!(expected_uuid_hex, canonical_hex([9; 16]));
            }
            other => panic!("expected VaultUuidMismatch, got {other:?}"),
        }
    }

    /// First acquire succeeds; second concurrent acquire returns LockfileHeld.
    #[test]
    fn lockfile_collision_returns_held() {
        let dir = TempDir::new().unwrap();
        let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("first acquire");
        let err = LockfileGuard::acquire(dir.path(), [3; 16]).unwrap_err();
        match err {
            StateError::LockfileHeld(path) => {
                assert_eq!(path, lock_file_path(dir.path(), [3; 16]));
            }
            other => panic!("expected LockfileHeld, got {other:?}"),
        }
    }

    /// Releasing the first guard (drop) allows a subsequent acquire to succeed.
    #[test]
    fn lockfile_releases_on_drop() {
        let dir = TempDir::new().unwrap();
        {
            let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("first acquire");
        } // drop releases
        let _g2 =
            LockfileGuard::acquire(dir.path(), [3; 16]).expect("second acquire after first drop");
    }

    /// Different vault UUIDs do NOT collide on the lockfile (each vault
    /// has its own lock).
    #[test]
    fn lockfile_different_vaults_dont_collide() {
        let dir = TempDir::new().unwrap();
        let _g1 = LockfileGuard::acquire(dir.path(), [3; 16]).expect("vault A");
        let _g2 = LockfileGuard::acquire(dir.path(), [4; 16]).expect("vault B");
    }

    /// `default_state_dir` returns Some on supported platforms; we only
    /// assert it does not panic and that the path ends in `secretary/sync`
    /// when returned.
    #[test]
    fn default_state_dir_ends_in_sync_subdir() {
        if let Some(dir) = default_state_dir() {
            assert!(
                dir.ends_with("secretary/sync"),
                "expected path ending in secretary/sync, got {dir:?}"
            );
        }
    }
}
