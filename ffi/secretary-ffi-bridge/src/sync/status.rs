//! `sync_status` — read-only projection of the per-vault `SyncState` cache.
//! No secrets: loads `<state-dir>/<vault_uuid>.state.cbor` + its mtime.

use std::path::Path;
use std::time::UNIX_EPOCH;

use secretary_cli::state::{default_state_dir, load, state_file_path, StateError};

use crate::error::FfiVaultError;

/// One device's vector-clock entry — public metadata, never secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceClockDto {
    /// 32-char lowercase hex of the 16-byte device UUID.
    pub device_uuid_hex: String,
    /// The highest vector-clock counter seen from this device.
    pub counter: u64,
}

/// Read-only sync status for a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatusDto {
    /// False ⇒ no `.state.cbor` exists yet (this vault has never synced here).
    pub has_state: bool,
    /// Per-device highest-seen vector clock.
    pub device_clocks: Vec<DeviceClockDto>,
    /// Unix-ms mtime of the state file. `None` when `has_state` is false,
    /// or when the OS does not report a modification time (best-effort —
    /// `None` here does not by itself mean "never synced"; check `has_state`).
    pub last_state_write_ms: Option<u64>,
}

/// Load the sync status for `vault_uuid` from the default OS state dir.
///
/// # Errors
/// - [`FfiVaultError::SyncStateVaultMismatch`] — state file is for a different vault.
/// - [`FfiVaultError::SyncStateCorrupt`] — the CBOR failed to decode.
/// - [`FfiVaultError::SyncFailed`] — no platform state dir, or an I/O error.
pub fn sync_status(vault_uuid: [u8; 16]) -> Result<SyncStatusDto, FfiVaultError> {
    let state_dir = default_state_dir().ok_or_else(|| FfiVaultError::SyncFailed {
        detail: "no platform data directory available for the sync state cache".into(),
    })?;
    sync_status_in(&state_dir, vault_uuid)
}

/// Crate-internal seam taking an explicit state dir — used by the unit tests
/// and (Task 5) by `sync_vault`. Mirrors `settings::load_or_create_device_uuid_in`.
pub(crate) fn sync_status_in(
    state_dir: &Path,
    vault_uuid: [u8; 16],
) -> Result<SyncStatusDto, FfiVaultError> {
    let path = state_file_path(state_dir, vault_uuid);
    let meta = std::fs::metadata(&path).ok();
    let has_state = meta.is_some();
    // `Duration::as_millis()` returns `u128`; we truncate to `u64`.
    // `u64::MAX` ms from the UNIX epoch is ≈ year 584_556_020 — past any
    // horizon where this code will run — so the truncation is safe and not
    // worth a runtime check (same rationale as `auto_lock::now_ms`).
    let last_state_write_ms = meta
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64);
    let state = load(state_dir, vault_uuid).map_err(map_state_error)?;
    let device_clocks = state
        .highest_vector_clock_seen
        .iter()
        .map(|e| DeviceClockDto {
            device_uuid_hex: secretary_cli::state::canonical_hex(e.device_uuid),
            counter: e.counter,
        })
        .collect();
    Ok(SyncStatusDto { has_state, device_clocks, last_state_write_ms })
}

/// Map `cli::state::StateError` → `FfiVaultError`. Shared with `sync_vault` (Task 5).
pub(crate) fn map_state_error(e: StateError) -> FfiVaultError {
    match e {
        StateError::VaultUuidMismatch { .. } => FfiVaultError::SyncStateVaultMismatch,
        StateError::Decode(_) | StateError::Encode(_) => {
            FfiVaultError::SyncStateCorrupt { detail: e.to_string() }
        }
        StateError::LockfileHeld(_) => FfiVaultError::SyncInProgress,
        StateError::Io(_) => FfiVaultError::SyncFailed { detail: e.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_cli::state::save;
    use secretary_core::sync::SyncState;
    use tempfile::TempDir;

    #[test]
    fn status_in_reports_no_state_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let status = sync_status_in(dir.path(), [9u8; 16]).expect("status");
        assert!(!status.has_state);
        assert!(status.device_clocks.is_empty());
        assert!(status.last_state_write_ms.is_none());
    }

    #[test]
    fn status_in_reports_state_after_save() {
        let dir = TempDir::new().unwrap();
        // Use SyncState::new with a single entry (sorted invariant trivially
        // satisfied for a one-element vec).
        let state = SyncState::new(
            [7u8; 16],
            vec![secretary_core::vault::block::VectorClockEntry {
                device_uuid: [0xAB; 16],
                counter: 5,
            }],
        )
        .expect("single-entry clock must be accepted");
        save(dir.path(), &state).unwrap();
        let status = sync_status_in(dir.path(), [7u8; 16]).expect("status");
        assert!(status.has_state);
        assert_eq!(status.device_clocks.len(), 1);
        assert_eq!(status.device_clocks[0].counter, 5);
        assert_eq!(
            status.device_clocks[0].device_uuid_hex,
            "abababababababababababababababab"
        );
        assert!(status.last_state_write_ms.is_some());
    }

    #[test]
    fn status_in_surfaces_vault_mismatch() {
        let dir = TempDir::new().unwrap();
        let state = SyncState::empty([7u8; 16]);
        save(dir.path(), &state).unwrap();
        let from = secretary_cli::state::state_file_path(dir.path(), [7u8; 16]);
        let to = secretary_cli::state::state_file_path(dir.path(), [9u8; 16]);
        std::fs::rename(from, to).unwrap();
        let err = sync_status_in(dir.path(), [9u8; 16]).unwrap_err();
        assert!(matches!(err, FfiVaultError::SyncStateVaultMismatch));
    }
}
