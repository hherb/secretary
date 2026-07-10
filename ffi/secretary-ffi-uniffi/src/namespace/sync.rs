//! uniffi namespace fns for the sync surface (#187) — `sync_status`,
//! `sync_vault`, `sync_commit_decisions` plus the bridge→uniffi DTO
//! converters. Extracted from `namespace/mod.rs` to keep that file under
//! the 500-line guideline; the logic lives in `secretary-ffi-bridge` and
//! this layer only adapts argument types and translates bridge errors.

use crate::errors::VaultError;
use crate::wrappers::sync::{
    CollisionDto, DeviceClockDto, SyncOutcomeDto, SyncStatusDto, VetoDecisionDto, VetoDto,
};

/// Read-only sync status for a vault. uniffi-projected (#187).
///
/// `state_dir` is the caller's sync-state directory (mobile sandbox path;
/// tests pass a tempdir). `vault_uuid` must be exactly 16 bytes.
///
/// # Errors
/// - [`VaultError::InvalidArgument`] — wrong-length `vault_uuid`.
/// - [`VaultError::SyncStateVaultMismatch`] / [`VaultError::SyncStateCorrupt`] /
///   [`VaultError::SyncFailed`] — see the bridge `sync_status_in` docs.
pub fn sync_status(state_dir: String, vault_uuid: Vec<u8>) -> Result<SyncStatusDto, VaultError> {
    let vault_uuid = super::uuid_from_vec(&vault_uuid, "vault_uuid")?;
    secretary_ffi_bridge::sync_status_in(std::path::Path::new(&state_dir), vault_uuid)
        .map(sync_status_from_bridge)
        .map_err(VaultError::from)
}

/// Run one manual sync pass. uniffi-projected (#187).
///
/// `password` is a zero-copy borrow of the foreign caller's buffer
/// (`[ByRef] bytes`, #307); the one controlled copy made here is wrapped
/// in `SecretBytes` (ZeroizeOnDrop) immediately. `now_ms` is the caller's
/// wall-clock used as the merge timestamp on a clean concurrent merge.
///
/// # Errors
/// See the bridge `sync_vault_in` docs (`SyncInProgress`,
/// `WrongPasswordOrCorrupt`, `SyncEvidenceStale`, `SyncFailed`, ...).
pub fn sync_vault(
    state_dir: String,
    vault_folder: String,
    password: &[u8],
    now_ms: u64,
) -> Result<SyncOutcomeDto, VaultError> {
    use secretary_core::crypto::secret::SecretBytes;
    // The borrowed `password` is foreign-owned (the adapter scrubs it);
    // SecretBytes owns the single Rust-side copy and its ZeroizeOnDrop
    // wipes that allocation when the bridge `_in` seam drops it.
    secretary_ffi_bridge::sync_vault_in(
        std::path::Path::new(&state_dir),
        std::path::Path::new(&vault_folder),
        SecretBytes::new(password.to_vec()),
        now_ms,
    )
    .map(sync_outcome_from_bridge)
    .map_err(VaultError::from)
}

/// Commit tombstone-veto decisions for a paused sync pass. uniffi-projected (#187).
///
/// `manifest_hash` is the opaque 32-byte freshness token from a prior
/// `sync_vault` `ConflictsPending` result.
///
/// # Errors
/// See the bridge `sync_commit_decisions_in` docs
/// (`SyncDecisionsIncomplete`, `SyncEvidenceStale`, `SyncFailed`, ...).
pub fn sync_commit_decisions(
    state_dir: String,
    vault_folder: String,
    password: &[u8],
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> Result<SyncOutcomeDto, VaultError> {
    use secretary_core::crypto::secret::SecretBytes;
    // Field-by-field rather than a From impl: the orphan rule forbids
    // `impl From<uniffi DTO> for the foreign bridge DTO` in this crate.
    let bridge_decisions = decisions
        .into_iter()
        .map(|d| secretary_ffi_bridge::VetoDecisionDto {
            record_uuid_hex: d.record_uuid_hex,
            keep_local: d.keep_local,
        })
        .collect();
    // `[ByRef] bytes` (#307): the borrowed `password` is foreign-owned
    // (the adapter scrubs it); SecretBytes owns the single Rust-side copy
    // and its ZeroizeOnDrop wipes that allocation when the bridge `_in`
    // seam drops it.
    secretary_ffi_bridge::sync_commit_decisions_in(
        std::path::Path::new(&state_dir),
        std::path::Path::new(&vault_folder),
        SecretBytes::new(password.to_vec()),
        bridge_decisions,
        manifest_hash,
        now_ms,
    )
    .map(sync_outcome_from_bridge)
    .map_err(VaultError::from)
}

/// Convert the bridge `SyncStatusDto` to the uniffi value type.
fn sync_status_from_bridge(s: secretary_ffi_bridge::SyncStatusDto) -> SyncStatusDto {
    SyncStatusDto {
        has_state: s.has_state,
        device_clocks: s
            .device_clocks
            .into_iter()
            .map(|c| DeviceClockDto {
                device_uuid_hex: c.device_uuid_hex,
                counter: c.counter,
            })
            .collect(),
        last_state_write_ms: s.last_state_write_ms,
    }
}

/// Convert the bridge `SyncOutcomeDto` to the uniffi value type.
fn sync_outcome_from_bridge(o: secretary_ffi_bridge::SyncOutcomeDto) -> SyncOutcomeDto {
    use secretary_ffi_bridge::SyncOutcomeDto as B;
    match o {
        B::NothingToDo => SyncOutcomeDto::NothingToDo,
        B::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
        B::SilentMerge => SyncOutcomeDto::SilentMerge,
        B::MergedClean => SyncOutcomeDto::MergedClean,
        B::RollbackRejected => SyncOutcomeDto::RollbackRejected,
        B::ConflictsPending {
            vetoes,
            collisions,
            manifest_hash,
        } => SyncOutcomeDto::ConflictsPending {
            vetoes: vetoes
                .into_iter()
                .map(|v| VetoDto {
                    record_uuid_hex: v.record_uuid_hex,
                    record_type: v.record_type,
                    tags: v.tags,
                    field_names: v.field_names,
                    local_last_mod_ms: v.local_last_mod_ms,
                    peer_tombstoned_at_ms: v.peer_tombstoned_at_ms,
                    peer_device_hex: v.peer_device_hex,
                })
                .collect(),
            collisions: collisions
                .into_iter()
                .map(|c| CollisionDto {
                    record_uuid_hex: c.record_uuid_hex,
                    field_names: c.field_names,
                })
                .collect(),
            manifest_hash,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::VaultError;

    #[test]
    fn sync_status_empty_dir_reports_no_state() {
        let dir = tempfile::tempdir().unwrap();
        let status = super::sync_status(dir.path().to_str().unwrap().to_string(), vec![9u8; 16])
            .expect("status");
        assert!(!status.has_state);
        assert!(status.device_clocks.is_empty());
    }

    #[test]
    fn sync_status_wrong_length_vault_uuid_is_invalid_argument() {
        let dir = tempfile::tempdir().unwrap();
        match super::sync_status(dir.path().to_str().unwrap().to_string(), vec![0u8; 15]) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("16 bytes") && detail.contains("got 15"));
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn sync_commit_decisions_bad_manifest_hash_len_is_sync_failed() {
        let dir = tempfile::tempdir().unwrap();
        let folder = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data/golden_vault_001");
        match super::sync_commit_decisions(
            dir.path().to_str().unwrap().to_string(),
            folder.to_str().unwrap().to_string(),
            b"correct horse battery staple",
            vec![],
            vec![0u8; 5], // != 32 -> reject before vault open
            0,
        ) {
            Err(VaultError::SyncFailed { detail }) => {
                assert!(detail.contains("manifest_hash must be 32 bytes"));
            }
            other => panic!("expected SyncFailed, got {other:?}"),
        }
    }
}
