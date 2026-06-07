//! Sync DTOs crossing the Tauri IPC boundary (D.1.14). Projections of the
//! bridge `SyncStatusDto` / `SyncOutcomeDto`:
//!
//! - `SyncStatusDto` drops `device_clocks` (not surfaced in v1 — a plain
//!   "last synced" time is enough; see spec §3 "Out of scope").
//! - `SyncOutcomeDto` is a serde-tagged union for the TS discriminated type.
//!   `rename_all_fields` is required so `ConflictsPending`'s `veto_count`
//!   field serializes as `vetoCount` (the enum-level `rename_all` renames
//!   *variants* only, not struct-variant *fields*).

use serde::Serialize;

use secretary_ffi_bridge::{
    SyncOutcomeDto as BridgeSyncOutcomeDto, SyncStatusDto as BridgeSyncStatusDto,
};

/// Desktop projection of the bridge [`BridgeSyncStatusDto`] for the TopBar
/// sync pill. Drops `device_clocks` (not surfaced in v1; spec §3).
/// `has_state` is `false` until the vault first syncs on this device;
/// `last_state_write_ms` is `None` when never synced or when the OS does
/// not report an mtime (read by the TS `lastSyncedLabel`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub has_state: bool,
    pub last_state_write_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SyncOutcomeDto {
    /// No remote state to ingest; vault and state unchanged.
    NothingToDo,
    /// A fast-forward / single-writer advance was applied; state persisted.
    AppliedAutomatically,
    /// Concurrent but non-diverging copies merged silently; state persisted.
    SilentMerge,
    /// Concurrent diverging copies merged cleanly with no vetoes; state persisted.
    MergedClean,
    /// Concurrent diverging copies produced tombstone vetoes; pass paused, nothing written.
    ConflictsPending { veto_count: u32 },
    /// A would-be rollback was rejected; vault and state unchanged.
    RollbackRejected,
}

impl From<BridgeSyncStatusDto> for SyncStatusDto {
    fn from(b: BridgeSyncStatusDto) -> Self {
        // device_clocks intentionally dropped (not surfaced in v1).
        Self {
            has_state: b.has_state,
            last_state_write_ms: b.last_state_write_ms,
        }
    }
}

impl From<BridgeSyncOutcomeDto> for SyncOutcomeDto {
    fn from(b: BridgeSyncOutcomeDto) -> Self {
        match b {
            BridgeSyncOutcomeDto::NothingToDo => Self::NothingToDo,
            BridgeSyncOutcomeDto::AppliedAutomatically => Self::AppliedAutomatically,
            BridgeSyncOutcomeDto::SilentMerge => Self::SilentMerge,
            BridgeSyncOutcomeDto::MergedClean => Self::MergedClean,
            BridgeSyncOutcomeDto::ConflictsPending { veto_count } => {
                Self::ConflictsPending { veto_count }
            }
            BridgeSyncOutcomeDto::RollbackRejected => Self::RollbackRejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_dto_serializes_camelcase_without_device_clocks() {
        let dto = SyncStatusDto {
            has_state: true,
            last_state_write_ms: Some(1_700_000_000_000),
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert_eq!(
            v,
            json!({ "hasState": true, "lastStateWriteMs": 1_700_000_000_000u64 })
        );
        assert!(
            v.get("deviceClocks").is_none(),
            "device_clocks must be dropped"
        );
    }

    #[test]
    fn status_dto_null_write_ms_when_never_synced() {
        let dto = SyncStatusDto {
            has_state: false,
            last_state_write_ms: None,
        };
        let v = serde_json::to_value(&dto).unwrap();
        // `None` must serialize as explicit `null`, not be omitted — the TS side
        // distinguishes `null` ("never synced here") from a missing key.
        assert_eq!(v, json!({ "hasState": false, "lastStateWriteMs": null }));
    }

    #[test]
    fn outcome_unit_variants_serialize_as_tagged_kind() {
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::NothingToDo).unwrap(),
            json!({ "kind": "nothingToDo" })
        );
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::AppliedAutomatically).unwrap(),
            json!({ "kind": "appliedAutomatically" })
        );
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::RollbackRejected).unwrap(),
            json!({ "kind": "rollbackRejected" })
        );
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::SilentMerge).unwrap(),
            json!({ "kind": "silentMerge" })
        );
        assert_eq!(
            serde_json::to_value(SyncOutcomeDto::MergedClean).unwrap(),
            json!({ "kind": "mergedClean" })
        );
    }

    #[test]
    fn conflicts_pending_serializes_kind_and_camelcase_veto_count() {
        let v = serde_json::to_value(SyncOutcomeDto::ConflictsPending { veto_count: 3 }).unwrap();
        assert_eq!(v, json!({ "kind": "conflictsPending", "vetoCount": 3 }));
    }
}
