//! Sync DTOs crossing the Tauri IPC boundary (D.1.14). Projections of the
//! bridge `SyncStatusDto` / `SyncOutcomeDto`:
//!
//! - `SyncStatusDto` drops `device_clocks` (not surfaced in v1 — a plain
//!   "last synced" time is enough; see spec §3 "Out of scope").
//! - `SyncOutcomeDto` is a serde-tagged union for the TS discriminated type.
//!   `rename_all_fields` is required so `ConflictsPending`'s struct fields
//!   (`vetoes` / `collisions` / `manifestHash`) serialize as camelCase (the
//!   enum-level `rename_all` renames *variants* only, not struct-variant
//!   *fields*). The `VetoDto` / `CollisionDto` detail carries metadata only —
//!   no secret values (the bridge guarantees this; we map field-for-field).

use serde::{Deserialize, Serialize};

use secretary_ffi_bridge::{
    CollisionDto as BridgeCollisionDto, SyncOutcomeDto as BridgeSyncOutcomeDto,
    SyncStatusDto as BridgeSyncStatusDto, VetoDto as BridgeVetoDto,
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
    ConflictsPending {
        vetoes: Vec<VetoDto>,
        collisions: Vec<CollisionDto>,
        manifest_hash: Vec<u8>,
    },
    /// A would-be rollback was rejected; vault and state unchanged.
    RollbackRejected,
}

/// Outbound veto detail for the resolution modal (camelCase wire format).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VetoDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub field_names: Vec<String>,
    pub local_last_mod_ms: u64,
    pub peer_tombstoned_at_ms: u64,
    pub peer_device_hex: String,
}

/// Outbound auto-merge-collision summary (camelCase).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollisionDto {
    pub record_uuid_hex: String,
    pub field_names: Vec<String>,
}

/// Inbound per-record decision from the renderer (deserialized from the command arg).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VetoDecisionDto {
    pub record_uuid_hex: String,
    pub keep_local: bool,
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

impl From<BridgeVetoDto> for VetoDto {
    fn from(b: BridgeVetoDto) -> Self {
        Self {
            record_uuid_hex: b.record_uuid_hex,
            record_type: b.record_type,
            tags: b.tags,
            field_names: b.field_names,
            local_last_mod_ms: b.local_last_mod_ms,
            peer_tombstoned_at_ms: b.peer_tombstoned_at_ms,
            peer_device_hex: b.peer_device_hex,
        }
    }
}

impl From<BridgeCollisionDto> for CollisionDto {
    fn from(b: BridgeCollisionDto) -> Self {
        Self {
            record_uuid_hex: b.record_uuid_hex,
            field_names: b.field_names,
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
            BridgeSyncOutcomeDto::ConflictsPending {
                vetoes,
                collisions,
                manifest_hash,
            } => Self::ConflictsPending {
                vetoes: vetoes.into_iter().map(VetoDto::from).collect(),
                collisions: collisions.into_iter().map(CollisionDto::from).collect(),
                manifest_hash,
            },
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
    fn conflicts_pending_serializes_detail() {
        let v = serde_json::to_value(SyncOutcomeDto::ConflictsPending {
            vetoes: vec![VetoDto {
                record_uuid_hex: "0a".repeat(16),
                record_type: "login".into(),
                tags: vec!["work".into()],
                field_names: vec!["password".into()],
                local_last_mod_ms: 10,
                peer_tombstoned_at_ms: 20,
                peer_device_hex: "9c".repeat(16),
            }],
            collisions: vec![CollisionDto {
                record_uuid_hex: "0a".repeat(16),
                field_names: vec!["password".into()],
            }],
            manifest_hash: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(v["kind"], "conflictsPending");
        assert_eq!(v["vetoes"][0]["recordType"], "login");
        assert_eq!(v["vetoes"][0]["localLastModMs"], 10);
        assert_eq!(v["vetoes"][0]["peerDeviceHex"], "9c".repeat(16));
        assert_eq!(v["collisions"][0]["fieldNames"][0], "password");
        assert_eq!(v["manifestHash"], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn veto_decision_dto_deserializes_camelcase() {
        let d: VetoDecisionDto =
            serde_json::from_value(serde_json::json!({ "recordUuidHex": "0a", "keepLocal": true }))
                .unwrap();
        assert!(d.keep_local);
        assert_eq!(d.record_uuid_hex, "0a");
    }
}
