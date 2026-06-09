//! uniffi-side value types mirroring the bridge sync DTOs
//! (`secretary_ffi_bridge::sync::{status,dto}`). Pure data — no logic;
//! the namespace fns convert these to/from the bridge types. Field names
//! and shapes match `secretary.udl` exactly (uniffi 0.31 scaffolding maps
//! `crate::TypeName` from the UDL).

/// One device's vector-clock entry — public metadata, never secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceClockDto {
    pub device_uuid_hex: String,
    pub counter: u64,
}

/// Read-only sync status for a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatusDto {
    pub has_state: bool,
    pub device_clocks: Vec<DeviceClockDto>,
    pub last_state_write_ms: Option<u64>,
}

/// Metadata-only tombstone-dispute projection (NO secret values — field
/// *names* only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VetoDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub field_names: Vec<String>,
    pub local_last_mod_ms: u64,
    pub peer_tombstoned_at_ms: u64,
    pub peer_device_hex: String,
}

/// Metadata-only field-collision summary for the "auto-merged" notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionDto {
    pub record_uuid_hex: String,
    pub field_names: Vec<String>,
}

/// Caller's per-record decision. `keep_local = true` -> reject the peer
/// tombstone; `false` -> accept the delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VetoDecisionDto {
    pub record_uuid_hex: String,
    pub keep_local: bool,
}

/// Result of one sync pass. Mirrors `secretary_ffi_bridge::SyncOutcomeDto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcomeDto {
    NothingToDo,
    AppliedAutomatically,
    SilentMerge,
    MergedClean,
    ConflictsPending {
        vetoes: Vec<VetoDto>,
        collisions: Vec<CollisionDto>,
        manifest_hash: Vec<u8>,
    },
    RollbackRejected,
}
