//! uniffi-side value type mirroring the bridge `PurgeReport` DTO
//! (`secretary_ffi_bridge::purge`). Pure data — no logic; the namespace
//! fn converts this to/from the bridge type. Field names and shapes
//! match `secretary.udl`'s `PurgeReport` dictionary exactly (uniffi 0.31
//! scaffolding maps `crate::PurgeReport` from the UDL).

/// Report of a completed (or already-completed) `purge_block` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    pub block_uuid: Vec<u8>,
    pub was_shared: Option<bool>,
    pub recipient_count: Option<u16>,
    pub files_removed: u32,
}
