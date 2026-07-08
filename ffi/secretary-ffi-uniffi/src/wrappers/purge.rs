//! uniffi-side value types mirroring the bridge `PurgeReport` /
//! `EmptyTrashReport` DTOs (`secretary_ffi_bridge::purge`). Pure data —
//! no logic; the namespace fns convert these to/from the bridge types.
//! Field names and shapes match `secretary.udl`'s `PurgeReport` /
//! `EmptyTrashReport` dictionaries exactly (uniffi 0.31 scaffolding maps
//! `crate::PurgeReport` / `crate::EmptyTrashReport` from the UDL).

/// Report of a completed (or already-completed) `purge_block` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    pub block_uuid: Vec<u8>,
    pub was_shared: Option<bool>,
    pub recipient_count: Option<u16>,
    pub files_removed: u32,
}

/// Report of a completed `empty_trash` call: aggregate counts across
/// every `TrashEntry` purged by this call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmptyTrashReport {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
}
