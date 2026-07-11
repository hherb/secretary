//! uniffi-side value type mirroring the bridge `TrashedBlock` DTO
//! (`secretary_ffi_bridge::TrashedBlock`). Pure data; the namespace fn
//! converts from the bridge type. Field names/shapes match
//! `secretary.udl`'s `TrashedBlock` dictionary exactly.

/// One trashed block, projected by name for a Trash view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashedBlock {
    /// 16-byte UUID of the trashed block.
    pub block_uuid: Vec<u8>,
    /// Human-readable block name, recovered from the newest trashed file.
    pub block_name: String,
    /// Unix-millis the block was moved to trash.
    pub tombstoned_at_ms: u64,
    /// 16-byte UUID of the device that trashed the block.
    pub tombstoned_by: Vec<u8>,
}
