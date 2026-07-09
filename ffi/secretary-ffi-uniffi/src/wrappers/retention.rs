//! uniffi-side value types mirroring the bridge `ExpiredEntry` /
//! `RetentionPurgeReport` DTOs (`secretary_ffi_bridge::retention`). Pure data;
//! the namespace fns convert to/from the bridge types. Field names/shapes
//! match `secretary.udl`'s `ExpiredEntry` / `RetentionPurgeReport`
//! dictionaries exactly.

/// One trash entry eligible for retention auto-purge (#402).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredEntry {
    /// 16-byte UUID of the trashed block.
    pub block_uuid: Vec<u8>,
    /// Signed death-clock (unix-millis) the age was computed from.
    pub tombstoned_at_ms: u64,
    /// `now_ms - tombstoned_at_ms` — how far past trashing this entry is.
    pub age_ms: u64,
}

/// Aggregate outcome of an `auto_purge_expired` call (#402).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: u32,
    /// Of `purged_count`, classified shared (>=1 non-owner recipient).
    pub shared_count: u32,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: u32,
    /// Of `purged_count`, unclassifiable (trash file unreadable).
    pub unknown_count: u32,
    /// On-disk trash files removed across every purged entry.
    pub files_removed: u32,
    /// Trash-file removals that errored (benign orphans; never fatal).
    pub files_failed: u32,
    /// The retention window this call applied (echoes the caller).
    pub window_ms: u64,
}
