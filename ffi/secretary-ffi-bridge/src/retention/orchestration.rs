//! Retention auto-purge FFI projection (#402): the pure `expired_trash_entries`
//! preview, the `auto_purge_expired` commit, their bridge-side DTOs, and an
//! exhaustive core-error mapper. Sibling of [`crate::purge`]; the commit is
//! byte-for-byte `empty_trash`'s orchestration plus two scalar args
//! (`window_ms`, `now_ms`) and one pass-through report field (`window_ms`).
//! `docs/vault-format.md` §7 step 5.
//!
//! NOTE(#402 Task 1): the free-function entry points (`auto_purge_expired`,
//! `expired_trash_entries`) and their supporting imports (`OsRng`,
//! `OpenVault`/`VaultError`, `FfiVaultError`, `UnlockedIdentity`,
//! `OpenVaultManifest`) land in Task 2. This task only carries the
//! bridge-side DTOs + `From` impls, so those imports are intentionally
//! absent here (clippy `-D warnings` would reject them unused).

/// One trash entry eligible for retention auto-purge — the pure preview
/// record a platform shows before committing. Bridge projection of
/// [`secretary_core::vault::ExpiredEntry`], field-for-field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredEntry {
    /// The trashed block's UUID.
    pub block_uuid: [u8; 16],
    /// The signed death-clock the age was computed from.
    pub tombstoned_at_ms: u64,
    /// `now_ms.saturating_sub(tombstoned_at_ms)` — how far past trashing
    /// this entry is (always `> window_ms` for an eligible entry).
    pub age_ms: u64,
}

impl From<secretary_core::vault::ExpiredEntry> for ExpiredEntry {
    fn from(e: secretary_core::vault::ExpiredEntry) -> Self {
        ExpiredEntry {
            block_uuid: e.block_uuid,
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        }
    }
}

/// Aggregate outcome of an `auto_purge_expired` call. Bridge projection
/// of [`secretary_core::vault::RetentionPurgeReport`]: every count narrowed
/// `usize`→`u32` for uniffi/pyo3 portability (a vault with more than 2^32
/// trashed blocks is not a realistic state); `window_ms` passes through.
///
/// Not `Default`: the empty-target return still carries the caller's real
/// `window_ms`, so a zero-count report is self-describing.
#[derive(Debug, Clone)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: u32,
    /// Of `purged_count`, classified shared (≥1 non-owner recipient).
    pub shared_count: u32,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: u32,
    /// Of `purged_count`, unclassifiable (trash file unreadable — honest
    /// "unknown", never fabricated).
    pub unknown_count: u32,
    /// On-disk `trash/` files removed across every purged entry.
    pub files_removed: u32,
    /// `trash/` removals that errored (benign orphans; never fatal).
    pub files_failed: u32,
    /// The retention window this call applied (echoes the caller).
    pub window_ms: u64,
}

impl From<secretary_core::vault::RetentionPurgeReport> for RetentionPurgeReport {
    fn from(r: secretary_core::vault::RetentionPurgeReport) -> Self {
        RetentionPurgeReport {
            purged_count: r.purged_count as u32,
            shared_count: r.shared_count as u32,
            owner_only_count: r.owner_only_count as u32,
            unknown_count: r.unknown_count as u32,
            files_removed: r.files_removed as u32,
            files_failed: r.files_failed as u32,
            window_ms: r.window_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_entry_from_core_projects_all_fields() {
        let core = secretary_core::vault::ExpiredEntry {
            block_uuid: [0xAB; 16],
            tombstoned_at_ms: 1_000,
            age_ms: 4_000,
        };
        let bridge = ExpiredEntry::from(core);
        assert_eq!(bridge.block_uuid, [0xAB; 16]);
        assert_eq!(bridge.tombstoned_at_ms, 1_000);
        assert_eq!(bridge.age_ms, 4_000);
    }

    #[test]
    fn retention_report_from_core_narrows_usize_and_passes_window() {
        let core = secretary_core::vault::RetentionPurgeReport {
            purged_count: 3,
            shared_count: 1,
            owner_only_count: 2,
            unknown_count: 0,
            files_removed: 3,
            files_failed: 0,
            window_ms: 7_776_000_000,
        };
        let bridge = RetentionPurgeReport::from(core);
        assert_eq!(bridge.purged_count, 3);
        assert_eq!(bridge.shared_count, 1);
        assert_eq!(bridge.owner_only_count, 2);
        assert_eq!(bridge.unknown_count, 0);
        assert_eq!(bridge.files_removed, 3);
        assert_eq!(bridge.files_failed, 0);
        assert_eq!(bridge.window_ms, 7_776_000_000);
    }

    #[test]
    fn default_window_re_export_matches_core() {
        assert_eq!(
            crate::DEFAULT_RETENTION_WINDOW_MS,
            secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS
        );
    }
}
