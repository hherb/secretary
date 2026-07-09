//! Retention auto-purge (#402): pure eligibility selection for
//! permanently purging trashed blocks older than a retention window, plus
//! the `auto_purge_expired` orchestrator. `docs/vault-format.md` §7 step 5.
//!
//! The selector is pure and I/O-free; the commit reuses
//! `purge::purge_batch_commit` (the same batch path `empty_trash` uses) so
//! both share one audited manifest-write sequence.

use std::path::Path;

use rand_core::{CryptoRng, RngCore};

use crate::vault::manifest::Manifest;
use crate::vault::purge::{classify_trash_target, purge_batch_commit};
use crate::vault::{OpenVault, VaultError};

/// Default trash retention window: 90 days in milliseconds
/// (`docs/vault-format.md` §7 step 5). Named to avoid a magic number;
/// the value is `90 * 24 * 60 * 60 * 1000` = 7_776_000_000 ms, which
/// exceeds `u32::MAX`, hence `u64`.
pub const DEFAULT_RETENTION_WINDOW_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// One trash entry eligible for retention auto-purge — the pure
/// preview record a platform shows before committing a purge.
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

/// Indices into `manifest.trash` of every entry eligible for retention
/// auto-purge (design §3.1): not already purged, not live in
/// `manifest.blocks`, and strictly older than `window_ms`. Pure. Shared
/// by [`expired_trash_entries`] (public preview) and
/// `auto_purge_expired` (commit target selection).
pub(crate) fn expired_trash_indices(
    manifest: &Manifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<usize> {
    manifest
        .trash
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.purged_at_ms.is_none()
                && now_ms.saturating_sub(e.tombstoned_at_ms) > window_ms
                && !manifest.blocks.iter().any(|b| b.block_uuid == e.block_uuid)
        })
        .map(|(i, _)| i)
        .collect()
}

/// Pure, side-effect-free preview of the entries retention auto-purge
/// would permanently remove for `(window_ms, now_ms)`. No I/O, no
/// recipient classification (that is best-effort, inside the commit
/// path). `docs/vault-format.md` §7 step 5 (#402).
pub fn expired_trash_entries(
    manifest: &Manifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<ExpiredEntry> {
    expired_trash_indices(manifest, window_ms, now_ms)
        .into_iter()
        .map(|i| {
            let e = &manifest.trash[i];
            ExpiredEntry {
                block_uuid: e.block_uuid,
                tombstoned_at_ms: e.tombstoned_at_ms,
                age_ms: now_ms.saturating_sub(e.tombstoned_at_ms),
            }
        })
        .collect()
}

/// Aggregate outcome of an [`auto_purge_expired`] call.
///
/// `window_ms` echoes the caller's window so a report is self-describing
/// even when `purged_count == 0`. Not `Default`: the empty-target return
/// still carries the real `window_ms`.
#[derive(Debug, Clone)]
pub struct RetentionPurgeReport {
    /// Entries newly marked purged by this call.
    pub purged_count: usize,
    /// Of `purged_count`, classified shared (≥1 non-owner recipient).
    pub shared_count: usize,
    /// Of `purged_count`, classified owner-only.
    pub owner_only_count: usize,
    /// Of `purged_count`, unclassifiable (trash file unreadable — honest
    /// "unknown", never fabricated).
    pub unknown_count: usize,
    /// On-disk `trash/` files removed across every purged entry.
    pub files_removed: usize,
    /// `trash/` removals that errored (benign orphans; logged, never fatal).
    pub files_failed: usize,
    /// The retention window this call applied.
    pub window_ms: u64,
}

/// Permanently purge every trashed block older than `window_ms` — the
/// retention auto-purge operation (`docs/vault-format.md` §7 step 5, #402).
///
/// Eligibility is the pure `expired_trash_indices` rule: not already
/// purged, not live in `manifest.blocks`, and `now_ms − tombstoned_at_ms >
/// window_ms` (saturating, exclusive boundary). Targets are classified for
/// reporting (best-effort, before the write) and committed in one batch via
/// `purge::purge_batch_commit` — one shared `now_ms`, one clock tick, one
/// signature, one write — then their `trash/` files are best-effort removed.
///
/// An empty target set returns a zero-count report **without touching the
/// manifest** (no clock tick, no re-sign, no write), mirroring
/// [`empty_trash`](crate::vault::empty_trash).
///
/// Wall-clock (`tombstoned_at_ms`) gates cleanup timing only, never a merge
/// decision — see the design doc §3.3 / vault-format §7 step 5. This is the
/// same `purged_at_ms` state transition as user-initiated `empty_trash`;
/// it adds no security surface.
pub fn auto_purge_expired(
    folder: &Path,
    open: &mut OpenVault,
    window_ms: u64,
    now_ms: u64,
    device_uuid: [u8; 16],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RetentionPurgeReport, VaultError> {
    let targets = expired_trash_indices(&open.manifest, window_ms, now_ms);
    let mut report = RetentionPurgeReport {
        purged_count: 0,
        shared_count: 0,
        owner_only_count: 0,
        unknown_count: 0,
        files_removed: 0,
        files_failed: 0,
        window_ms,
    };
    if targets.is_empty() {
        return Ok(report);
    }

    // Classify BEFORE the write, while trash files are still present
    // (reporting-only, best-effort — mirrors empty_trash).
    for &idx in &targets {
        let block_uuid = open.manifest.trash[idx].block_uuid;
        let tombstoned_at_ms = open.manifest.trash[idx].tombstoned_at_ms;
        match classify_trash_target(folder, &block_uuid, tombstoned_at_ms, &open.owner_card) {
            Some((true, _)) => report.shared_count += 1,
            Some((false, _)) => report.owner_only_count += 1,
            None => report.unknown_count += 1,
        }
    }

    let (removed, failed) = purge_batch_commit(
        folder,
        open,
        &targets,
        now_ms,
        device_uuid,
        rng,
        "auto_purge_expired: failed to write manifest.cbor.enc",
    )?;
    report.purged_count = targets.len();
    report.files_removed = removed;
    report.files_failed = failed;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::manifest::{BlockEntry, KdfParamsRef, Manifest, TrashEntry};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn empty_manifest() -> Manifest {
        // `expired_trash_entries` reads only `trash` and `blocks`; the
        // remaining fields are filled with minimal placeholder values
        // matching the pattern in `manifest.rs`'s own `minimal_manifest`
        // test helper. `UUID_LEN`/`SALT_LEN`/`MANIFEST_VERSION_V1` etc.
        // are private to `manifest.rs`, so array lengths are spelled out.
        Manifest {
            manifest_version: 1,
            vault_uuid: [0x01; 16],
            format_version: crate::version::FORMAT_VERSION,
            suite_id: crate::version::SUITE_ID,
            owner_user_uuid: [0x02; 16],
            vector_clock: Vec::new(),
            blocks: Vec::new(),
            trash: Vec::new(),
            kdf_params: KdfParamsRef {
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 1,
                salt: [0x11; 32],
            },
            unknown: BTreeMap::new(),
        }
    }

    fn trash_entry(block_uuid: [u8; 16], tombstoned_at_ms: u64, purged: Option<u64>) -> TrashEntry {
        TrashEntry {
            block_uuid,
            tombstoned_at_ms,
            tombstoned_by: [0u8; 16],
            fingerprint: None,
            purged_at_ms: purged,
            unknown: BTreeMap::new(),
        }
    }

    fn push_live_block(manifest: &mut Manifest, block_uuid: [u8; 16]) {
        manifest.blocks.push(BlockEntry {
            block_uuid,
            block_name: String::new(),
            fingerprint: [0u8; 32],
            recipients: Vec::new(),
            vector_clock_summary: Vec::new(),
            suite_id: crate::version::SUITE_ID,
            created_at_ms: 0,
            last_mod_ms: 0,
            unknown: BTreeMap::new(),
        });
    }

    const WINDOW: u64 = 100;

    #[test]
    fn old_not_purged_not_live_is_eligible() {
        let mut m = empty_manifest();
        m.trash.push(trash_entry([1u8; 16], 1_000, None));
        // now - tombstoned = 5000 - 1000 = 4000 > 100
        let got = expired_trash_entries(&m, WINDOW, 5_000);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].block_uuid, [1u8; 16]);
        assert_eq!(got[0].tombstoned_at_ms, 1_000);
        assert_eq!(got[0].age_ms, 4_000);
    }

    #[test]
    fn already_purged_is_skipped() {
        let mut m = empty_manifest();
        m.trash.push(trash_entry([1u8; 16], 1_000, Some(2_000)));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn too_young_is_skipped() {
        let mut m = empty_manifest();
        // age = 50 < window 100
        m.trash.push(trash_entry([1u8; 16], 4_950, None));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn boundary_equal_window_is_skipped() {
        let mut m = empty_manifest();
        // age exactly == window; exclusive boundary => not eligible
        m.trash.push(trash_entry([1u8; 16], 4_900, None));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn future_dated_tombstone_saturates_to_zero_age_skipped() {
        let mut m = empty_manifest();
        // tombstoned_at_ms > now => saturating_sub => age 0 => never eligible
        m.trash.push(trash_entry([1u8; 16], 9_000, None));
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn live_uuid_is_skipped_even_if_old() {
        let mut m = empty_manifest();
        m.trash.push(trash_entry([7u8; 16], 1_000, None));
        // Same uuid live in blocks => concurrent restore won => never purge.
        push_live_block(&mut m, [7u8; 16]);
        assert!(expired_trash_entries(&m, WINDOW, 5_000).is_empty());
    }

    #[test]
    fn default_window_is_ninety_days() {
        assert_eq!(DEFAULT_RETENTION_WINDOW_MS, 90 * 24 * 60 * 60 * 1000);
    }

    proptest! {
        /// Every returned entry genuinely satisfies all three eligibility
        /// clauses, and every non-returned trash entry fails at least one —
        /// selection is exactly the predicate, for arbitrary trash lists.
        #[test]
        fn selection_matches_predicate(
            seeds in proptest::collection::vec((any::<u8>(), 0u64..10_000, any::<bool>()), 0..20),
            window in 0u64..5_000,
            now in 0u64..10_000,
        ) {
            let mut m = empty_manifest();
            for (i, (uuid_seed, t, purged)) in seeds.iter().enumerate() {
                // distinct uuids so liveness/dedup is unambiguous
                let mut uuid = [*uuid_seed; 16];
                uuid[0] = i as u8;
                m.trash.push(trash_entry(uuid, *t, if *purged { Some(1) } else { None }));
            }
            let picked: std::collections::HashSet<usize> =
                expired_trash_indices(&m, window, now).into_iter().collect();
            for (i, e) in m.trash.iter().enumerate() {
                let eligible = e.purged_at_ms.is_none()
                    && now.saturating_sub(e.tombstoned_at_ms) > window
                    && !m.blocks.iter().any(|b| b.block_uuid == e.block_uuid);
                prop_assert_eq!(picked.contains(&i), eligible);
            }
        }
    }
}
