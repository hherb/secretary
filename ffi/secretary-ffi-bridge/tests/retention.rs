//! Integration tests for the bridge retention auto-purge
//! (`expired_trash_entries` / `auto_purge_expired`) against a writable copy
//! of `golden_vault_001`. Each test gets its own tempdir so trash / purge
//! mutations never reach the on-disk fixture.
//!
//! Sibling of `empty_trash.rs`: mirrors its fixture setup, but exercises the
//! retention-window seam end-to-end — a non-empty preview (proving the
//! `ExpiredEntry` field mapping, including the exact `age_ms` arithmetic)
//! followed by a non-zero-target commit (proving the `auto_purge_expired`
//! write-back Ok-arm), with a fresh block planted specifically to prove the
//! age filter is load-bearing (it must be spared, not just uncounted).

// Shared helpers pulled in for the fixture; some items are only used by
// share_block.rs, so allow dead code at this test bin.
#[allow(dead_code)]
mod share_block_helpers;

use secretary_ffi_bridge::{auto_purge_expired, expired_trash_entries, trash_block};

use share_block_helpers::{
    fresh_writable_vault, save_one_record_block, DEVICE_UUID, NEW_RECORD_UUID, NOW_MS_BASE,
};

const OLD_BLOCK_UUID: [u8; 16] = [0xF1; 16];
const FRESH_BLOCK_UUID: [u8; 16] = [0xF2; 16];

/// Two trashed blocks, one old enough to be past the retention window and
/// one still fresh. `auto_purge_expired` must purge exactly the old one and
/// spare the fresh one — proving the age filter (not just the "is trashed"
/// filter) is what gates eligibility at the FFI seam.
#[test]
fn auto_purge_expired_purges_old_spares_fresh() {
    let (_tmp, identity, manifest) = fresh_writable_vault();

    const WINDOW_MS: u64 = 10_000;
    let old_tombstoned_at_ms = NOW_MS_BASE + 1_000;
    let fresh_tombstoned_at_ms = NOW_MS_BASE + 100_000;
    let now_ms = NOW_MS_BASE + 101_000;

    // OLD block: save + trash. Age at `now_ms` = 100_000, well past WINDOW_MS.
    save_one_record_block(
        &identity,
        &manifest,
        OLD_BLOCK_UUID,
        NEW_RECORD_UUID,
        "password",
        "hunter2",
        NOW_MS_BASE,
    );
    trash_block(
        &identity,
        &manifest,
        OLD_BLOCK_UUID,
        DEVICE_UUID,
        old_tombstoned_at_ms,
    )
    .expect("trash old block");

    // FRESH block: save + trash. Age at `now_ms` = 1_000, under WINDOW_MS.
    save_one_record_block(
        &identity,
        &manifest,
        FRESH_BLOCK_UUID,
        [0xDD; 16],
        "password",
        "hunter3",
        NOW_MS_BASE,
    );
    trash_block(
        &identity,
        &manifest,
        FRESH_BLOCK_UUID,
        DEVICE_UUID,
        fresh_tombstoned_at_ms,
    )
    .expect("trash fresh block");

    // Preview (non-empty): only the old block is eligible, with the exact
    // field mapping (block_uuid / tombstoned_at_ms / age_ms) checked.
    let preview = expired_trash_entries(&manifest, WINDOW_MS, now_ms);
    assert_eq!(
        preview.len(),
        1,
        "only the old block is past the retention window"
    );
    assert_eq!(preview[0].block_uuid, OLD_BLOCK_UUID);
    assert_eq!(preview[0].tombstoned_at_ms, old_tombstoned_at_ms);
    assert_eq!(preview[0].age_ms, 100_000);

    // Commit: purge everything past WINDOW_MS as of now_ms.
    let report = auto_purge_expired(&identity, &manifest, WINDOW_MS, now_ms, DEVICE_UUID)
        .expect("auto_purge_expired must succeed");

    assert_eq!(
        report.purged_count, 1,
        "exactly the old block is purged; the fresh one is spared"
    );
    assert_eq!(
        report.owner_only_count, 1,
        "the purged block was never shared, so it classifies as owner-only"
    );
    assert_eq!(report.shared_count, 0);
    assert_eq!(report.unknown_count, 0);
    assert!(
        report.files_removed >= 1,
        "at least the newly-purged trash file must have been removed, got {}",
        report.files_removed
    );
    assert_eq!(report.files_failed, 0);
    assert_eq!(report.window_ms, WINDOW_MS);

    // Age filter spared FRESH, and the OLD entry is now marked purged: a
    // second preview at the same (window_ms, now_ms) must be empty — OLD is
    // excluded because it is purged, FRESH is excluded because it is still
    // too young. If the age filter were wrong, FRESH would have been
    // purged too (report.purged_count would be 2, not 1) — this test's
    // exact-1 assertion above is what makes the age clause load-bearing.
    let after = expired_trash_entries(&manifest, WINDOW_MS, now_ms);
    assert!(
        after.is_empty(),
        "expected no eligible entries after purge, got {after:?}"
    );
}
