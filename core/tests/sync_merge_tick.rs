//! A merge ticks the merging device's clock entry (#744).
//!
//! crypto-design §10: on a concurrent manifest clock "the merged manifest's
//! vector clock is the component-wise max of the two, plus one for the merging
//! device". §11.2 says the same of a merged block's clock. Before #744 the
//! manifest clock was written unticked and the block clock ticked the owner's
//! `user_uuid` instead of a device.

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, DraftMerge, SyncError, SyncOutcome, SyncState,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{open_vault, Record, Unlocker, VaultError};

mod fixtures;
mod sync_helpers;

use fixtures::extract_vault_uuid;

const CANONICAL_DEVICE: [u8; 16] = [0x0A; 16];
const SIBLING_DEVICE: [u8; 16] = [0x0B; 16];
const LOCAL_SEEN_DEVICE: [u8; 16] = [0x0C; 16];
const MERGING_DEVICE: [u8; 16] = [0x0D; 16];
const SIBLING_MANIFEST: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";
const SECOND_SIBLING_DEVICE: [u8; 16] = [0x0E; 16];
const SECOND_SIBLING_MANIFEST: &str = "manifest.cbor.enc.sync-conflict-from-device-ee";
const SECOND_SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-ee";
const COMMIT_NOW_MS: u64 = 1_000_000;
const FIXTURE_NOW_MS: u64 = 500_000;

fn vc(device_uuid: [u8; 16], counter: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid,
        counter,
    }
}

fn identity_for(folder: &std::path::Path) -> UnlockedIdentity {
    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).expect("read bundle");
    open_with_password(&vt, &bundle, &password).expect("open_with_password")
}

/// Drive `sync_once` to `ConcurrentDetected` and prepare with `MERGING_DEVICE`.
fn prepare(
    folder: &std::path::Path,
    identity: &UnlockedIdentity,
    local_seen: Vec<VectorClockEntry>,
) -> Result<DraftMerge, SyncError> {
    let state = SyncState::new(extract_vault_uuid(folder), local_seen).expect("SyncState::new");
    let (bundle, plan) = match sync_once(folder, identity, &state, 0).expect("sync_once") {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    prepare_merge(folder, identity, &bundle, &plan, MERGING_DEVICE)
}

/// [`prepare`], then commit with no decisions, and return the state the
/// commit returned.
fn merge_and_commit(folder: &std::path::Path, local_seen: Vec<VectorClockEntry>) -> SyncState {
    let identity = identity_for(folder);
    let draft = prepare(folder, &identity, local_seen).expect("prepare_merge");
    assert_eq!(draft.merging_device, MERGING_DEVICE);
    commit_with_decisions(folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
        .expect("commit_with_decisions")
}

/// The committed block's records, decrypted from disk.
fn disk_block_records(folder: &std::path::Path, block_uuid: [u8; 16]) -> Vec<Record> {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    let bytes =
        std::fs::read(sync_helpers::block_file_path(folder, &block_uuid)).expect("read block");
    sync_helpers::decrypt_block_using_open(&open, &bytes)
        .expect("decrypt committed block")
        .records
}

fn record_uuids(records: &[Record]) -> Vec<[u8; 16]> {
    records.iter().map(|r| r.record_uuid).collect()
}

fn disk_block_clock(folder: &std::path::Path, block_uuid: [u8; 16]) -> Vec<VectorClockEntry> {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    open.manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("merged block entry")
        .vector_clock_summary
        .clone()
}

fn disk_manifest_clock(folder: &std::path::Path) -> Vec<VectorClockEntry> {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    open.manifest.vector_clock.clone()
}

/// The written manifest clock is the LUB plus a fresh `MERGING_DEVICE: 1`
/// entry, and the returned state equals the disk (which is what makes the
/// next pass `NothingToDo`).
#[test]
fn a_manifest_only_merge_adds_the_merging_device_entry() {
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        vec![vc(CANONICAL_DEVICE, 1)],
        SIBLING_MANIFEST,
        vec![vc(SIBLING_DEVICE, 1)],
    );

    let new_state = merge_and_commit(&folder, vec![vc(LOCAL_SEEN_DEVICE, 1)]);

    let want = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(MERGING_DEVICE, 1),
    ];
    assert_eq!(disk_manifest_clock(&folder), want);
    assert_eq!(new_state.highest_vector_clock_seen, want);
}

/// A merging device already in the clock is incremented, not reset.
#[test]
fn a_merge_increments_an_existing_merging_device_entry() {
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        vec![vc(CANONICAL_DEVICE, 1), vc(MERGING_DEVICE, 3)],
        SIBLING_MANIFEST,
        vec![vc(SIBLING_DEVICE, 1), vc(MERGING_DEVICE, 2)],
    );

    merge_and_commit(&folder, vec![vc(LOCAL_SEEN_DEVICE, 1)]);

    assert_eq!(
        disk_manifest_clock(&folder),
        vec![
            vc(CANONICAL_DEVICE, 1),
            vc(SIBLING_DEVICE, 1),
            vc(MERGING_DEVICE, 4),
        ]
    );
}

/// A diverging block's merged clock ticks the merging device (§11.2), not the
/// owner's `user_uuid`.
#[test]
fn a_block_merge_ticks_the_merging_device_not_the_user_uuid() {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);
    let user_uuid = identity_for(&probe).identity.user_uuid;

    let canonical_clock = vec![vc(CANONICAL_DEVICE, 1)];
    let sibling_clock = vec![vc(SIBLING_DEVICE, 1)];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            [0xAA; 16],
            CANONICAL_DEVICE,
            100,
            "canonical",
        )],
        canonical_clock.clone(),
        canonical_clock,
        vec![sync_helpers::live_record(
            [0xBB; 16],
            SIBLING_DEVICE,
            200,
            "sibling",
        )],
        sibling_clock.clone(),
        sibling_clock,
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );

    merge_and_commit(&folder, vec![vc(LOCAL_SEEN_DEVICE, 1)]);

    let block_clock = disk_block_clock(&folder, block_uuid);
    assert_eq!(
        block_clock,
        vec![
            vc(CANONICAL_DEVICE, 1),
            vc(SIBLING_DEVICE, 1),
            vc(MERGING_DEVICE, 1),
        ]
    );
    assert!(block_clock.iter().all(|e| e.device_uuid != user_uuid));
}

/// Three concurrent copies of one block are one merge event, so the merged
/// block clock gets ONE tick for the merging device, not one per fold step
/// (crypto-design §11.2 "N-way merge", #751). The manifest clock likewise.
#[test]
fn a_three_way_block_merge_ticks_the_merging_device_once() {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);

    let canonical_clock = vec![vc(CANONICAL_DEVICE, 1)];
    let sibling_clock = vec![vc(SIBLING_DEVICE, 1)];
    let second_clock = vec![vc(SECOND_SIBLING_DEVICE, 1)];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            [0xAA; 16],
            CANONICAL_DEVICE,
            100,
            "canonical",
        )],
        canonical_clock.clone(),
        canonical_clock,
        vec![sync_helpers::live_record(
            [0xBB; 16],
            SIBLING_DEVICE,
            200,
            "sibling",
        )],
        sibling_clock.clone(),
        sibling_clock,
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    sync_helpers::add_concurrent_block_sibling(
        &folder,
        block_uuid,
        vec![sync_helpers::live_record(
            [0xCC; 16],
            SECOND_SIBLING_DEVICE,
            300,
            "second",
        )],
        second_clock.clone(),
        second_clock,
        SECOND_SIBLING_MANIFEST,
        SECOND_SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );

    merge_and_commit(&folder, vec![vc(LOCAL_SEEN_DEVICE, 1)]);

    let want = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(MERGING_DEVICE, 1),
        vc(SECOND_SIBLING_DEVICE, 1),
    ];
    assert_eq!(disk_block_clock(&folder, block_uuid), want);
    assert_eq!(disk_manifest_clock(&folder), want);
    assert_eq!(
        record_uuids(&disk_block_records(&folder, block_uuid)),
        vec![[0xAA; 16], [0xBB; 16], [0xCC; 16]]
    );
}

/// Canonical `{C1}` plus two conflict copies of one block: one concurrent
/// with it (`{S1}`) and one that has seen both and dominates them
/// (`{C1,S1,E1}`). `dominating_first` puts the dominating copy in the
/// sibling that folds first (`-bb`), else in the one that folds last
/// (`-ee`); siblings fold in path order. The dominating copy's version of
/// record 0xAA carries an OLDER `last_mod` than the canonical one, so a
/// per-field LWW merge would pick the canonical value and adopting the copy
/// whole would not.
fn vault_with_a_dominating_copy(
    dominating_first: bool,
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);

    let canonical_clock = vec![vc(CANONICAL_DEVICE, 1)];
    let concurrent = (
        vec![sync_helpers::live_record(
            [0xBB; 16],
            SIBLING_DEVICE,
            200,
            "sibling",
        )],
        vec![vc(SIBLING_DEVICE, 1)],
    );
    let dominating = (
        vec![
            sync_helpers::live_record([0xAA; 16], SECOND_SIBLING_DEVICE, 50, "dominating"),
            sync_helpers::live_record([0xBB; 16], SIBLING_DEVICE, 200, "sibling"),
            sync_helpers::live_record([0xCC; 16], SECOND_SIBLING_DEVICE, 300, "second"),
        ],
        vec![
            vc(CANONICAL_DEVICE, 1),
            vc(SIBLING_DEVICE, 1),
            vc(SECOND_SIBLING_DEVICE, 1),
        ],
    );
    let (first, last) = if dominating_first {
        (dominating, concurrent)
    } else {
        (concurrent, dominating)
    };
    let (folder, tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            [0xAA; 16],
            CANONICAL_DEVICE,
            100,
            "canonical",
        )],
        canonical_clock.clone(),
        canonical_clock,
        first.0,
        first.1.clone(),
        first.1,
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    sync_helpers::add_concurrent_block_sibling(
        &folder,
        block_uuid,
        last.0,
        last.1.clone(),
        last.1,
        SECOND_SIBLING_MANIFEST,
        SECOND_SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    (folder, tmp, block_uuid)
}

/// A copy that dominates every other copy is adopted whole with its clock
/// untouched, whichever position it folds in: the tick is a function of the
/// set of copies, not of fold order (crypto-design §11.2 "N-way merge").
/// Keying the tick on "some step was concurrent" ticked the dominating copy
/// only when it folded after the concurrent pair.
#[test]
fn a_dominating_copy_is_adopted_untouched_in_either_fold_order() {
    for dominating_first in [false, true] {
        let (folder, _tmp, block_uuid) = vault_with_a_dominating_copy(dominating_first);

        merge_and_commit(&folder, vec![vc(LOCAL_SEEN_DEVICE, 1)]);

        assert_eq!(
            disk_block_clock(&folder, block_uuid),
            vec![
                vc(CANONICAL_DEVICE, 1),
                vc(SIBLING_DEVICE, 1),
                vc(SECOND_SIBLING_DEVICE, 1),
            ],
            "dominating_first = {dominating_first}"
        );
        let records = disk_block_records(&folder, block_uuid);
        assert_eq!(
            record_uuids(&records),
            vec![[0xAA; 16], [0xBB; 16], [0xCC; 16]],
            "dominating_first = {dominating_first}"
        );
        assert_eq!(
            records[0].fields["k"].last_mod, 50,
            "dominating_first = {dominating_first}: record 0xAA must be the dominating copy's"
        );
    }
}

/// A merge whose `+1` would overflow the merging device's counter fails as
/// the typed `VaultError::ClockOverflow`, not as a structural bundle error.
#[test]
fn a_merge_tick_that_overflows_is_a_typed_clock_overflow() {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);

    let canonical_clock = vec![vc(CANONICAL_DEVICE, 1)];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            [0xAA; 16],
            CANONICAL_DEVICE,
            100,
            "canonical",
        )],
        canonical_clock.clone(),
        canonical_clock,
        vec![sync_helpers::live_record(
            [0xBB; 16],
            SIBLING_DEVICE,
            200,
            "sibling",
        )],
        vec![vc(SIBLING_DEVICE, 1), vc(MERGING_DEVICE, u64::MAX)],
        vec![vc(SIBLING_DEVICE, 1)],
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );

    let identity = identity_for(&folder);
    match prepare(&folder, &identity, vec![vc(LOCAL_SEEN_DEVICE, 1)]) {
        Err(SyncError::Vault(VaultError::ClockOverflow { device_uuid })) => {
            assert_eq!(device_uuid, MERGING_DEVICE)
        }
        other => panic!("expected ClockOverflow, got {:?}", other.map(|_| ())),
    }
}

/// A diverging block whose sibling copy strictly dominates the canonical one
/// has no concurrent fold step, so the dominating clock is adopted unchanged
/// and the merging device gets no block tick (crypto-design §11.2 "N-way
/// merge", #751). The manifest clocks are concurrent, so the manifest still
/// gets its one tick.
#[test]
fn a_dominated_block_fold_adopts_the_dominating_clock_untouched() {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);

    let canonical_block_clock = vec![vc(CANONICAL_DEVICE, 1)];
    let sibling_block_clock = vec![vc(CANONICAL_DEVICE, 1), vc(SIBLING_DEVICE, 1)];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            [0xAA; 16],
            CANONICAL_DEVICE,
            100,
            "canonical",
        )],
        canonical_block_clock,
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![sync_helpers::live_record(
            [0xBB; 16],
            SIBLING_DEVICE,
            200,
            "sibling",
        )],
        sibling_block_clock.clone(),
        vec![vc(SIBLING_DEVICE, 1)],
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );

    merge_and_commit(&folder, vec![vc(LOCAL_SEEN_DEVICE, 1)]);

    assert_eq!(disk_block_clock(&folder, block_uuid), sibling_block_clock);
    assert_eq!(
        disk_manifest_clock(&folder),
        vec![
            vc(CANONICAL_DEVICE, 1),
            vc(SIBLING_DEVICE, 1),
            vc(MERGING_DEVICE, 1),
        ]
    );
}
