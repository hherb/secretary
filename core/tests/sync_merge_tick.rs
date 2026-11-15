//! A merge ticks the merging device's clock entry (#744).
//!
//! crypto-design §10: on a concurrent manifest clock "the merged manifest's
//! vector clock is the component-wise max of the two, plus one for the merging
//! device". §11.2 says the same of a merged block's clock. Before #744 the
//! manifest clock was written unticked and the block clock ticked the owner's
//! `user_uuid` instead of a device.

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncOutcome, SyncState,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{open_vault, Unlocker};

mod fixtures;
mod sync_helpers;

use fixtures::extract_vault_uuid;

const CANONICAL_DEVICE: [u8; 16] = [0x0A; 16];
const SIBLING_DEVICE: [u8; 16] = [0x0B; 16];
const LOCAL_SEEN_DEVICE: [u8; 16] = [0x0C; 16];
const MERGING_DEVICE: [u8; 16] = [0x0D; 16];
const SIBLING_MANIFEST: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";
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

/// Drive `sync_once` to `ConcurrentDetected`, prepare and commit with
/// `MERGING_DEVICE`, and return the state the commit returned.
fn merge_and_commit(folder: &std::path::Path, local_seen: Vec<VectorClockEntry>) -> SyncState {
    let identity = identity_for(folder);
    let state = SyncState::new(extract_vault_uuid(folder), local_seen).expect("SyncState::new");
    let (bundle, plan) = match sync_once(folder, &identity, &state, 0).expect("sync_once") {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    let draft =
        prepare_merge(folder, &identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge");
    assert_eq!(draft.merging_device, MERGING_DEVICE);
    commit_with_decisions(folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
        .expect("commit_with_decisions")
}

fn disk_manifest_clock(folder: &std::path::Path) -> Vec<VectorClockEntry> {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    open.manifest.vector_clock.clone()
}

/// The written manifest clock is the LUB plus a fresh `MERGING_DEVICE: 1`
/// entry, and the returned state equals the disk, so the next pass is
/// `NothingToDo`.
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

    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open_vault");
    let block_clock = &open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("merged block entry")
        .vector_clock_summary;
    assert_eq!(
        block_clock,
        &vec![
            vc(CANONICAL_DEVICE, 1),
            vc(SIBLING_DEVICE, 1),
            vc(MERGING_DEVICE, 1),
        ]
    );
    assert!(block_clock.iter().all(|e| e.device_uuid != user_uuid));
}
