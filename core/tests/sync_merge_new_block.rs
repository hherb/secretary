//! A conflict-copy merge carries a block only a copy holds (crypto-design
//! §11.7, #781).
//!
//! The merged manifest's clock covers every folded copy, so a later sync does
//! not offer that copy again. A block another device created concurrently, and
//! which the local manifest lists in neither `blocks` nor `trash`, must reach
//! the merged manifest; while its file has not arrived the merge is refused.

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, DiffPlan, SyncError, SyncOutcome, SyncState,
    VaultBundle,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{open_vault, BlockEntry, Unlocker};

mod fixtures;
mod sync_helpers;

use fixtures::extract_vault_uuid;

const CANONICAL_DEVICE: [u8; 16] = [0x0A; 16];
const SIBLING_DEVICE: [u8; 16] = [0x0B; 16];
const LOCAL_SEEN_DEVICE: [u8; 16] = [0x0C; 16];
const MERGING_DEVICE: [u8; 16] = [0x0D; 16];
const THIRD_DEVICE: [u8; 16] = [0x0E; 16];
const SIBLING_MANIFEST: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";
const THIRD_MANIFEST: &str = "manifest.cbor.enc.sync-conflict-from-device-ee";
const COMMIT_NOW_MS: u64 = 1_000_000;
const FIXTURE_NOW_MS: u64 = 500_000;
/// The record one copy holds live and the other tombstones.
const TOMBSTONED_RECORD: [u8; 16] = [0xAA; 16];
const LIVE_LAST_MOD_MS: u64 = 100;
const TOMBSTONE_AT_MS: u64 = 200;

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

fn open_entries(folder: &std::path::Path) -> Vec<BlockEntry> {
    let password = fixtures::golden_vault_001_password();
    open_vault(folder, Unlocker::Password(&password), None)
        .expect("open_vault")
        .manifest
        .blocks
}

/// Drive `sync_once` to `ConcurrentDetected` from a local clock no copy holds.
fn concurrent_bundle(
    folder: &std::path::Path,
    identity: &UnlockedIdentity,
) -> (VaultBundle, DiffPlan) {
    let state = SyncState::new(extract_vault_uuid(folder), vec![vc(LOCAL_SEEN_DEVICE, 1)])
        .expect("SyncState::new");
    match sync_once(folder, identity, &state, 0).expect("sync_once") {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

/// The golden vault with its first block present only in a concurrent copy
/// manifest: the canonical manifest lists it in neither `blocks` nor `trash`.
/// Returns the folder, the block and the copy's entry for it.
fn vault_with_a_block_only_the_copy_holds() -> (std::path::PathBuf, tempfile::TempDir, BlockEntry) {
    let (folder, tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);
    let copy_entry = open_entries(&folder)
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("golden block entry");
    sync_helpers::write_manifest_at(
        &folder,
        SIBLING_MANIFEST,
        vec![vc(SIBLING_DEVICE, 1)],
        &sync_helpers::SIBLING_NONCE_B,
    );
    sync_helpers::write_manifest_at_with(
        &folder,
        sync_helpers::MANIFEST_FILENAME,
        vec![vc(CANONICAL_DEVICE, 1)],
        // Not CANONICAL_NONCE_A: `fresh_vault_with_clock` signed under it.
        &sync_helpers::SIBLING_NONCE_C,
        |m| m.blocks.retain(|b| b.block_uuid != block_uuid),
    );
    (folder, tmp, copy_entry)
}

/// The merged entry is the copy's, rewritten by the commit: same block, name,
/// creation time and clock (the copy's version is adopted whole, no tick).
fn assert_carried(folder: &std::path::Path, copy_entry: &BlockEntry) {
    let merged = open_entries(folder)
        .into_iter()
        .find(|b| b.block_uuid == copy_entry.block_uuid)
        .expect("the copy-only block reaches the merged manifest");
    assert_eq!(merged.created_at_ms, copy_entry.created_at_ms);
    assert_eq!(merged.block_name, copy_entry.block_name);
    assert_eq!(merged.vector_clock_summary, copy_entry.vector_clock_summary);
}

#[test]
fn a_block_only_a_copy_holds_is_carried_into_the_merge() {
    let (folder, _tmp, copy_entry) = vault_with_a_block_only_the_copy_holds();
    let block_path = sync_helpers::block_file_path(&folder, &copy_entry.block_uuid);
    let password = fixtures::golden_vault_001_password();
    let before = {
        let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");
        let bytes = std::fs::read(&block_path).expect("read block");
        sync_helpers::decrypt_block_using_open(&open, &bytes).expect("decrypt block")
    };

    let identity = identity_for(&folder);
    let (bundle, plan) = concurrent_bundle(&folder, &identity);
    assert_eq!(plan.diverging_blocks, vec![copy_entry.block_uuid]);
    let draft =
        prepare_merge(&folder, &identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge");
    commit_with_decisions(&folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
        .expect("commit_with_decisions");

    assert_carried(&folder, &copy_entry);
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("reopen");
    let after = sync_helpers::decrypt_block_using_open(
        &open,
        &std::fs::read(&block_path).expect("read merged block"),
    )
    .expect("decrypt merged block");
    assert_eq!(after.records, before.records);
}

#[test]
fn a_block_only_a_copy_holds_is_refused_until_its_file_arrives() {
    let (folder, _tmp, copy_entry) = vault_with_a_block_only_the_copy_holds();
    let block_path = sync_helpers::block_file_path(&folder, &copy_entry.block_uuid);
    let block_bytes = std::fs::read(&block_path).expect("read block");
    std::fs::remove_file(&block_path).expect("remove block");

    let identity = identity_for(&folder);
    let (bundle, plan) = concurrent_bundle(&folder, &identity);
    match prepare_merge(&folder, &identity, &bundle, &plan, MERGING_DEVICE) {
        Err(SyncError::BlockCopyUnavailable { block_uuid }) => {
            assert_eq!(block_uuid, copy_entry.block_uuid)
        }
        other => panic!("expected BlockCopyUnavailable, got {other:?}"),
    }

    std::fs::write(&block_path, &block_bytes).expect("the block arrives");
    let (bundle, plan) = concurrent_bundle(&folder, &identity);
    let draft =
        prepare_merge(&folder, &identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge");
    commit_with_decisions(&folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
        .expect("commit_with_decisions");
    assert_carried(&folder, &copy_entry);
}

/// Two concurrent copies hold a block new to this device: one keeps
/// `TOMBSTONED_RECORD` live, the other tombstones it later. The veto exists to
/// protect a LOCAL live record from a peer's tombstone; this device never
/// held the block, so the merge applies the tombstone and asks nothing.
#[test]
fn a_block_new_to_this_device_raises_no_veto() {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);
    let mut tombstoned = sync_helpers::live_record(
        TOMBSTONED_RECORD,
        SIBLING_DEVICE,
        TOMBSTONE_AT_MS,
        "tombstoned",
    );
    tombstoned.tombstone = true;
    tombstoned.tombstoned_at_ms = TOMBSTONE_AT_MS;
    tombstoned.fields.clear();
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            TOMBSTONED_RECORD,
            CANONICAL_DEVICE,
            LIVE_LAST_MOD_MS,
            "live",
        )],
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![tombstoned],
        vec![vc(SIBLING_DEVICE, 1)],
        vec![vc(SIBLING_DEVICE, 1)],
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    // Move the live version into a third copy, then drop the block from the
    // canonical manifest: both versions are now copies of a block new here.
    sync_helpers::write_manifest_at(
        &folder,
        THIRD_MANIFEST,
        vec![vc(THIRD_DEVICE, 1)],
        &sync_helpers::SIBLING_NONCE_C,
    );
    sync_helpers::write_manifest_at_with(
        &folder,
        sync_helpers::MANIFEST_FILENAME,
        vec![vc(CANONICAL_DEVICE, 2)],
        &sync_helpers::SIBLING_NONCE_D,
        |m| m.blocks.retain(|b| b.block_uuid != block_uuid),
    );

    let identity = identity_for(&folder);
    let (bundle, plan) = concurrent_bundle(&folder, &identity);
    let draft =
        prepare_merge(&folder, &identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge");
    assert!(draft.vetoes.is_empty(), "got {:?}", draft.vetoes);
    let merged = draft
        .merged_records
        .iter()
        .find(|r| r.record_uuid == TOMBSTONED_RECORD)
        .expect("merged record");
    assert!(merged.tombstone);
}
