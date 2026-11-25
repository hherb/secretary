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
/// The device that edits the new block again before its manifest lands.
const NEWER_EDIT_DEVICE: [u8; 16] = [0x0F; 16];
const NEWER_RECORD: [u8; 16] = [0xCC; 16];
const NEWER_LAST_MOD_MS: u64 = 300;
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

/// The new block's own file holds a version newer than any manifest names:
/// its device edited it again and the file landed before the manifest, or a
/// commit wrote the merged block and crashed before the manifest. Pairing
/// that file to a manifest entry by fingerprint finds none; its owner-signed
/// header clock dominates the copy's entry, so the merge adopts it whole
/// rather than refusing every retry (#781 review).
#[test]
fn a_new_block_whose_file_is_newer_than_every_manifest_is_adopted() {
    let (folder, _tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);
    let password = fixtures::golden_vault_001_password();
    let cached = open_vault(&folder, Unlocker::Password(&password), None).expect("open_vault");
    let copy_entry = cached
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .cloned()
        .expect("golden block entry");
    let mut newer_records = sync_helpers::decrypt_block_using_open(
        &cached,
        &std::fs::read(sync_helpers::block_file_path(&folder, &block_uuid)).expect("read block"),
    )
    .expect("decrypt block")
    .records;
    newer_records.push(sync_helpers::live_record(
        NEWER_RECORD,
        NEWER_EDIT_DEVICE,
        NEWER_LAST_MOD_MS,
        "newer",
    ));
    let mut newer_clock = copy_entry.vector_clock_summary.clone();
    newer_clock.push(vc(NEWER_EDIT_DEVICE, 1));
    newer_clock.sort_by_key(|e| e.device_uuid);

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
        &sync_helpers::SIBLING_NONCE_C,
        |m| m.blocks.retain(|b| b.block_uuid != block_uuid),
    );
    sync_helpers::rewrite_block_with_records_at_clock(
        &folder,
        &cached,
        block_uuid,
        newer_records,
        newer_clock.clone(),
        &sync_helpers::BLOCK_NONCE_E,
    );

    let identity = identity_for(&folder);
    let (bundle, plan) = concurrent_bundle(&folder, &identity);
    let draft =
        prepare_merge(&folder, &identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge");
    commit_with_decisions(&folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
        .expect("commit_with_decisions");

    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("reopen");
    let merged = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("the new block reaches the merged manifest");
    assert_eq!(merged.vector_clock_summary, newer_clock);
    let plaintext = sync_helpers::decrypt_block_using_open(
        &open,
        &std::fs::read(sync_helpers::block_file_path(&folder, &block_uuid)).expect("read"),
    )
    .expect("decrypt merged block");
    assert!(plaintext
        .records
        .iter()
        .any(|r| r.record_uuid == NEWER_RECORD));
}

fn expect_unavailable(folder: &std::path::Path, identity: &UnlockedIdentity, block_uuid: [u8; 16]) {
    let (bundle, plan) = concurrent_bundle(folder, identity);
    match prepare_merge(folder, identity, &bundle, &plan, MERGING_DEVICE) {
        Err(SyncError::BlockCopyUnavailable { block_uuid: got }) => assert_eq!(got, block_uuid),
        other => panic!("expected BlockCopyUnavailable, got {other:?}"),
    }
}

/// The copy names a newer version than the block's own file holds: its
/// device edited the block again and the manifest landed before the file.
/// The file's header clock does not cover the copy's entry, so the merge
/// refuses; once the newer file lands it is adopted.
#[test]
fn a_new_block_whose_file_is_older_than_its_copy_entry_is_refused_until_it_lands() {
    let (folder, _tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);
    let password = fixtures::golden_vault_001_password();
    let cached = open_vault(&folder, Unlocker::Password(&password), None).expect("open_vault");
    let copy_entry = cached
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .cloned()
        .expect("golden block entry");
    let mut newer_clock = copy_entry.vector_clock_summary.clone();
    newer_clock.push(vc(NEWER_EDIT_DEVICE, 1));
    newer_clock.sort_by_key(|e| e.device_uuid);

    let claimed = newer_clock.clone();
    sync_helpers::write_manifest_at_with(
        &folder,
        SIBLING_MANIFEST,
        vec![vc(SIBLING_DEVICE, 1)],
        &sync_helpers::SIBLING_NONCE_B,
        |m| {
            for b in m.blocks.iter_mut().filter(|b| b.block_uuid == block_uuid) {
                b.vector_clock_summary = claimed.clone();
            }
        },
    );
    sync_helpers::write_manifest_at_with(
        &folder,
        sync_helpers::MANIFEST_FILENAME,
        vec![vc(CANONICAL_DEVICE, 1)],
        &sync_helpers::SIBLING_NONCE_C,
        |m| m.blocks.retain(|b| b.block_uuid != block_uuid),
    );

    let identity = identity_for(&folder);
    expect_unavailable(&folder, &identity, block_uuid);

    let mut newer_records = sync_helpers::decrypt_block_using_open(
        &cached,
        &std::fs::read(sync_helpers::block_file_path(&folder, &block_uuid)).expect("read block"),
    )
    .expect("decrypt block")
    .records;
    newer_records.push(sync_helpers::live_record(
        NEWER_RECORD,
        NEWER_EDIT_DEVICE,
        NEWER_LAST_MOD_MS,
        "newer",
    ));
    sync_helpers::rewrite_block_with_records_at_clock(
        &folder,
        &cached,
        block_uuid,
        newer_records,
        newer_clock,
        &sync_helpers::BLOCK_NONCE_E,
    );
    let (bundle, plan) = concurrent_bundle(&folder, &identity);
    let draft =
        prepare_merge(&folder, &identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge");
    assert!(draft
        .merged_records
        .iter()
        .any(|r| r.record_uuid == NEWER_RECORD));
}

/// A new block's own file that is present but fails authentication is
/// refused like a missing one, not decrypted into a vault error.
#[test]
fn a_new_block_whose_file_fails_authentication_is_refused() {
    let (folder, _tmp, copy_entry) = vault_with_a_block_only_the_copy_holds();
    let block_path = sync_helpers::block_file_path(&folder, &copy_entry.block_uuid);
    let mut bytes = std::fs::read(&block_path).expect("read block");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&block_path, &bytes).expect("corrupt block");

    let identity = identity_for(&folder);
    expect_unavailable(&folder, &identity, copy_entry.block_uuid);
}

/// A block the local manifest lists, whose copy diverges, but whose own file
/// has not landed: ingest leaves it out of the plan, and the merge must not
/// cover the copy without it (#781 review).
#[test]
fn a_listed_diverging_block_whose_file_is_missing_is_refused() {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            TOMBSTONED_RECORD,
            CANONICAL_DEVICE,
            LIVE_LAST_MOD_MS,
            "canonical",
        )],
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![sync_helpers::live_record(
            NEWER_RECORD,
            SIBLING_DEVICE,
            NEWER_LAST_MOD_MS,
            "sibling",
        )],
        vec![vc(SIBLING_DEVICE, 1)],
        vec![vc(SIBLING_DEVICE, 1)],
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    let identity = identity_for(&folder);
    let block_path = sync_helpers::block_file_path(&folder, &block_uuid);
    std::fs::remove_file(&block_path).expect("remove canonical block");
    expect_unavailable(&folder, &identity, block_uuid);
}

/// A draft whose added entry names a block the manifest already lists is
/// refused before any file is written.
#[test]
fn a_commit_refuses_an_added_entry_the_manifest_already_lists() {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            TOMBSTONED_RECORD,
            CANONICAL_DEVICE,
            LIVE_LAST_MOD_MS,
            "canonical",
        )],
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![sync_helpers::live_record(
            NEWER_RECORD,
            SIBLING_DEVICE,
            NEWER_LAST_MOD_MS,
            "sibling",
        )],
        vec![vc(SIBLING_DEVICE, 1)],
        vec![vc(SIBLING_DEVICE, 1)],
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    let identity = identity_for(&folder);
    let (bundle, plan) = concurrent_bundle(&folder, &identity);
    let mut draft =
        prepare_merge(&folder, &identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge");
    let listed = open_entries(&folder)
        .into_iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("listed entry");
    draft
        .per_block_meta
        .get_mut(&block_uuid)
        .expect("meta")
        .added_entry = Some(listed);

    let block_path = sync_helpers::block_file_path(&folder, &block_uuid);
    let block_before = std::fs::read(&block_path).expect("read block");
    let manifest_path = folder.join(sync_helpers::MANIFEST_FILENAME);
    let manifest_before = std::fs::read(&manifest_path).expect("read manifest");
    assert!(matches!(
        commit_with_decisions(&folder, &identity, draft, Vec::new(), COMMIT_NOW_MS),
        Err(SyncError::InvalidArgument { .. })
    ));
    assert_eq!(
        std::fs::read(&block_path).expect("reread block"),
        block_before
    );
    assert_eq!(
        std::fs::read(&manifest_path).expect("reread manifest"),
        manifest_before
    );
}
