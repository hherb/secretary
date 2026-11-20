//! What a sync commit writes for a merged block (#759).
//!
//! crypto-design §11.2 "Writing a merge": the written block carries the
//! merged `block_name` and `unknown` map, and a block whose fold adopted
//! one copy whole keeps that copy's clock only while the written plaintext
//! is that copy's. A keep-local decision changes the records, so it ticks
//! the merging device once; otherwise two devices hold different plaintexts
//! under one clock (the equal-clock invariant, vault-format §6.5.1).

use std::collections::BTreeMap;

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, DraftMerge, SyncError, SyncOutcome, SyncState,
    VetoDecision,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::record::UnknownValue;
use secretary_core::vault::{open_vault, BlockPlaintext, Record, Unlocker, VaultError};

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
const THIRD_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-ee";
const COMMIT_NOW_MS: u64 = 1_000_000;
const FIXTURE_NOW_MS: u64 = 500_000;
/// The vetoed record: live on the canonical side, tombstoned by the copy.
const VETO_RECORD: [u8; 16] = [0xAA; 16];
const LOCAL_LAST_MOD_MS: u64 = 100;
const DISK_TOMBSTONE_AT_MS: u64 = 200;
/// A block name that sorts after the golden vault's, so the §11.2
/// lex-larger rule picks it on a concurrent fold too.
const RENAMED_BLOCK: &str = "\u{10FFFF} renamed by the third copy";
const EXTENSION_KEY: &str = "x_v2_extension";
/// Canonical CBOR for the unsigned integer 7.
const EXTENSION_VALUE_CBOR: [u8; 1] = [0x07];
/// `(block_version, schema_version)` of a block a later client wrote: each
/// above v1's, and different from each other so a swapped pair is caught.
const LATER_VERSIONS: (u32, u32) = (2, 3);

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
fn prepare(folder: &std::path::Path, identity: &UnlockedIdentity) -> DraftMerge {
    let state = SyncState::new(extract_vault_uuid(folder), vec![vc(LOCAL_SEEN_DEVICE, 1)])
        .expect("SyncState::new");
    let (bundle, plan) = match sync_once(folder, identity, &state, 0).expect("sync_once") {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    prepare_merge(folder, identity, &bundle, &plan, MERGING_DEVICE).expect("prepare_merge")
}

/// The committed block as it is on disk: its plaintext, its manifest
/// `vector_clock_summary` and its manifest `block_name`.
fn disk_block(
    folder: &std::path::Path,
    block_uuid: [u8; 16],
) -> (BlockPlaintext, Vec<VectorClockEntry>, String) {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    let bytes =
        std::fs::read(sync_helpers::block_file_path(folder, &block_uuid)).expect("read block");
    let plaintext =
        sync_helpers::decrypt_block_using_open(&open, &bytes).expect("decrypt committed block");
    let entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("merged block entry");
    (
        plaintext,
        entry.vector_clock_summary.clone(),
        entry.block_name.clone(),
    )
}

fn extension_map() -> BTreeMap<String, UnknownValue> {
    let value = UnknownValue::from_canonical_cbor(&EXTENSION_VALUE_CBOR).expect("canonical cbor");
    BTreeMap::from([(EXTENSION_KEY.to_string(), value)])
}

/// Canonical `{C1}` and a concurrent `{S1}` copy, plus a third copy carrying
/// a new `block_name`, a block-level `unknown` key and `third_versions`
/// (`(block_version, schema_version)`) under `third_clock`.
fn vault_with_a_renamed_extended_copy(
    third_clock: Vec<VectorClockEntry>,
    third_versions: (u32, u32),
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);

    let canonical_clock = vec![vc(CANONICAL_DEVICE, 1)];
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
        vec![sync_helpers::live_record(
            [0xBB; 16],
            SIBLING_DEVICE,
            200,
            "sibling",
        )],
        vec![vc(SIBLING_DEVICE, 1)],
        vec![vc(SIBLING_DEVICE, 1)],
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    sync_helpers::add_block_sibling_with_meta(
        &folder,
        block_uuid,
        vec![
            sync_helpers::live_record([0xAA; 16], CANONICAL_DEVICE, 100, "canonical"),
            sync_helpers::live_record([0xBB; 16], SIBLING_DEVICE, 200, "sibling"),
        ],
        Some(RENAMED_BLOCK),
        extension_map(),
        third_versions,
        third_clock.clone(),
        third_clock,
        THIRD_MANIFEST,
        THIRD_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    (folder, tmp, block_uuid)
}

/// The merged `block_name` and block-level `unknown` keys reach the disk,
/// both when the fold adopts the third copy whole (it dominates the other
/// two, so its clock stands) and when it merges it concurrently (§11.2:
/// `unknown` per-key, `block_name` lex-larger). Before #759 the commit
/// wrote an empty `unknown` and the canonical name, so a dominating copy's
/// clock was written over a plaintext that was not that copy's.
#[test]
fn the_merged_block_name_and_unknown_keys_are_written() {
    let dominating = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(THIRD_DEVICE, 1),
    ];
    let concurrent = vec![vc(THIRD_DEVICE, 1)];
    let ticked = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(MERGING_DEVICE, 1),
        vc(THIRD_DEVICE, 1),
    ];
    for (third_clock, want_clock) in [(dominating.clone(), dominating), (concurrent, ticked)] {
        let (folder, _tmp, block_uuid) = vault_with_a_renamed_extended_copy(
            third_clock.clone(),
            sync_helpers::V1_BLOCK_VERSIONS,
        );
        let identity = identity_for(&folder);
        let draft = prepare(&folder, &identity);
        commit_with_decisions(&folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
            .expect("commit_with_decisions");

        let (plaintext, clock, manifest_name) = disk_block(&folder, block_uuid);
        let label = format!("third copy clock {third_clock:?}");
        assert_eq!(plaintext.unknown, extension_map(), "{label}");
        assert_eq!(plaintext.block_name, RENAMED_BLOCK, "{label}");
        assert_eq!(manifest_name, RENAMED_BLOCK, "{label}");
        assert_eq!(clock, want_clock, "{label}");
    }
}

/// A third copy written by a later client, with `block_version` and
/// `schema_version` above v1's. §11.2 merges both as `max`, so the commit
/// writes the copy's pair rather than v1's. Writing `1` was a downgrade,
/// and when the fold adopted the copy whole (its clock stands untouched)
/// also a second plaintext under that copy's clock (#761).
#[test]
fn the_merged_block_and_schema_versions_are_written() {
    let dominating = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(THIRD_DEVICE, 1),
    ];
    let concurrent = vec![vc(THIRD_DEVICE, 1)];
    for third_clock in [dominating, concurrent] {
        let (folder, _tmp, block_uuid) =
            vault_with_a_renamed_extended_copy(third_clock.clone(), LATER_VERSIONS);
        let identity = identity_for(&folder);
        let draft = prepare(&folder, &identity);
        commit_with_decisions(&folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
            .expect("commit_with_decisions");

        let (plaintext, _, _) = disk_block(&folder, block_uuid);
        assert_eq!(
            (plaintext.block_version, plaintext.schema_version),
            LATER_VERSIONS,
            "third copy clock {third_clock:?}"
        );
    }
}

/// Canonical `{C1}` holds `VETO_RECORD` live; the sibling copy, under
/// `sibling_block_clock`, tombstoned that record later, so the veto fires.
/// `{C1,S1}` dominates the canonical copy (the fold adopts it whole);
/// `{S1}` is concurrent with it (the fold merges and ticks).
fn vault_with_a_later_tombstone(
    sibling_block_clock: Vec<VectorClockEntry>,
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
    vault_with_later_tombstones(&[VETO_RECORD], sibling_block_clock)
}

/// [`vault_with_a_later_tombstone`] over several records: each of
/// `record_ids` is live on the canonical side and tombstoned later by the
/// sibling, so each fires its own veto.
fn vault_with_later_tombstones(
    record_ids: &[[u8; 16]],
    sibling_block_clock: Vec<VectorClockEntry>,
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);
    let live = record_ids
        .iter()
        .map(|id| sync_helpers::live_record(*id, CANONICAL_DEVICE, LOCAL_LAST_MOD_MS, "local"))
        .collect();
    let tombstoned = record_ids
        .iter()
        .map(|id| {
            let mut r =
                sync_helpers::live_record(*id, SIBLING_DEVICE, DISK_TOMBSTONE_AT_MS, "gone");
            r.tombstone = true;
            r.tombstoned_at_ms = DISK_TOMBSTONE_AT_MS;
            r
        })
        .collect();

    let (folder, tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        live,
        vec![vc(CANONICAL_DEVICE, 1)],
        vec![vc(CANONICAL_DEVICE, 1)],
        tombstoned,
        sibling_block_clock,
        vec![vc(SIBLING_DEVICE, 1)],
        SIBLING_MANIFEST,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
    );
    (folder, tmp, block_uuid)
}

fn only_record(plaintext: &BlockPlaintext) -> &Record {
    assert_eq!(plaintext.records.len(), 1, "one record in the block");
    &plaintext.records[0]
}

/// `KeepLocal` restores the record an adopted copy tombstoned, so the
/// written plaintext is no longer that copy's and the block clock gets the
/// merging device's `+1`. `AcceptTombstone` writes the copy's plaintext, so
/// its clock stands untouched. A fold that already ticked gets no second
/// tick from a `KeepLocal`: its clock is this merge's own, and §11.2 ticks
/// a merge at most once.
#[test]
fn a_keep_local_ticks_the_merging_device_once_per_block() {
    let adopted = vec![vc(CANONICAL_DEVICE, 1), vc(SIBLING_DEVICE, 1)];
    let ticked = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(MERGING_DEVICE, 1),
    ];
    let keep_local = VetoDecision::KeepLocal {
        record_id: VETO_RECORD,
    };
    let accept = VetoDecision::AcceptTombstone {
        record_id: VETO_RECORD,
    };
    // (sibling block clock, decision, fold clock, written clock, tombstoned)
    let cases = [
        (
            adopted.clone(),
            keep_local.clone(),
            adopted.clone(),
            ticked.clone(),
            false,
        ),
        (adopted.clone(), accept, adopted.clone(), adopted, true),
        (
            vec![vc(SIBLING_DEVICE, 1)],
            keep_local,
            ticked.clone(),
            ticked,
            false,
        ),
    ];
    for (sibling_clock, decision, fold_clock, want_clock, want_tombstone) in cases {
        let label = format!("sibling {sibling_clock:?}, {decision:?}");
        let (folder, _tmp, block_uuid) = vault_with_a_later_tombstone(sibling_clock);
        let identity = identity_for(&folder);
        let draft = prepare(&folder, &identity);
        assert_eq!(
            draft.vetoes.len(),
            1,
            "{label}: the tombstone vetoes the live record"
        );
        assert_eq!(
            draft.per_block_clocks[&block_uuid], fold_clock,
            "{label}: fold clock"
        );
        commit_with_decisions(&folder, &identity, draft, vec![decision], COMMIT_NOW_MS)
            .expect("commit_with_decisions");

        let (plaintext, clock, _) = disk_block(&folder, block_uuid);
        assert_eq!(only_record(&plaintext).tombstone, want_tombstone, "{label}");
        assert_eq!(clock, want_clock, "{label}: written clock");
    }
}

/// Two vetoed records in one adopted block. The tick is per changed block,
/// not per `KeepLocal`: two keep-locals tick once (§11.2 ticks a merge at
/// most once), and a keep-local beside an accept-tombstone ticks once too.
#[test]
fn several_keep_locals_in_one_adopted_block_tick_once() {
    const SECOND_RECORD: [u8; 16] = [0xAB; 16];
    let adopted = vec![vc(CANONICAL_DEVICE, 1), vc(SIBLING_DEVICE, 1)];
    let ticked = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(MERGING_DEVICE, 1),
    ];
    let keep = |record_id| VetoDecision::KeepLocal { record_id };
    let accept = |record_id| VetoDecision::AcceptTombstone { record_id };
    // (decisions, tombstoned records after the commit)
    let cases = [
        (vec![keep(VETO_RECORD), keep(SECOND_RECORD)], vec![]),
        (
            vec![keep(VETO_RECORD), accept(SECOND_RECORD)],
            vec![SECOND_RECORD],
        ),
    ];
    for (decisions, want_tombstoned) in cases {
        let label = format!("{decisions:?}");
        let (folder, _tmp, block_uuid) =
            vault_with_later_tombstones(&[VETO_RECORD, SECOND_RECORD], adopted.clone());
        let identity = identity_for(&folder);
        let draft = prepare(&folder, &identity);
        assert_eq!(draft.vetoes.len(), 2, "{label}: both records vetoed");
        assert_eq!(draft.per_block_clocks[&block_uuid], adopted, "{label}");
        commit_with_decisions(&folder, &identity, draft, decisions, COMMIT_NOW_MS)
            .expect("commit_with_decisions");

        let (plaintext, clock, _) = disk_block(&folder, block_uuid);
        let tombstoned: Vec<[u8; 16]> = plaintext
            .records
            .iter()
            .filter(|r| r.tombstone)
            .map(|r| r.record_uuid)
            .collect();
        assert_eq!(plaintext.records.len(), 2, "{label}");
        assert_eq!(tombstoned, want_tombstoned, "{label}");
        assert_eq!(clock, ticked, "{label}: written clock");
    }
}

/// The bytes a refused commit must leave alone: the merged block file and
/// the canonical manifest.
fn commit_targets(folder: &std::path::Path, block_uuid: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
    (
        std::fs::read(sync_helpers::block_file_path(folder, &block_uuid)).expect("read block"),
        std::fs::read(folder.join("manifest.cbor.enc")).expect("read manifest"),
    )
}

/// A draft missing a diverging block's `per_block_meta` or
/// `per_block_clocks` (`DraftMerge`'s fields are public) is refused as
/// `InvalidArgument` naming the map, before any file is written, rather
/// than panicking at `rewrite_one_block`'s lookups or writing a default.
#[test]
fn a_draft_missing_a_blocks_meta_or_clock_is_refused_before_any_write() {
    type Clear = fn(&mut DraftMerge);
    let cases: [(&str, Clear); 2] = [
        ("per_block_meta", |d| d.per_block_meta.clear()),
        ("per_block_clocks", |d| d.per_block_clocks.clear()),
    ];
    for (map, clear) in cases {
        let (folder, _tmp, block_uuid) =
            vault_with_a_later_tombstone(vec![vc(CANONICAL_DEVICE, 1), vc(SIBLING_DEVICE, 1)]);
        let identity = identity_for(&folder);
        let mut draft = prepare(&folder, &identity);
        clear(&mut draft);
        let before = commit_targets(&folder, block_uuid);
        let decision = VetoDecision::KeepLocal {
            record_id: VETO_RECORD,
        };
        match commit_with_decisions(&folder, &identity, draft, vec![decision], COMMIT_NOW_MS) {
            Err(SyncError::InvalidArgument { detail }) => {
                assert!(detail.contains(map), "{map}: detail {detail:?}")
            }
            other => panic!("{map}: expected InvalidArgument, got {other:?}"),
        }
        assert!(
            commit_targets(&folder, block_uuid) == before,
            "{map}: nothing written"
        );
    }
}

/// The keep-local tick is computed before the first file write, so a block
/// clock at `u64::MAX` for the merging device fails the commit with nothing
/// written. The same fixture with `AcceptTombstone` commits, which shows the
/// overflow comes from the conditional tick alone.
#[test]
fn a_keep_local_tick_that_overflows_writes_nothing() {
    let at_max = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(MERGING_DEVICE, u64::MAX),
    ];

    let (folder, _tmp, block_uuid) = vault_with_a_later_tombstone(at_max.clone());
    let identity = identity_for(&folder);
    let draft = prepare(&folder, &identity);
    assert_eq!(draft.per_block_clocks[&block_uuid], at_max, "adopted fold");
    let before = commit_targets(&folder, block_uuid);
    let keep = VetoDecision::KeepLocal {
        record_id: VETO_RECORD,
    };
    match commit_with_decisions(&folder, &identity, draft, vec![keep], COMMIT_NOW_MS) {
        Err(SyncError::Vault(VaultError::ClockOverflow { device_uuid })) => {
            assert_eq!(device_uuid, MERGING_DEVICE)
        }
        other => panic!("expected ClockOverflow, got {other:?}"),
    }
    assert!(
        commit_targets(&folder, block_uuid) == before,
        "nothing written"
    );

    let (folder, _tmp, block_uuid) = vault_with_a_later_tombstone(at_max.clone());
    let identity = identity_for(&folder);
    let draft = prepare(&folder, &identity);
    let accept = VetoDecision::AcceptTombstone {
        record_id: VETO_RECORD,
    };
    commit_with_decisions(&folder, &identity, draft, vec![accept], COMMIT_NOW_MS)
        .expect("accept-tombstone commits");
    assert_eq!(disk_block(&folder, block_uuid).1, at_max);
}
