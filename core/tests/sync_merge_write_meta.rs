//! What a sync commit writes for a merged block's metadata (#759, #761,
//! #764): the merged `block_name`, block-level `unknown` keys and
//! `(block_version, schema_version)` reach the disk, both when the fold
//! adopts one copy whole (crypto-design §11.2 "Writing a merge") and when
//! it merges concurrently. Split out of `sync_merge_write.rs` at its
//! 500-line threshold; the keep-local tick tests stay there.

use std::collections::BTreeMap;

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, DraftMerge, SyncOutcome, SyncState,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::record::UnknownValue;
use secretary_core::vault::{open_vault, BlockPlaintext, Unlocker};

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

/// Canonical `{C1}` carrying `canonical_versions` and a concurrent v1
/// `{S1}` copy, plus a third copy carrying a new `block_name`, a
/// block-level `unknown` key and `third_versions` under `third_clock`.
/// Each versions pair is `(block_version, schema_version)`.
fn vault_with_a_renamed_extended_copy(
    canonical_versions: (u32, u32),
    third_clock: Vec<VectorClockEntry>,
    third_versions: (u32, u32),
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
    let (probe, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe);

    let canonical_clock = vec![vc(CANONICAL_DEVICE, 1)];
    let (folder, tmp) = sync_helpers::fresh_vault_two_concurrent_blocks_with_versions(
        block_uuid,
        vec![sync_helpers::live_record(
            [0xAA; 16],
            CANONICAL_DEVICE,
            100,
            "canonical",
        )],
        canonical_clock.clone(),
        canonical_clock,
        canonical_versions,
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
/// two, or its clock is exactly their unticked max `{C1,S1}`, so its step
/// is `Equal` (#764); either way its clock stands) and when it merges it
/// concurrently (§11.2: `unknown` per-key, `block_name` lex-larger).
/// Before #759 the commit wrote an empty `unknown` and the canonical name,
/// so a dominating copy's clock was written over a plaintext that was not
/// that copy's.
#[test]
fn the_merged_block_name_and_unknown_keys_are_written() {
    let dominating = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(THIRD_DEVICE, 1),
    ];
    let equal_to_max = vec![vc(CANONICAL_DEVICE, 1), vc(SIBLING_DEVICE, 1)];
    let concurrent = vec![vc(THIRD_DEVICE, 1)];
    let ticked = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(MERGING_DEVICE, 1),
        vc(THIRD_DEVICE, 1),
    ];
    for (third_clock, want_clock) in [
        (dominating.clone(), dominating),
        (equal_to_max.clone(), equal_to_max),
        (concurrent, ticked),
    ] {
        let (folder, _tmp, block_uuid) = vault_with_a_renamed_extended_copy(
            sync_helpers::V1_BLOCK_VERSIONS,
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

/// The commit writes the merged `(block_version, schema_version)`, not
/// v1's. §11.2 takes the `max` on a concurrent fold step and adopts an
/// equal or dominating copy whole, versions included. Writing `1` was a
/// downgrade of a later client's block, and when the fold adopted a copy
/// whole (its clock stands untouched) also a second plaintext under that
/// copy's clock (#761). Each row breaks a plausible wrong rule:
///
/// - a later third copy, dominating and concurrent: the v1 constant;
/// - a later canonical copy, each copy later in one field: last-copy-wins
///   and a constant initial value (canonical `(3, 1)`, third `(1, 4)`);
/// - a dominating third copy LOWER than the canonical: max over every
///   copy, which would write the canonical's pair under the third copy's
///   untouched clock;
/// - a third copy at exactly the unticked max `{C1,S1}`, higher and lower:
///   its step is `Equal`, which keeps the accumulator's versions (#764).
#[test]
fn the_merged_block_and_schema_versions_are_written() {
    let dominating = vec![
        vc(CANONICAL_DEVICE, 1),
        vc(SIBLING_DEVICE, 1),
        vc(THIRD_DEVICE, 1),
    ];
    let equal_to_max = vec![vc(CANONICAL_DEVICE, 1), vc(SIBLING_DEVICE, 1)];
    let concurrent = vec![vc(THIRD_DEVICE, 1)];
    let v1 = sync_helpers::V1_BLOCK_VERSIONS;
    let cases = [
        (dominating.clone(), v1, LATER_VERSIONS, LATER_VERSIONS),
        (concurrent.clone(), v1, LATER_VERSIONS, LATER_VERSIONS),
        (concurrent, (3, 1), (1, 4), (3, 4)),
        (dominating.clone(), LATER_VERSIONS, v1, v1),
        (equal_to_max.clone(), v1, LATER_VERSIONS, LATER_VERSIONS),
        (equal_to_max.clone(), LATER_VERSIONS, v1, v1),
    ];
    for (third_clock, canonical_versions, third_versions, want) in cases {
        let (folder, _tmp, block_uuid) = vault_with_a_renamed_extended_copy(
            canonical_versions,
            third_clock.clone(),
            third_versions,
        );
        let identity = identity_for(&folder);
        let draft = prepare(&folder, &identity);
        commit_with_decisions(&folder, &identity, draft, Vec::new(), COMMIT_NOW_MS)
            .expect("commit_with_decisions");

        let (plaintext, clock, _) = disk_block(&folder, block_uuid);
        let label = format!(
            "third copy clock {third_clock:?}, canonical {canonical_versions:?}, \
             third {third_versions:?}"
        );
        assert_eq!(
            (plaintext.block_version, plaintext.schema_version),
            want,
            "{label}"
        );
        if third_clock == dominating || third_clock == equal_to_max {
            assert_eq!(clock, third_clock, "adopted whole, untouched: {label}");
        }
    }
}
