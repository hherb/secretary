//! Integration tests for C.1.1b Task 13 — the four veto-handling
//! commit paths (`KeepLocal`, `AcceptTombstone`, `MissingVetoDecision`,
//! `UnknownVetoDecision`). All four share the per-block-divergent
//! fixture [`sync_helpers::fresh_vault_two_concurrent_blocks`] (Task
//! 13a): canonical block holds record `[0xAA; 16]` LIVE at
//! `last_mod_ms = 100`; sibling block holds the same record TOMBSTONED
//! at `tombstoned_at_ms = 200`. The per-record veto pass in
//! `prepare_merge::tombstone_veto_set` emits one
//! `RecordTombstoneVeto { record_id: [0xAA; 16], … }`; downstream tests
//! cover all four bijection / decision combinations.
//!
//! This file is separate from `core/tests/sync_merge.rs` because each
//! `tests/*.rs` is its own test binary, and `sync_merge.rs` already
//! sits at ~500 LOC after Task 12. New per-veto tests live here so the
//! veto concern is in one file.

use std::collections::BTreeMap;

use secretary_core::crypto::secret::SecretString;
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncOutcome, SyncState, VetoDecision,
};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{open_vault, Record, RecordField, RecordFieldValue, Unlocker};

mod fixtures;
mod sync_helpers;

use fixtures::extract_vault_uuid;

/// Record UUID shared across all four Task 13 fixtures. Single byte
/// (`0xAA`) replicated 16× so the bytes stay readable in failing-test
/// output.
const VETO_RECORD_UUID: [u8; 16] = [0xAA; 16];
/// Canonical device clock anchor. The local edit (live record) carries
/// `last_mod_ms = LOCAL_LAST_MOD_MS` and the canonical block's
/// `vector_clock_summary` references this device.
const CANONICAL_DEVICE_UUID: [u8; 16] = [0x0A; 16];
/// Sibling device clock anchor. The peer's tombstone carries
/// `tombstoned_at_ms = DISK_TOMBSTONE_AT_MS` and the sibling block's
/// `vector_clock_summary` references this device.
const SIBLING_DEVICE_UUID: [u8; 16] = [0x0B; 16];
/// Local device clock anchor. Distinct from canonical / sibling so the
/// `SyncState.highest_vector_clock_seen` vs disk-manifest clock is
/// `Concurrent` (sync_once precondition for `ConcurrentDetected`).
const LOCAL_DEVICE_UUID: [u8; 16] = [0x0C; 16];
/// Live record `last_mod_ms` — strictly less than `DISK_TOMBSTONE_AT_MS`
/// so the peer's tombstone is "after" the local edit and the per-record
/// veto pass fires.
const LOCAL_LAST_MOD_MS: u64 = 100;
/// Sibling tombstone timestamp. Strictly greater than `LOCAL_LAST_MOD_MS`
/// so `tombstone_veto_set` returns `Some(_)`.
const DISK_TOMBSTONE_AT_MS: u64 = 200;
/// Commit timestamp passed to `commit_with_decisions`.
const COMMIT_NOW_MS: u64 = 1_000_000;
/// Sibling manifest filename — must start with `manifest.cbor.enc` per
/// `enumerate_manifest_siblings`. The Syncthing-style suffix is used
/// throughout the C.1.1a / C.1.1b tests for consistency.
const SIBLING_MANIFEST_FILENAME: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
/// Sibling block-file suffix — must start with a non-empty separator so
/// the resulting filename is recognised by `enumerate_block_siblings`.
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";

/// Build the LIVE local record carried by the canonical block. One
/// field with a synthetic key so the tombstone-veto check sees a non-
/// empty `last_modifier_device` signal.
fn live_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("local")),
            last_mod: LOCAL_LAST_MOD_MS,
            device_uuid: CANONICAL_DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: VETO_RECORD_UUID,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: LOCAL_LAST_MOD_MS,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// Build the TOMBSTONED peer record carried by the sibling block. The
/// `tombstoned_at_ms` is strictly greater than `LOCAL_LAST_MOD_MS` so
/// the per-record veto pass fires (`tombstone_veto_set`'s strict-greater
/// branch).
fn tombstoned_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("ignored")),
            last_mod: DISK_TOMBSTONE_AT_MS,
            device_uuid: SIBLING_DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: VETO_RECORD_UUID,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: DISK_TOMBSTONE_AT_MS,
        tombstone: true,
        tombstoned_at_ms: DISK_TOMBSTONE_AT_MS,
        unknown: BTreeMap::new(),
    }
}

/// Drive the shared fixture forward to the
/// `(folder, identity, bundle, plan)` quadruple used by every Task 13
/// test. Encapsulates the boilerplate: copy golden_vault_001 + force
/// per-block divergence on the first block + open the identity + run
/// `sync_once` + assert `ConcurrentDetected`.
///
/// Returns the temp dir folder, the unlocked identity, the bundle, the
/// plan, AND the `tempfile::TempDir` (must outlive every test).
fn make_veto_fixture() -> (
    std::path::PathBuf,
    secretary_core::unlock::UnlockedIdentity,
    secretary_core::sync::VaultBundle,
    secretary_core::sync::DiffPlan,
    tempfile::TempDir,
) {
    // Discover the golden vault's first block_uuid in a throwaway open.
    let (probe_folder, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe_folder);

    let canonical_block_clock = vec![VectorClockEntry {
        device_uuid: CANONICAL_DEVICE_UUID,
        counter: 1,
    }];
    let sibling_block_clock = vec![VectorClockEntry {
        device_uuid: SIBLING_DEVICE_UUID,
        counter: 1,
    }];

    let (folder, tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![live_record()],
        canonical_block_clock.clone(),
        canonical_block_clock,
        vec![tombstoned_record()],
        sibling_block_clock.clone(),
        sibling_block_clock,
        SIBLING_MANIFEST_FILENAME,
        SIBLING_BLOCK_SUFFIX,
        COMMIT_NOW_MS,
    );

    let password = fixtures::golden_vault_001_password();
    let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle_bytes =
        std::fs::read(folder.join("identity.bundle.enc")).expect("read identity bundle");
    let identity =
        open_with_password(&vt_bytes, &bundle_bytes, &password).expect("open_with_password");

    let vault_uuid = extract_vault_uuid(&folder);
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    let outcome = sync_once(&folder, &identity, &state, 0u64).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    assert!(
        !plan.diverging_blocks.is_empty(),
        "Task 13 fixture must force per-block divergence — plan.diverging_blocks is empty",
    );

    (folder, identity, bundle, plan, tmp)
}

/// Read the canonical block file post-commit and return the records
/// inside. Used by Tasks 13.1 + 13.2 to assert the on-disk record
/// state matches the caller's decision.
fn read_canonical_block_records(folder: &std::path::Path, block_uuid: [u8; 16]) -> Vec<Record> {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("post-commit open");
    let block_path = sync_helpers::block_file_path(folder, &block_uuid);
    let bytes = std::fs::read(&block_path).expect("read post-commit canonical block");
    let plaintext =
        sync_helpers::decrypt_block_using_open(&open, &bytes).expect("decrypt post-commit block");
    plaintext.records
}

/// Task 13.1 — `KeepLocal` rejects the peer's tombstone, the live local
/// record survives on disk.
///
/// Fixture: canonical block has record `[0xAA]` LIVE at `t = 100`;
/// sibling block has record `[0xAA]` TOMBSTONED at `t = 200`. The
/// per-record veto pass in `prepare_merge` emits one
/// `RecordTombstoneVeto { record_id: [0xAA; 16], … }` because the peer
/// tombstone is strictly later than the local last_mod. The caller
/// passes `VetoDecision::KeepLocal { record_id: [0xAA; 16] }` to
/// `commit_with_decisions`; `apply_decisions` restores the veto's
/// `local_state` over the merge's tombstoned record, the commit
/// re-encrypts the canonical block, and the new on-disk record set
/// holds the LIVE record (`tombstone == false`,
/// `last_mod_ms == 100`).
///
/// Asserts:
/// 1. `commit_with_decisions(...)` succeeds with the supplied decision.
/// 2. Post-commit, the canonical block decrypts to exactly one record:
///    the live record with `tombstone == false` and `last_mod_ms == 100`.
/// 3. The returned `SyncState.highest_vector_clock_seen` carries both
///    the canonical + sibling block devices' entries (manifest-level
///    clock fold).
#[test]
fn commit_with_decisions_keep_local_overrides_peer_tombstone() {
    let (folder, identity, bundle, plan, _tmp) = make_veto_fixture();
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);

    let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
    assert_eq!(
        draft.vetoes.len(),
        1,
        "fixture must produce exactly one veto for the per-block-divergent record",
    );
    assert_eq!(
        draft.vetoes[0].record_id, VETO_RECORD_UUID,
        "veto must target the live record",
    );

    let password = fixtures::golden_vault_001_password();
    let new_state = commit_with_decisions(
        &folder,
        &password,
        draft,
        vec![VetoDecision::KeepLocal {
            record_id: VETO_RECORD_UUID,
        }],
        COMMIT_NOW_MS,
    )
    .expect("commit_with_decisions");

    // Post-commit on-disk state: the canonical block holds the LIVE
    // record. The merge would have written the tombstoned record (per
    // `merge_block`'s tombstone-wins-by-clock semantics); `KeepLocal`
    // restored the veto's `local_state`, which `commit_with_decisions`
    // re-encrypted into the new canonical block.
    let records = read_canonical_block_records(&folder, block_uuid);
    assert_eq!(
        records.len(),
        1,
        "post-commit block must contain exactly the kept record",
    );
    assert_eq!(records[0].record_uuid, VETO_RECORD_UUID);
    assert!(
        !records[0].tombstone,
        "KeepLocal must leave the record LIVE on disk",
    );
    assert_eq!(
        records[0].last_mod_ms, LOCAL_LAST_MOD_MS,
        "post-commit record must carry the local last_mod_ms (not the peer's tombstone clock)",
    );

    // Manifest-level clock fold: the returned SyncState carries both
    // manifest devices' entries (canonical_block_clock for device A and
    // sibling_block_clock for device B both flowed into the
    // manifest-level vector_clock via `post_merge_clock`).
    assert!(
        new_state
            .highest_vector_clock_seen
            .iter()
            .any(|e| e.device_uuid == CANONICAL_DEVICE_UUID && e.counter == 1),
        "new SyncState must include canonical-side device entry",
    );
    assert!(
        new_state
            .highest_vector_clock_seen
            .iter()
            .any(|e| e.device_uuid == SIBLING_DEVICE_UUID && e.counter == 1),
        "new SyncState must include sibling-side device entry",
    );
}

/// Task 13.2 — `AcceptTombstone` finalizes the peer's tombstone: the
/// merged tombstoned record is persisted unchanged.
///
/// Fixture is identical to Task 13.1's. The caller passes
/// `VetoDecision::AcceptTombstone { record_id: [0xAA; 16] }`;
/// `apply_decisions` treats `AcceptTombstone` as a no-op (the merge
/// already wrote the tombstone into `merged_records` via
/// `merge_block`'s §11.3 tombstone-wins-by-clock rule), the commit
/// re-encrypts the canonical block, and the new on-disk record set
/// holds the TOMBSTONED record (`tombstone == true`,
/// `tombstoned_at_ms == 200`).
///
/// Asserts:
/// 1. `commit_with_decisions(...)` succeeds with the
///    `AcceptTombstone` decision.
/// 2. Post-commit, the canonical block decrypts to one record with
///    `tombstone == true` and `tombstoned_at_ms == 200` (the peer's
///    death clock).
/// 3. The merged record's `last_mod_ms` advances to the peer's
///    `tombstoned_at_ms` (per `merge_record`'s
///    `last_mod_ms = local.last_mod_ms.max(remote.last_mod_ms)`).
#[test]
fn commit_with_decisions_accept_tombstone_finalizes_peer_delete() {
    let (folder, identity, bundle, plan, _tmp) = make_veto_fixture();
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);

    let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
    assert_eq!(
        draft.vetoes.len(),
        1,
        "fixture must produce exactly one veto for the per-block-divergent record",
    );

    let password = fixtures::golden_vault_001_password();
    commit_with_decisions(
        &folder,
        &password,
        draft,
        vec![VetoDecision::AcceptTombstone {
            record_id: VETO_RECORD_UUID,
        }],
        COMMIT_NOW_MS,
    )
    .expect("commit_with_decisions");

    // Post-commit on-disk state: the canonical block now holds the
    // TOMBSTONED record. The merge wrote the death clock and
    // `AcceptTombstone` did not override it (no-op on the merged set).
    let records = read_canonical_block_records(&folder, block_uuid);
    assert_eq!(
        records.len(),
        1,
        "post-commit block must contain exactly the tombstoned record (tombstones are kept-for-undelete per §6.3)",
    );
    assert_eq!(records[0].record_uuid, VETO_RECORD_UUID);
    assert!(
        records[0].tombstone,
        "AcceptTombstone must leave the record TOMBSTONED on disk",
    );
    assert_eq!(
        records[0].tombstoned_at_ms, DISK_TOMBSTONE_AT_MS,
        "post-commit record must carry the peer's tombstoned_at_ms (death clock)",
    );
    // §11.5 invariant: `tombstoned_at_ms == last_mod_ms` on tombstoned
    // records. `merge_record`'s `last_mod_ms = max(local, remote)` plus
    // the §11.3 staleness filter together enforce this — the assertion
    // pins the post-merge shape against an accidental drift.
    assert_eq!(
        records[0].last_mod_ms, DISK_TOMBSTONE_AT_MS,
        "tombstoned record must satisfy §11.5 invariant `tombstoned_at_ms == last_mod_ms`",
    );
}

/// Task 13.3 — Missing veto decision aborts the commit with a typed
/// error pointing at the un-adjudicated `record_id`.
///
/// Fixture is identical to Task 13.1's. The caller passes EMPTY
/// `decisions` even though `draft.vetoes` carries one veto. The
/// bijection check in `commit::apply_decisions` (see §"bijection
/// rules") sees `veto_ids - decision_ids = {[0xAA; 16]}` and returns
/// `SyncError::MissingVetoDecision { record_id: [0xAA; 16] }`. The
/// abort happens BEFORE any block re-encrypt or manifest rewrite.
///
/// Asserts:
/// 1. `commit_with_decisions(...)` returns
///    `Err(SyncError::MissingVetoDecision { record_id: [0xAA; 16] })`.
/// 2. The on-disk canonical block file is byte-identical to its
///    pre-commit state — the abort happens before any commit-side
///    write, so the fixture's block survives unchanged. (The
///    manifest is also pre-commit-identical, but the manifest's
///    no-write invariant is already covered by Task 12's
///    `commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes`;
///    this test focuses on the block-side proof.)
#[test]
fn commit_with_decisions_missing_veto_decision_aborts_with_typed_error() {
    let (folder, identity, bundle, plan, _tmp) = make_veto_fixture();
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);

    let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
    assert_eq!(
        draft.vetoes.len(),
        1,
        "fixture must produce exactly one veto for the per-block-divergent record",
    );

    // Snapshot the canonical block bytes BEFORE the (expected-to-abort)
    // commit so the no-disk-write post-condition can be proved.
    let block_path = sync_helpers::block_file_path(&folder, &block_uuid);
    let block_bytes_before = std::fs::read(&block_path).expect("read canonical block pre-commit");

    let password = fixtures::golden_vault_001_password();
    let err = commit_with_decisions(&folder, &password, draft, Vec::new(), COMMIT_NOW_MS)
        .expect_err(
            "commit_with_decisions must reject an empty decisions vec when vetoes are non-empty",
        );

    match err {
        secretary_core::sync::SyncError::MissingVetoDecision { record_id } => {
            assert_eq!(
                record_id, VETO_RECORD_UUID,
                "MissingVetoDecision must report the un-adjudicated record_id",
            );
        }
        other => panic!("expected SyncError::MissingVetoDecision, got {other:?}"),
    }

    // Post-condition: the canonical block file is byte-identical to its
    // pre-commit state. `apply_decisions` runs at commit step 3 (BEFORE
    // step 5's per-block re-encrypt), so the typed error fires with
    // zero block writes happening downstream.
    let block_bytes_after = std::fs::read(&block_path).expect("read canonical block post-abort");
    assert_eq!(
        block_bytes_before, block_bytes_after,
        "MissingVetoDecision must abort with NO block writes; canonical block bytes changed",
    );
}
