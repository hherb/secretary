//! Integration test for the D5 TOCTOU freshness short-circuit inside
//! `commit_with_decisions` — the *block-write* half (#103).
//!
//! `commit_with_decisions` re-checks the on-disk manifest envelope hash
//! against `draft.manifest_hash` at step 2 of its prologue, BEFORE step 5
//! re-encrypts any diverging block ([core/src/sync/commit/write.rs] —
//! the `EvidenceStale` early return at step 2 precedes the per-block
//! `rewrite_one_block` loop at step 5). A mid-flight manifest mutation
//! therefore aborts the commit with [`SyncError::EvidenceStale`] and must
//! leave the disk *completely* untouched: no manifest write AND no block
//! write.
//!
//! The companion test
//! [`sync_merge.rs::commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes`]
//! (Task 12) proves the *manifest* half using the empty-divergence
//! fixture — there are no affected blocks, so manifest byte-equality is
//! the single commit-point check. This file adds the *block* half: a
//! divergence-bearing fixture (`bundle.diverging_blocks` non-empty) so
//! step 5 has real per-block rewrites queued, and asserts those block
//! files are byte-identical across the failed commit. Together the two
//! tests prove the freshness re-check has the *complete* short-circuit
//! property.
//!
//! Lives in its own test binary (rather than extending `sync_merge.rs`,
//! already near the ~500-LOC threshold) per the project's split-by-concept
//! precedent (`sync_merge_vetoes.rs`, `sync_merge_crash.rs`).

use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncOutcome, SyncState,
};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;

mod fixtures;
mod sync_helpers;

use fixtures::extract_vault_uuid;

/// Record UUID carried by the canonical block. Distinct from the sibling
/// UUID so the merge is a clean union with no per-record vetoes — the
/// abort under test must fire from the freshness re-check, not a veto.
const CANONICAL_RECORD_UUID: [u8; 16] = [0xAA; 16];
/// Record UUID carried by the sibling block (distinct from canonical).
const SIBLING_RECORD_UUID: [u8; 16] = [0xBB; 16];
/// Canonical device clock anchor (block `vector_clock_summary` + manifest
/// `vector_clock` on the canonical side).
const CANONICAL_DEVICE_UUID: [u8; 16] = [0x0A; 16];
/// Sibling device clock anchor (block + manifest clocks on the sibling
/// conflict-copy).
const SIBLING_DEVICE_UUID: [u8; 16] = [0x0B; 16];
/// Local device clock anchor (the persisted `SyncState`'s seen-clock
/// entry; distinct from canonical + sibling so the relation is
/// `Concurrent` and `sync_once` yields `ConcurrentDetected`).
const LOCAL_DEVICE_UUID: [u8; 16] = [0x0C; 16];
/// Clock counter on every single-entry vector clock in this fixture.
const CLOCK_COUNTER: u64 = 1;
/// `last_mod_ms` on the canonical record.
const CANONICAL_LAST_MOD_MS: u64 = 100;
/// `last_mod_ms` on the sibling record.
const SIBLING_LAST_MOD_MS: u64 = 200;
/// `now_ms` the fixture stamps onto both blocks + manifests.
const FIXTURE_NOW_MS: u64 = 1_000_000;
/// `now_ms` passed to the (doomed) `commit_with_decisions` call.
const COMMIT_NOW_MS: u64 = 2_000_000;
/// Sibling manifest filename. Must start with `manifest.cbor.enc` so
/// `enumerate_manifest_siblings` discovers it.
const SIBLING_MANIFEST_FILENAME: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
/// Sibling block-file suffix. Must start with a non-empty separator so
/// `enumerate_block_siblings` picks it up.
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";

/// Mutating the canonical manifest between `prepare_merge` and
/// `commit_with_decisions` — on a fixture whose merge DOES have per-block
/// rewrites queued — must abort with [`SyncError::EvidenceStale`] AND
/// leave BOTH the manifest and the diverging block files byte-identical
/// to their pre-commit state (the complete short-circuit: zero disk
/// writes).
///
/// This is the block-write half of the property proved (for the manifest
/// only) by `sync_merge.rs::commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes`.
///
/// Flow:
/// 1. Build a per-block-divergent canonical/sibling fixture so that after
///    `sync_once` the bundle/plan carry a non-empty `diverging_blocks`
///    (asserted — guards against a vacuous test where step 5 has nothing
///    to write).
/// 2. `sync_once → prepare_merge`. The draft captures `manifest_hash`
///    over the current (`CANONICAL_NONCE_A`) canonical manifest envelope.
///    The draft has no vetoes (distinct record UUIDs → clean union).
/// 3. Snapshot the canonical manifest + diverging block file bytes.
/// 4. Open the TOCTOU race window: re-emit the canonical manifest with
///    the SAME logical content but a different AEAD nonce
///    (`SIBLING_NONCE_D`). The envelope bytes — hence the BLAKE3 hash —
///    change, so the on-disk hash diverges from `draft.manifest_hash`,
///    while `open_vault` (commit step 1) still accepts it (the block
///    entries / fingerprints / signature are unchanged).
/// 5. `commit_with_decisions` must return `Err(EvidenceStale)`.
/// 6. Assert the canonical block file is byte-identical to step 3 — step
///    5's `rewrite_one_block` never ran (the NEW assertion for #103).
/// 7. Assert the canonical manifest is byte-identical to its
///    post-race-window state — no manifest write either.
#[test]
fn commit_with_decisions_stale_manifest_with_diverging_blocks_writes_no_block_files() {
    // Step 0: discover the golden vault's first block_uuid via a throwaway
    // open (the fixture diverges this exact block on both sides).
    let (probe_folder, _probe_tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&probe_folder);

    let canonical_block_clock = vec![VectorClockEntry {
        device_uuid: CANONICAL_DEVICE_UUID,
        counter: CLOCK_COUNTER,
    }];
    let sibling_block_clock = vec![VectorClockEntry {
        device_uuid: SIBLING_DEVICE_UUID,
        counter: CLOCK_COUNTER,
    }];

    // Step 1: build the divergence-bearing fixture. Canonical block holds
    // record [0xAA] @100; sibling block holds record [0xBB] @200. Distinct
    // UUIDs → the merge unions them with no vetoes. Both the canonical
    // block file and the canonical manifest end up on disk; the manifest
    // is signed with CANONICAL_NONCE_A.
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![sync_helpers::live_record(
            CANONICAL_RECORD_UUID,
            CANONICAL_DEVICE_UUID,
            CANONICAL_LAST_MOD_MS,
            "canonical",
        )],
        canonical_block_clock.clone(),
        canonical_block_clock.clone(),
        vec![sync_helpers::live_record(
            SIBLING_RECORD_UUID,
            SIBLING_DEVICE_UUID,
            SIBLING_LAST_MOD_MS,
            "sibling",
        )],
        sibling_block_clock.clone(),
        sibling_block_clock,
        SIBLING_MANIFEST_FILENAME,
        SIBLING_BLOCK_SUFFIX,
        FIXTURE_NOW_MS,
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
        counter: CLOCK_COUNTER,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    // Step 2: drive sync to a draft. The draft's manifest_hash pins the
    // CANONICAL_NONCE_A envelope captured here.
    let outcome = sync_once(&folder, &identity, &state, 0u64).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    assert!(
        !bundle.diverging_blocks.is_empty(),
        "fixture must force per-block divergence so step 5 has real block rewrites to short-circuit",
    );
    assert!(
        plan.diverging_blocks.contains(&block_uuid),
        "the block we snapshot must be one step 5 would rewrite on a successful commit",
    );

    let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
    assert!(
        draft.vetoes.is_empty(),
        "distinct record UUIDs must merge with no vetoes (got {} vetoes)",
        draft.vetoes.len(),
    );

    // Step 4: open the TOCTOU race window. Re-emit the canonical manifest
    // with its existing logical content (same vector_clock, same preserved
    // block entries) but a fresh AEAD nonce. Only the envelope bytes
    // change, so commit step 1's `open_vault` still accepts the manifest
    // (it is logically identical to one that already opened cleanly) while
    // step 2's BLAKE3 freshness re-check sees a hash != draft.manifest_hash.
    // SIBLING_NONCE_D differs from the fixture's CANONICAL_NONCE_A, so the
    // re-emitted bytes are guaranteed distinct.
    sync_helpers::write_manifest_at(
        &folder,
        sync_helpers::MANIFEST_FILENAME,
        canonical_block_clock,
        &sync_helpers::SIBLING_NONCE_D,
    );

    // Step 3 (snapshot AFTER the race window — the block file is untouched
    // by `write_manifest_at`, and we want the manifest baseline to be its
    // post-mutation state so any commit-side write would be detectable).
    let manifest_path = folder.join(sync_helpers::MANIFEST_FILENAME);
    let block_path = sync_helpers::block_file_path(&folder, &block_uuid);
    let manifest_before = std::fs::read(&manifest_path).expect("read manifest before commit");
    let block_before = std::fs::read(&block_path).expect("read diverging block before commit");

    // Step 5: the doomed commit.
    let err = commit_with_decisions(&folder, &password, draft, Vec::new(), COMMIT_NOW_MS)
        .expect_err("commit_with_decisions must reject a stale draft.manifest_hash");
    assert!(
        matches!(err, secretary_core::sync::SyncError::EvidenceStale),
        "expected SyncError::EvidenceStale, got {err:?}",
    );

    // Step 6 (NEW, #103): the diverging block file is byte-identical —
    // step 5's `rewrite_one_block` never persisted a tempfile.
    let block_after = std::fs::read(&block_path).expect("read diverging block after commit");
    assert_eq!(
        block_before, block_after,
        "EvidenceStale must abort BEFORE any block re-encrypt; diverging block bytes changed",
    );

    // Step 7: the canonical manifest is byte-identical too — no manifest
    // write happened either (mirrors the Task 12 manifest-half assertion).
    let manifest_after = std::fs::read(&manifest_path).expect("read manifest after commit");
    assert_eq!(
        manifest_before, manifest_after,
        "EvidenceStale must abort with NO disk writes; manifest bytes changed",
    );
}
