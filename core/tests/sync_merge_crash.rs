//! Integration test for C.1.1b Task 14 — partial-commit crash recovery
//! via CRDT-idempotent re-run (design §D6 / option (d)).
//!
//! `commit_with_decisions` writes blocks first (step 5) and the manifest
//! last (step 7). A crash between those steps leaves the disk with the
//! new block content but the old manifest — pointing to a stale
//! `BlockEntry.fingerprint`. The next `open_vault` runs
//! `verify_block_fingerprints` (D6 gate) and surfaces
//! [`VaultError::BlockFingerprintMismatch`].
//!
//! The recovery story is: roll the affected block back to its pre-commit
//! bytes, then re-run `sync_once → prepare_merge → commit_with_decisions`
//! using the caller's PRE-COMMIT [`SyncState`] (the commit crashed
//! before it could return [`SyncState`], so the caller never persisted
//! the v1 state). Since the merge is deterministic in the records +
//! clocks (only the AEAD nonces differ between commits), the retried
//! commit produces the same observable `SyncState` and the same decrypted
//! canonical block records — CRDT idempotence in action.
//!
//! Lives in its own test binary rather than extending `sync_merge_vetoes.rs`
//! because that file already sits at ~500 LOC after Task 13.4 and crash
//! recovery is a distinct concern from veto handling.

use std::collections::BTreeMap;

use secretary_core::crypto::secret::SecretString;
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncOutcome, SyncState,
};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{
    open_vault, Record, RecordField, RecordFieldValue, Unlocker, VaultError,
};

mod fixtures;
mod sync_helpers;

use fixtures::extract_vault_uuid;

/// Record UUID carried by the canonical block. Single byte (`0xAA`)
/// replicated 16× for readability in failing-test output.
const CANONICAL_RECORD_UUID: [u8; 16] = [0xAA; 16];
/// Record UUID carried by the sibling block. Distinct from
/// `CANONICAL_RECORD_UUID` so the records do NOT conflict — the merge
/// produces a clean union with no per-record vetoes.
const SIBLING_RECORD_UUID: [u8; 16] = [0xBB; 16];
/// Canonical device clock anchor (records `last_modifier_device`,
/// `vector_clock_summary` on the canonical block).
const CANONICAL_DEVICE_UUID: [u8; 16] = [0x0A; 16];
/// Sibling device clock anchor (records `last_modifier_device`,
/// `vector_clock_summary` on the sibling block).
const SIBLING_DEVICE_UUID: [u8; 16] = [0x0B; 16];
/// Local device clock anchor (the persisted `SyncState`'s
/// `highest_vector_clock_seen` entry; distinct from canonical +
/// sibling so the relation is `Concurrent`).
const LOCAL_DEVICE_UUID: [u8; 16] = [0x0C; 16];
/// `last_mod_ms` on the canonical record. Constant; nothing else fixes
/// the value.
const CANONICAL_LAST_MOD_MS: u64 = 100;
/// `last_mod_ms` on the sibling record. Constant; nothing else fixes
/// the value.
const SIBLING_LAST_MOD_MS: u64 = 200;
/// `now_ms` passed to `commit_with_decisions`. Reused across both
/// invocations so the manifest `last_mod_ms` matches between v1 and v2.
const COMMIT_NOW_MS: u64 = 1_000_000;
/// Sibling manifest filename. Must start with `manifest.cbor.enc` per
/// `enumerate_manifest_siblings`.
const SIBLING_MANIFEST_FILENAME: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
/// Sibling block-file suffix. Must start with a non-empty separator so
/// `enumerate_block_siblings` picks it up.
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";

/// Build a LIVE record with a single field. `uuid` controls the
/// `record_uuid` so the canonical and sibling sides carry distinct
/// (non-conflicting) records.
fn live_record(uuid: [u8; 16], device_uuid: [u8; 16], last_mod_ms: u64, marker: &str) -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from(marker)),
            last_mod: last_mod_ms,
            device_uuid,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: uuid,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// Read the canonical block file at `block_uuid` and return the
/// decrypted records inside. The block is decrypted via a freshly opened
/// vault so the caller's stale `OpenVault` state does not contaminate
/// the assertion.
fn read_canonical_block_records(folder: &std::path::Path, block_uuid: [u8; 16]) -> Vec<Record> {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    let block_path = sync_helpers::block_file_path(folder, &block_uuid);
    let bytes = std::fs::read(&block_path).expect("read block file");
    let plaintext = sync_helpers::decrypt_block_using_open(&open, &bytes).expect("decrypt block");
    plaintext.records
}

/// Task 14 — a crash between block-write and manifest-write is
/// detectable, recoverable, and the retried commit converges to the
/// same observable state.
///
/// Fixture: per-block-divergent canonical / sibling pair. Canonical
/// block holds record `[0xAA]` LIVE at `last_mod_ms = 100`; sibling
/// block holds record `[0xBB]` LIVE at `last_mod_ms = 200`. The records
/// have distinct UUIDs, so the merge produces a clean union with no
/// vetoes — `commit_with_decisions(..., decisions = [])` succeeds.
///
/// Flow:
/// 1. Capture pre-commit canonical block bytes `b_v0` + manifest bytes
///    `m_v0`.
/// 2. Drive `sync_once → prepare_merge → commit_with_decisions` →
///    `state_v1`. Capture post-commit block bytes `b_v1` + manifest
///    bytes `m_v1` + decrypted record set `records_v1`.
/// 3. Roll the manifest BACK to `m_v0` while leaving the block at
///    `b_v1`. This is the on-disk shape of a crash AFTER step 5 (block
///    re-encrypt) but BEFORE step 7 (manifest write) of
///    `commit_with_decisions`.
/// 4. Assert `open_vault` errs with `VaultError::BlockFingerprintMismatch`
///    (D6 gate fires on the stale manifest's fingerprint vs the new
///    block's bytes).
/// 5. Recovery: restore the block to `b_v0`. The vault is now back to
///    its pre-commit consistent state. (The caller never persisted
///    `state_v1` because the commit crashed before returning; the
///    persisted state is still the pre-commit `state_pre`.)
/// 6. Re-run `sync_once → prepare_merge → commit_with_decisions` with
///    `state_pre` → `state_v2`. Capture `records_v2`.
/// 7. Assert `state_v2 == state_v1` (post-merge vector clocks
///    deterministic in the inputs).
/// 8. Assert `records_v2 == records_v1` (merged record set
///    deterministic in the inputs; AEAD nonces differ but plaintext
///    matches).
/// 9. Assert `open_vault` succeeds on the recovered + re-committed
///    vault.
#[test]
fn partial_commit_recovers_via_idempotent_re_run() {
    // Step 0: discover the golden vault's first block_uuid in a throwaway
    // open, mirroring the pattern in sync_merge_vetoes.rs::make_veto_fixture.
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

    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![live_record(
            CANONICAL_RECORD_UUID,
            CANONICAL_DEVICE_UUID,
            CANONICAL_LAST_MOD_MS,
            "canonical",
        )],
        canonical_block_clock.clone(),
        canonical_block_clock,
        vec![live_record(
            SIBLING_RECORD_UUID,
            SIBLING_DEVICE_UUID,
            SIBLING_LAST_MOD_MS,
            "sibling",
        )],
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
    // Pre-commit SyncState. Re-used on the retry path — the caller
    // never persisted state_v1 because the crash interrupted the commit
    // before it could return.
    let state_pre = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    // Step 1: capture pre-commit canonical block + manifest bytes.
    let canonical_block_path = sync_helpers::block_file_path(&folder, &block_uuid);
    let manifest_path = folder.join(sync_helpers::MANIFEST_FILENAME);
    let b_v0 = std::fs::read(&canonical_block_path).expect("read pre-commit canonical block");
    let m_v0 = std::fs::read(&manifest_path).expect("read pre-commit manifest");

    // Step 2: drive the initial sync to a successful commit.
    let outcome_v1 = sync_once(&folder, &identity, &state_pre, 0u64).expect("sync_once v1");
    let (bundle_v1, plan_v1) = match outcome_v1 {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected v1, got {other:?}"),
    };
    assert!(
        !plan_v1.diverging_blocks.is_empty(),
        "fixture must force per-block divergence (plan.diverging_blocks empty in v1)",
    );
    let draft_v1 =
        prepare_merge(&folder, &identity, &bundle_v1, &plan_v1).expect("prepare_merge v1");
    assert!(
        draft_v1.vetoes.is_empty(),
        "non-conflicting records must produce no vetoes (got {} vetoes in v1 draft)",
        draft_v1.vetoes.len(),
    );
    let state_v1 = commit_with_decisions(&folder, &password, draft_v1, Vec::new(), COMMIT_NOW_MS)
        .expect("commit_with_decisions v1");

    // Step 3: capture post-commit block + manifest bytes and the merged
    // record set on the canonical block.
    let b_v1 = std::fs::read(&canonical_block_path).expect("read post-commit canonical block");
    let m_v1 = std::fs::read(&manifest_path).expect("read post-commit manifest");
    assert_ne!(
        b_v0, b_v1,
        "post-commit canonical block must differ from pre-commit (re-encrypt with fresh AEAD nonce)",
    );
    assert_ne!(
        m_v0, m_v1,
        "post-commit manifest must differ from pre-commit (updated vector_clock + BlockEntry.fingerprint)",
    );
    let records_v1 = read_canonical_block_records(&folder, block_uuid);
    assert_eq!(
        records_v1.len(),
        2,
        "merged canonical block must hold both canonical and sibling records (got {} records)",
        records_v1.len(),
    );

    // Step 4: simulate the crash — roll the manifest BACK to m_v0 while
    // leaving the block at b_v1. The atomic-write contract guarantees
    // each file's write is all-or-nothing; multi-file atomicity is NOT
    // a filesystem primitive, so a crash between the per-block write
    // and the manifest write surfaces exactly this disk shape.
    std::fs::write(&manifest_path, &m_v0).expect("roll manifest back to m_v0");

    // Step 5: D6 gate must fire. open_vault re-runs
    // verify_block_fingerprints against the (stale) manifest's
    // BlockEntry.fingerprint vs the (new) on-disk block bytes — they
    // disagree.
    let open_err = open_vault(&folder, Unlocker::Password(&password), None)
        .expect_err("open_vault must err on post-crash fingerprint mismatch");
    let crashed_block_uuid = match open_err {
        VaultError::BlockFingerprintMismatch { block_uuid, .. } => block_uuid,
        other => panic!("expected VaultError::BlockFingerprintMismatch, got {other:?}"),
    };
    assert_eq!(
        crashed_block_uuid, block_uuid,
        "BlockFingerprintMismatch must name the rewritten block",
    );

    // Step 6: recovery — restore the canonical block to b_v0. The vault
    // is now back to its pre-commit consistent state.
    std::fs::write(&canonical_block_path, &b_v0).expect("restore canonical block to b_v0");

    // Step 7: re-run sync with the SAME pre-commit SyncState. The
    // caller never persisted state_v1 because the commit crashed before
    // returning.
    let outcome_v2 = sync_once(&folder, &identity, &state_pre, 0u64).expect("sync_once v2");
    let (bundle_v2, plan_v2) = match outcome_v2 {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected v2, got {other:?}"),
    };
    let draft_v2 =
        prepare_merge(&folder, &identity, &bundle_v2, &plan_v2).expect("prepare_merge v2");
    let state_v2 = commit_with_decisions(&folder, &password, draft_v2, Vec::new(), COMMIT_NOW_MS)
        .expect("commit_with_decisions v2");

    // Step 8: SyncState idempotence — the merged vector clocks are
    // deterministic in the canonical + sibling inputs, so state_v2
    // equals state_v1 even though AEAD nonces differ between the two
    // commits.
    assert_eq!(
        state_v2, state_v1,
        "retried commit must converge to the same SyncState",
    );

    // Step 9: merged-record idempotence — the canonical block's
    // decrypted plaintext is identical between v1 and v2 even though
    // the ciphertext (and the manifest's BlockEntry.fingerprint) differ
    // per AEAD nonce.
    let records_v2 = read_canonical_block_records(&folder, block_uuid);
    assert_eq!(
        records_v2, records_v1,
        "retried commit must reproduce the same canonical block record set",
    );

    // Step 10: the recovered vault opens cleanly.
    let _open =
        open_vault(&folder, Unlocker::Password(&password), None).expect("recovered open_vault");
}
