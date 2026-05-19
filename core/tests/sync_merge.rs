//! Integration tests for the C.1.1b merge layer.
//!
//! Tasks 8, 9, 12, 13, 14 each grow this file. Task 8 covers the
//! happy-path empty-divergence case: two concurrent manifests that
//! reference the SAME block contents, so `bundle.diverging_blocks` is
//! empty and `prepare_merge` should produce a `DraftMerge` with no
//! vetoes, no merged records, and a manifest-level vector clock equal
//! to the component-wise max of the canonical and copy clocks.

use std::collections::BTreeMap;
use std::path::Path;

use secretary_core::crypto::secret::SecretString;
use secretary_core::sync::{prepare_merge, sync_once, SyncOutcome, SyncState};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{open_vault, Record, RecordField, RecordFieldValue, Unlocker};

mod fixtures;
mod sync_helpers;

/// Read the vault_uuid from the fixture folder's `vault.toml`. Mirrors
/// the helper used in `core/tests/sync.rs`; pulled into this file so
/// the merge-layer integration tests don't depend on the sync.rs test
/// module. (A follow-up could lift this into `fixtures/mod.rs` if more
/// test files need it, but it's deferred — out of scope for Task 8.)
fn extract_vault_uuid(folder: &Path) -> [u8; 16] {
    let s = std::fs::read_to_string(folder.join("vault.toml"))
        .expect("vault.toml must exist in fixture folder");
    let vt = secretary_core::unlock::vault_toml::decode(&s).expect("decode vault.toml");
    vt.vault_uuid
}

/// Concurrent canonical + sibling manifests with no per-block changes:
/// `bundle.diverging_blocks` is empty, so `prepare_merge` runs zero
/// iterations of the per-block decap loop. The expected `DraftMerge`
/// has no vetoes, no merged records, an empty `plan.diverging_blocks`,
/// and a `post_merge_clock` that includes both the canonical and the
/// sibling manifest's vector-clock entries.
///
/// Tasks 9 + 13 cover the non-empty `diverging_blocks` paths and the
/// veto-detection paths respectively; this test only asserts the
/// orchestrator wires up correctly end-to-end.
#[test]
fn prepare_merge_on_two_concurrent_manifests_returns_draft_with_no_vetoes() {
    let device_canonical = [0x0A; 16];
    let device_sibling = [0x0B; 16];
    let device_local = [0x0C; 16];

    let canonical_clock = vec![VectorClockEntry {
        device_uuid: device_canonical,
        counter: 1,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: device_sibling,
        counter: 1,
    }];
    // The sibling filename MUST start with the canonical manifest name —
    // [`crate::sync::ingest::enumerate_manifest_siblings`] uses that
    // prefix as its discovery heuristic; ".sync-conflict-from-device-bb"
    // mirrors the Syncthing naming convention used in `sync_ingest.rs`.
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.sync-conflict-from-device-bb",
        sibling_clock,
    );

    let password = fixtures::golden_vault_001_password();
    let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle_bytes =
        std::fs::read(folder.join("identity.bundle.enc")).expect("read identity bundle");
    let identity =
        open_with_password(&vt_bytes, &bundle_bytes, &password).expect("open_with_password");

    // State carries a third device unrelated to canonical/sibling, so
    // the clock relation between state.highest_vector_clock_seen and
    // the disk's canonical manifest clock is `Concurrent` — neither
    // dominates the other. This is the precondition for sync_once to
    // produce `ConcurrentDetected`.
    let vault_uuid = extract_vault_uuid(&folder);
    let local_clock = vec![VectorClockEntry {
        device_uuid: device_local,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    let outcome = sync_once(&folder, &identity, &state, 0u64).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };

    let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");

    assert!(
        draft.vetoes.is_empty(),
        "no vetoes expected when no blocks diverge"
    );
    assert!(
        draft.merged_records.is_empty(),
        "no merged records expected when no blocks diverge",
    );
    assert_eq!(
        draft.plan.diverging_blocks.len(),
        plan.diverging_blocks.len(),
        "draft must forward the diverging_blocks plan verbatim",
    );
    assert_eq!(
        draft.vault_uuid, vault_uuid,
        "draft vault_uuid must match the fixture's vault.toml",
    );

    let post = &draft.post_merge_clock;
    assert!(
        post.iter()
            .any(|e| e.device_uuid == device_canonical && e.counter == 1),
        "post_merge_clock must include canonical manifest device entry",
    );
    assert!(
        post.iter()
            .any(|e| e.device_uuid == device_sibling && e.counter == 1),
        "post_merge_clock must include sibling manifest device entry",
    );
}

/// Task 9: exercise the canonical-block-rewrite path end-to-end. Uses
/// [`sync_helpers::rewrite_block_with_records_and_update_manifest`] to
/// install a single new record into a canonical block (re-signing the
/// manifest so `verify_block_fingerprints` agrees), then writes a
/// sibling manifest with a concurrent top-level vector clock. Both
/// manifests reference the same (rewritten) block file with the same
/// per-block `vector_clock_summary`, so `bundle.diverging_blocks` is
/// empty and the iterative merge loop runs zero times — same smoke
/// level as Task 8, but with a non-trivial canonical fixture that
/// proves:
///
/// 1. The new helper produces an on-disk vault that opens cleanly
///    (the D6 fingerprint gate accepts the post-rewrite state).
/// 2. The new record actually lands inside the canonical block
///    envelope, retrievable via the owner identity.
/// 3. `prepare_merge` composes correctly on the post-rewrite fixture:
///    empty `diverging_blocks` ⇒ empty `merged_records` + empty
///    `vetoes`, and `post_merge_clock` still folds the canonical and
///    sibling manifest-level clocks together.
///
/// Task 13 will extend this fixture to force `diverging_blocks` to be
/// non-empty (per-block clock divergence between canonical and
/// sibling) and exercise `prepare_merge`'s iterative fold path with
/// real divergent records.
#[test]
fn prepare_merge_after_canonical_block_rewrite_produces_well_formed_draft() {
    let device_a = [0x0A; 16];
    let device_b = [0x0B; 16];
    let device_local = [0x0C; 16];
    let record_uuid: [u8; 16] = [0xAA; 16];

    // Pre-rewrite open: cached handle drives both the block re-encrypt
    // AND the manifest re-sign without ever re-reading disk during the
    // fingerprint-inconsistent window.
    let (folder, _tmp) = sync_helpers::fresh_vault_with_clock(Vec::new());
    let password = fixtures::golden_vault_001_password();
    let pre_open = open_vault(&folder, Unlocker::Password(&password), None).expect("pre-open");

    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);
    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("local")),
            last_mod: 100,
            device_uuid: device_a,
            unknown: BTreeMap::new(),
        },
    );
    let local_record = Record {
        record_uuid,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: 100,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    };
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: device_a,
        counter: 1,
    }];
    sync_helpers::rewrite_block_with_records_and_update_manifest(
        &folder,
        &pre_open,
        block_uuid,
        vec![local_record.clone()],
        &sync_helpers::BLOCK_NONCE_E,
        canonical_clock,
        &sync_helpers::CANONICAL_NONCE_A,
    );
    // Helper's contract: pre_open is consumed for its cached keys only;
    // a fresh open_vault must now succeed against the rewritten state.
    drop(pre_open);

    // Sibling manifest: same on-disk block, different top-level clock.
    // [`write_manifest_at`] internally re-opens the vault — that only
    // works because the canonical helper above re-signed the manifest
    // consistently with the rewritten block bytes.
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: device_b,
        counter: 1,
    }];
    sync_helpers::write_manifest_at(
        &folder,
        "manifest.cbor.enc.sync-conflict-from-device-bb",
        sibling_clock,
        &sync_helpers::SIBLING_NONCE_B,
    );

    // Round-trip: the rewritten block actually contains the new record.
    let post_open = open_vault(&folder, Unlocker::Password(&password), None).expect("post-open");
    let block_path = sync_helpers::block_file_path(&folder, &block_uuid);
    let block_bytes = std::fs::read(&block_path).expect("read block file");
    let plaintext = sync_helpers::decrypt_block_using_open(&post_open, &block_bytes)
        .expect("decrypt rewritten block");
    assert_eq!(
        plaintext.records.len(),
        1,
        "rewritten block should hold exactly the helper-supplied record",
    );
    assert_eq!(
        plaintext.records[0].record_uuid, record_uuid,
        "rewritten block must carry the local record",
    );

    let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle_bytes =
        std::fs::read(folder.join("identity.bundle.enc")).expect("read identity bundle");
    let identity =
        open_with_password(&vt_bytes, &bundle_bytes, &password).expect("open_with_password");

    let vault_uuid = extract_vault_uuid(&folder);
    let local_clock = vec![VectorClockEntry {
        device_uuid: device_local,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    let outcome = sync_once(&folder, &identity, &state, 0u64).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    // Both manifests carry identical per-block vector_clock_summary
    // (`write_manifest_at` only mutates the manifest-level clock), so
    // the bundle's per-block divergence map is empty even though the
    // top-level clocks are concurrent.
    assert!(
        bundle.diverging_blocks.is_empty(),
        "Task 9 fixture does not force per-block divergence; that arrives in Task 13",
    );
    assert!(
        plan.diverging_blocks.is_empty(),
        "plan must match bundle on empty diverging_blocks",
    );

    let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
    assert!(draft.vetoes.is_empty(), "no vetoes when no blocks diverge",);
    assert!(
        draft.merged_records.is_empty(),
        "no merged records when no blocks diverge",
    );
    assert_eq!(
        draft.vault_uuid, vault_uuid,
        "draft vault_uuid must match the fixture's vault.toml",
    );
    let post = &draft.post_merge_clock;
    assert!(
        post.iter()
            .any(|e| e.device_uuid == device_a && e.counter == 1),
        "post_merge_clock must include canonical-rewriter device entry",
    );
    assert!(
        post.iter()
            .any(|e| e.device_uuid == device_b && e.counter == 1),
        "post_merge_clock must include sibling device entry",
    );
}
