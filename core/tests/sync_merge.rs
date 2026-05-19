//! Integration tests for the C.1.1b merge layer.
//!
//! Tasks 8, 9, 12, 13, 14 each grow this file. Task 8 covers the
//! happy-path empty-divergence case: two concurrent manifests that
//! reference the SAME block contents, so `bundle.diverging_blocks` is
//! empty and `prepare_merge` should produce a `DraftMerge` with no
//! vetoes, no merged records, and a manifest-level vector clock equal
//! to the component-wise max of the canonical and copy clocks.

#![forbid(unsafe_code)]

use std::path::Path;

use secretary_core::sync::{prepare_merge, sync_once, SyncOutcome, SyncState};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;

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
