//! #401 — conflict-copy trash-list reconciliation end-to-end. A block is
//! trashed on both devices, purged on A, restored concurrently on B; after
//! reconciliation the merged manifest must have the block purged-in-trash
//! and absent from `blocks` (purge is terminal), and re-open + sweep must
//! remove the restoring device's leftover `blocks/` ciphertext.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use convergence_helpers::{reconcile, Baseline, Device};

const A_UUID: [u8; 16] = [0x0A; 16];
const B_UUID: [u8; 16] = [0x0B; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];
const X_RECORD: [u8; 16] = [0xAA; 16];

#[test]
fn purge_beats_concurrent_restore_across_conflict_copy() {
    // Baseline with one block X that both devices share.
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "seed", 100);
    let baseline = convergence_helpers::baseline_from_seeded(baseline, &a);

    // Both fork from a baseline where X is live, then both trash X.
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.trash_block(X_BLOCK, 200);
    b.trash_block(X_BLOCK, 200);
    // A purges X (permanent); B restores X (live again).
    a.purge_block(X_BLOCK, 300);
    b.restore_block(X_BLOCK, 300);

    // A canonical, B merger — B's manifest becomes the conflict copy.
    let shared = reconcile(&a, Some(&b), X_BLOCK);

    // Drive the actual merge through the production sync pipeline: B
    // (the merger) detects ConcurrentDetected against the shared folder
    // (A's canonical files + B's conflict-copy siblings) and commits.
    let merger_state = convergence_helpers::sync_as_merger(
        &baseline,
        shared.folder(),
        &b,
        convergence_helpers::VetoPolicy::NoVetoExpected,
        1_000,
    );
    // A (the canonical/adopter) then adopts the merged LUB, and both
    // devices must quiesce afterwards — standard convergence-harness
    // proof that the merge is real, not just a one-sided write.
    let adopter_state = convergence_helpers::sync_as_adopter(&baseline, shared.folder(), &a, 1_001);
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &merger_state,
        1_002
    ));
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &adopter_state,
        1_003
    ));

    // Re-open the reconciled vault and assert purge-terminal outcome.
    let merged = Baseline::from_folder(shared.folder(), baseline.password().clone());
    let manifest = merged.open_manifest();
    assert!(
        manifest.blocks.iter().all(|blk| blk.block_uuid != X_BLOCK),
        "purge is terminal: X must not be live in blocks"
    );
    let entry = manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == X_BLOCK)
        .expect("X present as a trash entry");
    assert!(entry.purged_at_ms.is_some(), "X must remain purged");

    // The open above ran the sweep; the restoring device's blocks/X
    // ciphertext must be gone.
    let blocks_x = sync_helpers::block_file_path(shared.folder(), &X_BLOCK);
    assert!(!blocks_x.exists(), "purge sweep removed blocks/ residue");
}
