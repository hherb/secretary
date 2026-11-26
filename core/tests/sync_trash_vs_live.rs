//! #783: a block trashed on one device and still live on another merges to
//! one result whichever manifest is canonical (crypto-design §11.6).
//!
//! Every scenario merges the same pair of devices twice, once with each
//! manifest canonical. The shared folder is the one a sync tool produces:
//! the canonical device's files, the other manifest as a conflict copy, the
//! trashing device's `blocks/ -> trash/` move applied, and a block edited
//! concurrently with that move at its own path (an edit beats a delete).
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use std::collections::BTreeSet;
use std::path::Path;

use convergence_helpers::{apply_trash_move, reconcile, Baseline, Device, VetoPolicy};
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, DraftMerge, SyncError, SyncOutcome, SyncState,
};
use secretary_core::unlock::{open_with_password, UnlockedIdentity};

const A_UUID: [u8; 16] = [0x0A; 16];
const B_UUID: [u8; 16] = [0x0B; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];
const Y_BLOCK: [u8; 16] = [0xCC; 16];
const SEED_RECORD: [u8; 16] = [0xA0; 16];
const A_RECORD: [u8; 16] = [0xA1; 16];
const B_RECORD: [u8; 16] = [0xB1; 16];
const TRASH_MS: u64 = 300;
const MERGE_MS: u64 = 1_000;

/// A baseline holding blocks X and Y, one record each.
fn seeded() -> Baseline {
    let baseline = Baseline::create();
    let mut s = Device::fork(&baseline, A_UUID, 0xA0);
    s.edit_text_field(X_BLOCK, SEED_RECORD, "f", "x", 100);
    s.edit_text_field(Y_BLOCK, SEED_RECORD, "f", "y", 100);
    convergence_helpers::baseline_from_seeded(baseline, &s)
}

/// Put `editor`'s `blocks/X` at its own path in `shared`: an edit made
/// concurrently with the trash survives the trashing device's move.
fn apply_edit(editor: &Device, shared: &Path) {
    std::fs::copy(
        sync_helpers::block_file_path(editor.folder(), &X_BLOCK),
        sync_helpers::block_file_path(shared, &X_BLOCK),
    )
    .expect("copy edited block");
}

/// What the merged vault holds for X: live or not, trashed or not, and the
/// record uuids of its live block.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Outcome {
    live: bool,
    trashed: bool,
    records: BTreeSet<[u8; 16]>,
}

fn outcome(baseline: &Baseline, shared: &Path) -> Outcome {
    let manifest = Baseline::from_folder(shared, baseline.password().clone()).open_manifest();
    let live = manifest.blocks.iter().any(|b| b.block_uuid == X_BLOCK);
    let records = if live {
        convergence_helpers::decrypt_block_records(shared, baseline.password(), X_BLOCK)
            .iter()
            .map(|r| r.record_uuid)
            .collect()
    } else {
        BTreeSet::new()
    };
    Outcome {
        live,
        trashed: manifest.trash.iter().any(|t| t.block_uuid == X_BLOCK),
        records,
    }
}

/// Merge as `merger` over `shared`, then check the other device adopts the
/// result and both quiesce.
fn merge_and_settle(baseline: &Baseline, shared: &Path, merger: &Device, adopter: &Device) {
    let merged = convergence_helpers::sync_as_merger(
        baseline,
        shared,
        merger,
        VetoPolicy::NoVetoExpected,
        MERGE_MS,
    );
    let adopted = convergence_helpers::sync_as_adopter(baseline, shared, adopter, MERGE_MS + 1);
    assert!(convergence_helpers::is_nothing_to_do(
        baseline,
        shared,
        &merged,
        MERGE_MS + 2
    ));
    assert!(convergence_helpers::is_nothing_to_do(
        baseline,
        shared,
        &adopted,
        MERGE_MS + 3
    ));
}

/// A trashes X; B, which never saw the trash, edits Y. B's X is the trashed
/// version itself, or (when A edited X just before trashing it) an older one
/// the trashed version's clock dominates, so the trash wins in both orders.
/// With B canonical this used to fail every commit with `BlockFileMissing`:
/// B's manifest named the file A had moved to `trash/`.
#[test]
fn a_device_that_never_saw_the_trash_does_not_bring_the_block_back() {
    let baseline = seeded();
    let mut outcomes = Vec::new();
    for (trasher_is_canonical, edit_before_trash) in
        [(true, false), (false, false), (true, true), (false, true)]
    {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        if edit_before_trash {
            a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
        }
        a.trash_block(X_BLOCK, TRASH_MS);
        b.edit_text_field(Y_BLOCK, B_RECORD, "f", "b", TRASH_MS);
        let shared = if trasher_is_canonical {
            let shared = reconcile(&a, Some(&b), Y_BLOCK);
            merge_and_settle(&baseline, shared.folder(), &b, &a);
            shared
        } else {
            let shared = reconcile(&b, Some(&a), Y_BLOCK);
            apply_trash_move(&a, shared.folder(), X_BLOCK, false);
            merge_and_settle(&baseline, shared.folder(), &a, &b);
            shared
        };
        outcomes.push(outcome(&baseline, shared.folder()));
    }
    let expected = Outcome {
        live: false,
        trashed: true,
        records: BTreeSet::new(),
    };
    assert_eq!(outcomes, [0, 1, 2, 3].map(|_| expected.clone()));
}

/// A edits X, then trashes it; B edits X concurrently. Live wins in both
/// orders, and the merged block holds both devices' edits: B's live one and
/// A's, which only the trashed version holds. (Each harness edit saves the
/// whole block as one record, so the seed record is in neither.)
#[test]
fn a_concurrent_edit_keeps_the_block_live_with_the_trashed_edits() {
    let baseline = seeded();
    let mut outcomes = Vec::new();
    for trasher_is_canonical in [true, false] {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
        a.trash_block(X_BLOCK, TRASH_MS);
        b.edit_text_field(X_BLOCK, B_RECORD, "f", "b", 200);
        let shared = if trasher_is_canonical {
            let shared = reconcile(&a, Some(&b), Y_BLOCK);
            apply_edit(&b, shared.folder());
            merge_and_settle(&baseline, shared.folder(), &b, &a);
            shared
        } else {
            let shared = reconcile(&b, Some(&a), Y_BLOCK);
            apply_trash_move(&a, shared.folder(), X_BLOCK, true);
            merge_and_settle(&baseline, shared.folder(), &a, &b);
            shared
        };
        outcomes.push(outcome(&baseline, shared.folder()));
    }
    let expected = Outcome {
        live: true,
        trashed: false,
        records: [A_RECORD, B_RECORD].into_iter().collect(),
    };
    assert_eq!(outcomes[0], expected, "trasher canonical");
    assert_eq!(outcomes[1], expected, "editor canonical");
}

/// B saw A's trash and restored X while A edited Y. B's restored X keeps the
/// trashed fingerprint, so to the merge it looks like a device that never
/// saw the trash, and the trash wins in both orders. X can be restored again.
#[test]
fn a_concurrent_restore_leaves_the_block_restorable_in_the_trash() {
    let baseline = seeded();
    let mut trashed = Device::fork(&baseline, A_UUID, 0xA0);
    trashed.trash_block(X_BLOCK, TRASH_MS);
    let baseline = convergence_helpers::baseline_from_seeded(baseline, &trashed);
    let mut outcomes = Vec::new();
    for trasher_is_canonical in [true, false] {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        b.restore_block(X_BLOCK, 400);
        a.edit_text_field(Y_BLOCK, A_RECORD, "f", "a", 400);
        let shared = if trasher_is_canonical {
            let shared = reconcile(&a, Some(&b), Y_BLOCK);
            // B's restore copied the trashed file back to `blocks/`.
            apply_edit(&b, shared.folder());
            merge_and_settle(&baseline, shared.folder(), &b, &a);
            shared
        } else {
            let shared = reconcile(&b, Some(&a), Y_BLOCK);
            merge_and_settle(&baseline, shared.folder(), &a, &b);
            shared
        };
        outcomes.push(outcome(&baseline, shared.folder()));
        // The open in `outcome` swept X back into `trash/`; it restores.
        let merged = Baseline::from_folder(shared.folder(), baseline.password().clone());
        let mut restorer = Device::fork(&merged, B_UUID, 0xB1);
        restorer.restore_block(X_BLOCK, 2_000);
        assert_eq!(restorer.decrypt_block_records(X_BLOCK).len(), 1);
    }
    let expected = Outcome {
        live: false,
        trashed: true,
        records: BTreeSet::new(),
    };
    assert_eq!(outcomes[0], expected, "trasher canonical");
    assert_eq!(outcomes[1], expected, "restorer canonical");
}

/// Run `sync_once` and `prepare_merge` over `shared` as `merger`.
fn prepare_as(
    baseline: &Baseline,
    shared: &Path,
    merger: &Device,
) -> (UnlockedIdentity, Result<DraftMerge, SyncError>) {
    let identity = open_with_password(
        &std::fs::read(shared.join("vault.toml")).expect("vault.toml"),
        &std::fs::read(shared.join("identity.bundle.enc")).expect("bundle"),
        baseline.password(),
    )
    .expect("unlock");
    let vault_uuid = baseline.open_manifest().vault_uuid;
    let state = SyncState::new(vault_uuid, merger.manifest_clock()).expect("state");
    let SyncOutcome::ConcurrentDetected { bundle, plan, .. } =
        sync_once(shared, &identity, &state, MERGE_MS).expect("sync_once")
    else {
        panic!("expected ConcurrentDetected");
    };
    let draft = prepare_merge(shared, &identity, &bundle, &plan, merger.device_uuid());
    (identity, draft)
}

/// A draft that would rewrite a block its own merged trash removes is
/// refused before any file is written.
#[test]
fn a_commit_refuses_to_rewrite_a_block_its_trash_removes() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(X_BLOCK, B_RECORD, "f", "b", 200);
    let shared = reconcile(&b, Some(&a), Y_BLOCK);
    apply_trash_move(&a, shared.folder(), X_BLOCK, true);
    let (identity, draft) = prepare_as(&baseline, shared.folder(), &a);
    let mut draft = draft.expect("prepare_merge");
    assert!(draft.plan.diverging_blocks.contains(&X_BLOCK));
    let entry = Baseline::from_folder(a.folder(), baseline.password().clone())
        .open_manifest()
        .trash
        .into_iter()
        .find(|t| t.block_uuid == X_BLOCK)
        .expect("A's trash entry");
    draft.merged_trash.push(entry);

    let manifest_path = shared.folder().join("manifest.cbor.enc");
    let before = std::fs::read(&manifest_path).expect("manifest");
    let block_before =
        std::fs::read(sync_helpers::block_file_path(shared.folder(), &X_BLOCK)).expect("block");
    assert!(matches!(
        commit_with_decisions(shared.folder(), &identity, draft, Vec::new(), MERGE_MS),
        Err(SyncError::InvalidArgument { .. })
    ));
    assert_eq!(std::fs::read(&manifest_path).expect("manifest"), before);
    assert_eq!(
        std::fs::read(sync_helpers::block_file_path(shared.folder(), &X_BLOCK)).expect("block"),
        block_before
    );
}

/// Deciding a collision whose live version differs from the trashed one
/// needs the trashed file. Until it arrives the merge is refused and nothing
/// is written; once it lands the merge commits.
#[test]
fn the_merge_waits_for_a_trashed_file_it_needs() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(X_BLOCK, B_RECORD, "f", "b", 200);
    let shared = reconcile(&b, Some(&a), Y_BLOCK);

    let before = std::fs::read(shared.folder().join("manifest.cbor.enc")).expect("manifest");
    let (_, draft) = prepare_as(&baseline, shared.folder(), &a);
    assert!(matches!(
        draft,
        Err(SyncError::BlockCopyUnavailable { block_uuid }) if block_uuid == X_BLOCK
    ));
    assert_eq!(
        std::fs::read(shared.folder().join("manifest.cbor.enc")).expect("manifest"),
        before,
        "nothing written while refused"
    );

    apply_trash_move(&a, shared.folder(), X_BLOCK, true);
    merge_and_settle(&baseline, shared.folder(), &a, &b);
    assert_eq!(
        outcome(&baseline, shared.folder()).records,
        [A_RECORD, B_RECORD].into_iter().collect()
    );
}

/// B saw A's trash, restored X and edited it, while A edited Y. The restore
/// kept the trashed file (vault-format §7.1 step 5), so the merge can tell
/// B's edit is newer than the trashed version: X stays live with B's edit in
/// both orders. Before the restore kept the file, both orders refused for
/// good: the edit had overwritten the only copy of the trashed version.
#[test]
fn a_restore_then_edit_keeps_the_block_live_in_both_orders() {
    let baseline = seeded();
    let mut trasher = Device::fork(&baseline, A_UUID, 0xA0);
    trasher.trash_block(X_BLOCK, TRASH_MS);
    let baseline = convergence_helpers::baseline_from_seeded(baseline, &trasher);
    let mut outcomes = Vec::new();
    for trasher_is_canonical in [true, false] {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        b.restore_block(X_BLOCK, 400);
        b.edit_text_field(X_BLOCK, B_RECORD, "f", "b", 500);
        a.edit_text_field(Y_BLOCK, A_RECORD, "f", "a", 400);
        let shared = if trasher_is_canonical {
            let shared = reconcile(&a, Some(&b), Y_BLOCK);
            apply_edit(&b, shared.folder());
            merge_and_settle(&baseline, shared.folder(), &b, &a);
            shared
        } else {
            let shared = reconcile(&b, Some(&a), Y_BLOCK);
            merge_and_settle(&baseline, shared.folder(), &a, &b);
            shared
        };
        outcomes.push(outcome(&baseline, shared.folder()));
    }
    let expected = Outcome {
        live: true,
        trashed: false,
        records: [B_RECORD].into_iter().collect(),
    };
    assert_eq!(outcomes[0], expected, "trasher canonical");
    assert_eq!(outcomes[1], expected, "restorer canonical");
}

/// Sync tools leave old conflict copies in place. After a merge trashed X
/// and the user restored it (synced everywhere), a later concurrent merge
/// still sees A's old manifest with its trash entry for X. That manifest is superseded (the
/// merged manifest dominates it), so its entry is not counted and the
/// restore stands (crypto-design §11.7).
#[test]
fn an_old_conflict_copy_does_not_trash_a_restored_block_again() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(Y_BLOCK, B_RECORD, "f", "b", TRASH_MS);
    let first = reconcile(&a, Some(&b), Y_BLOCK);
    merge_and_settle(&baseline, first.folder(), &b, &a);
    let merged = Baseline::from_folder(first.folder(), baseline.password().clone());
    assert!(
        !outcome(&baseline, first.folder()).live,
        "first merge trashed X"
    );

    // The restore syncs to every device before the next concurrent write.
    let mut r = Device::fork(&merged, A_UUID, 0xA1);
    r.restore_block(X_BLOCK, 2_000);
    let restored = convergence_helpers::baseline_from_seeded(merged, &r);

    for p_is_canonical in [true, false] {
        let mut p = Device::fork(&restored, A_UUID, 0xA2);
        let mut q = Device::fork(&restored, B_UUID, 0xB2);
        p.edit_text_field(Y_BLOCK, A_RECORD, "f", "p", 3_000);
        q.edit_text_field(Y_BLOCK, B_RECORD, "f", "q", 3_000);
        let (canonical, merger) = if p_is_canonical { (&p, &q) } else { (&q, &p) };
        let shared = reconcile(canonical, Some(merger), Y_BLOCK);
        std::fs::copy(
            a.folder().join("manifest.cbor.enc"),
            shared.folder().join("manifest.cbor.enc.sync-conflict-old"),
        )
        .expect("leave A's old manifest in place");
        merge_and_settle(&restored, shared.folder(), merger, canonical);
        let got = outcome(&baseline, shared.folder());
        assert!(
            got.live && !got.trashed,
            "p canonical: {p_is_canonical}: {got:?}"
        );
    }
}

/// The trashed version is found as a conflict-copy sibling of the block, and
/// another authentic version sits at the block's own path. Ingest picks the
/// sibling by fingerprint, and the merge pairs it with its own header clock
/// (no counted manifest lists it), so live wins with both edits.
#[test]
fn a_trashed_version_left_as_a_sibling_is_found_and_folded() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(X_BLOCK, B_RECORD, "f", "b", 200);
    let shared = reconcile(&b, Some(&a), Y_BLOCK);
    let trashed = std::fs::read_dir(a.folder().join("trash"))
        .expect("A's trash")
        .next()
        .expect("one trashed file")
        .expect("entry")
        .path();
    let own = sync_helpers::block_file_path(shared.folder(), &X_BLOCK);
    let sibling = own.with_file_name(format!(
        "{}.sync-conflict-trashed",
        own.file_name().expect("name").to_string_lossy()
    ));
    std::fs::copy(trashed, sibling).expect("place trashed version as a sibling");
    merge_and_settle(&baseline, shared.folder(), &a, &b);
    assert_eq!(
        outcome(&baseline, shared.folder()).records,
        [A_RECORD, B_RECORD].into_iter().collect()
    );
}

/// A block live won for, which the canonical manifest lists, must be merged
/// to fold its trashed version. While its own file has not arrived the merge
/// refuses instead of leaving it out.
#[test]
fn a_live_won_block_whose_own_file_is_unreadable_is_refused() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(X_BLOCK, B_RECORD, "f", "b", 200);
    let shared = reconcile(&b, Some(&a), Y_BLOCK);
    apply_trash_move(&a, shared.folder(), X_BLOCK, true);
    std::fs::remove_file(sync_helpers::block_file_path(shared.folder(), &X_BLOCK))
        .expect("own file not arrived");
    let (_, draft) = prepare_as(&baseline, shared.folder(), &a);
    assert!(matches!(
        draft,
        Err(SyncError::BlockCopyUnavailable { block_uuid }) if block_uuid == X_BLOCK
    ));
}

/// The mirror of the test above: B's old manifest, left in place after a
/// merge trashed X, still lists X live. It is superseded, so it does not
/// bring X back as a block new to the merging device.
#[test]
fn an_old_conflict_copy_does_not_bring_a_trashed_block_back() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(Y_BLOCK, B_RECORD, "f", "b", TRASH_MS);
    let first = reconcile(&a, Some(&b), Y_BLOCK);
    merge_and_settle(&baseline, first.folder(), &b, &a);
    let merged = Baseline::from_folder(first.folder(), baseline.password().clone());

    for p_is_canonical in [true, false] {
        let mut p = Device::fork(&merged, A_UUID, 0xA2);
        let mut q = Device::fork(&merged, B_UUID, 0xB2);
        p.edit_text_field(Y_BLOCK, A_RECORD, "f", "p", 3_000);
        q.edit_text_field(Y_BLOCK, B_RECORD, "f", "q", 3_000);
        let (canonical, merger) = if p_is_canonical { (&p, &q) } else { (&q, &p) };
        let shared = reconcile(canonical, Some(merger), Y_BLOCK);
        std::fs::copy(
            b.folder().join("manifest.cbor.enc"),
            shared.folder().join("manifest.cbor.enc.sync-conflict-old"),
        )
        .expect("leave B's old manifest in place");
        merge_and_settle(&merged, shared.folder(), merger, canonical);
        let got = outcome(&baseline, shared.folder());
        assert!(
            !got.live && got.trashed,
            "p canonical: {p_is_canonical}: {got:?}"
        );
    }
}

/// #790: A trashes X; B, which never saw the trash, writes more than 90 days
/// later. With B canonical, the merge commit's verification sweeps against
/// B's manifest, which names no entry for A's trash file. That file is the
/// trashed block's only copy, and its clock equals B's live X, so it stays.
#[test]
fn the_merge_keeps_a_peers_trash_file_its_stale_manifest_does_not_name() {
    const NINETY_DAYS_MS: u64 = 90 * 24 * 60 * 60 * 1000;
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(Y_BLOCK, B_RECORD, "f", "b", TRASH_MS + NINETY_DAYS_MS + 1);
    let shared = reconcile(&b, Some(&a), Y_BLOCK);
    apply_trash_move(&a, shared.folder(), X_BLOCK, false);
    let trash_files: Vec<_> = std::fs::read_dir(shared.folder().join("trash"))
        .expect("read trash")
        .map(|e| e.expect("trash entry").path())
        .collect();
    assert_eq!(trash_files.len(), 1);

    merge_and_settle(&baseline, shared.folder(), &a, &b);

    assert!(outcome(&baseline, shared.folder()).trashed);
    assert!(
        trash_files[0].exists(),
        "the trashed block stays restorable"
    );
}
