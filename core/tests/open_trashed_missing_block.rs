//! #788: a vault whose canonical manifest lists a block that a concurrent
//! trash moved away still opens (vault-format §4.3, "Block files at open").
//!
//! The folder is the one a sync tool leaves: B's manifest canonical (B never
//! saw A's trash of X), A's manifest as a conflict copy, A's
//! `blocks/X -> trash/` move applied. Open used to fail with
//! `BlockFileMissing` here, and every app opens before it syncs, so no app
//! could recover. Open now excuses a missing file only when an authenticated
//! conflict copy has a trash entry for that block, and the next sync's merge
//! trashes it.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use convergence_helpers::{apply_trash_move, prepare_as, reconcile, Baseline, Device, VetoPolicy};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use secretary_core::sync::{commit_with_decisions, SyncError};
use secretary_core::vault::{open_vault, restore_block, trash_block, Unlocker, VaultError};

const A_UUID: [u8; 16] = [0x0A; 16];
const B_UUID: [u8; 16] = [0x0B; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];
const Y_BLOCK: [u8; 16] = [0xCC; 16];
const SEED_RECORD: [u8; 16] = [0xA0; 16];
const A_RECORD: [u8; 16] = [0xA1; 16];
const B_RECORD: [u8; 16] = [0xB1; 16];
const TRASH_MS: u64 = 300;
const MERGE_MS: u64 = 1_000;
const RESTORE_MS: u64 = 2_000;
/// The conflict-copy name `reconcile` gives device A's manifest.
const A_MANIFEST_COPY: &str = "manifest.cbor.enc.sync-conflict-from-device-0a";

/// A baseline holding blocks X and Y, one record each.
fn seeded() -> Baseline {
    let baseline = Baseline::create();
    let mut s = Device::fork(&baseline, A_UUID, 0xA0);
    s.edit_text_field(X_BLOCK, SEED_RECORD, "f", "x", 100);
    s.edit_text_field(Y_BLOCK, SEED_RECORD, "f", "y", 100);
    convergence_helpers::baseline_from_seeded(baseline, &s)
}

/// The #788 folder: A trashes X (optionally editing it first), B edits Y
/// without seeing the trash, B's manifest is canonical, A's move is applied.
fn trashed_while_b_wrote(
    baseline: &Baseline,
    edit_before_trash: bool,
) -> (Device, Device, convergence_helpers::SharedFolder) {
    let mut a = Device::fork(baseline, A_UUID, 0xA0);
    let mut b = Device::fork(baseline, B_UUID, 0xB0);
    if edit_before_trash {
        a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
    }
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(Y_BLOCK, B_RECORD, "f", "b", TRASH_MS);
    let shared = reconcile(&b, Some(&a), Y_BLOCK);
    apply_trash_move(&a, shared.folder(), X_BLOCK, false);
    (a, b, shared)
}

fn open(
    baseline: &Baseline,
    folder: &std::path::Path,
) -> Result<secretary_core::vault::OpenVault, VaultError> {
    open_vault(folder, Unlocker::Password(baseline.password()), None)
}

/// Both the plain trash and edit-then-trash (where B lists an older
/// fingerprint than A's trash entry) open. The session keeps X listed, as
/// the canonical manifest says, and the next sync trashes it.
#[test]
fn a_block_a_conflict_copy_trashed_does_not_stop_the_open() {
    let baseline = seeded();
    for edit_before_trash in [false, true] {
        let (a, b, shared) = trashed_while_b_wrote(&baseline, edit_before_trash);
        let opened = open(&baseline, shared.folder()).expect("open before the merge");
        assert!(
            opened
                .manifest
                .blocks
                .iter()
                .any(|e| e.block_uuid == X_BLOCK),
            "open keeps the canonical manifest's listing"
        );
        drop(opened);

        convergence_helpers::sync_as_merger(
            &baseline,
            shared.folder(),
            &a,
            VetoPolicy::NoVetoExpected,
            MERGE_MS,
        );
        convergence_helpers::sync_as_adopter(&baseline, shared.folder(), &b, MERGE_MS + 1);
        let merged = open(&baseline, shared.folder())
            .expect("open after the merge")
            .manifest;
        assert!(!merged.blocks.iter().any(|e| e.block_uuid == X_BLOCK));
        assert!(merged.trash.iter().any(|t| t.block_uuid == X_BLOCK));
    }
}

/// A missing file that no conflict copy trashed is still refused.
#[test]
fn a_missing_block_no_copy_trashed_is_still_refused() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(Y_BLOCK, A_RECORD, "f", "a", TRASH_MS);
    b.edit_text_field(Y_BLOCK, B_RECORD, "f", "b", TRASH_MS);
    for copy in [None, Some(&a)] {
        let shared = reconcile(&b, copy, Y_BLOCK);
        std::fs::remove_file(sync_helpers::block_file_path(shared.folder(), &X_BLOCK))
            .expect("rm X");
        match open(&baseline, shared.folder()) {
            Err(VaultError::BlockFileMissing { block_uuid }) => assert_eq!(block_uuid, X_BLOCK),
            other => panic!("expected BlockFileMissing, got {:?}", other.err()),
        }
    }
}

/// A conflict copy that does not authenticate is not credited with its
/// trash entry: flipping one byte of A's copy makes the open refuse again.
#[test]
fn a_tampered_conflict_copy_does_not_excuse_a_missing_block() {
    let baseline = seeded();
    let (_a, _b, shared) = trashed_while_b_wrote(&baseline, false);
    let copy = shared.folder().join(A_MANIFEST_COPY);
    let mut bytes = std::fs::read(&copy).expect("read copy");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&copy, bytes).expect("write tampered copy");
    match open(&baseline, shared.folder()) {
        Err(VaultError::BlockFileMissing { block_uuid }) => assert_eq!(block_uuid, X_BLOCK),
        other => panic!("expected BlockFileMissing, got {:?}", other.err()),
    }
}

/// Only the absence of the trashed block itself is excused: wrong bytes at
/// X, a non-NotFound read failure at X, and a missing Y (checked after X)
/// are each refused as before.
#[test]
fn the_excuse_covers_only_the_trashed_blocks_absence() {
    let baseline = seeded();

    let (_a, _b, shared) = trashed_while_b_wrote(&baseline, false);
    let x = sync_helpers::block_file_path(shared.folder(), &X_BLOCK);
    std::fs::write(&x, b"not the block").expect("plant garbage at X");
    match open(&baseline, shared.folder()) {
        Err(VaultError::BlockFingerprintMismatch { block_uuid, .. }) => {
            assert_eq!(block_uuid, X_BLOCK)
        }
        other => panic!("expected BlockFingerprintMismatch, got {:?}", other.err()),
    }

    let (_a, _b, shared) = trashed_while_b_wrote(&baseline, false);
    let x = sync_helpers::block_file_path(shared.folder(), &X_BLOCK);
    std::fs::create_dir(&x).expect("a directory where X's file belongs");
    match open(&baseline, shared.folder()) {
        Err(VaultError::Io { .. }) => {}
        other => panic!("expected Io, got {:?}", other.err()),
    }

    let (_a, _b, shared) = trashed_while_b_wrote(&baseline, false);
    std::fs::remove_file(sync_helpers::block_file_path(shared.folder(), &Y_BLOCK)).expect("rm Y");
    match open(&baseline, shared.folder()) {
        Err(VaultError::BlockFileMissing { block_uuid }) => assert_eq!(block_uuid, Y_BLOCK),
        other => panic!("expected BlockFileMissing, got {:?}", other.err()),
    }
}

/// Trashing the excused block in the opened session is refused, and nothing
/// is written: a newer trash entry naming no file in `trash/` would win the
/// merge and strand A's restorable copy.
#[test]
fn a_session_cannot_trash_an_excused_block() {
    let baseline = seeded();
    let (_a, _b, shared) = trashed_while_b_wrote(&baseline, false);
    let manifest_path = shared.folder().join("manifest.cbor.enc");
    let before = std::fs::read(&manifest_path).expect("manifest");
    let mut opened = open(&baseline, shared.folder()).expect("open");
    let mut rng = ChaCha20Rng::from_seed([0xB1; 32]);
    match trash_block(
        shared.folder(),
        &mut opened,
        X_BLOCK,
        B_UUID,
        MERGE_MS,
        &mut rng,
    ) {
        Err(VaultError::BlockFileMissing { block_uuid }) => assert_eq!(block_uuid, X_BLOCK),
        other => panic!("expected BlockFileMissing, got {other:?}"),
    }
    assert_eq!(std::fs::read(&manifest_path).expect("manifest"), before);
}

/// crypto-design §11.7: A's conflict copy stays in the folder after the
/// merge. Once X is restored the canonical manifest supersedes that copy, so
/// its old trash entry no longer excuses X's file going missing.
#[test]
fn a_superseded_copy_does_not_excuse_a_missing_block() {
    let baseline = seeded();
    let (a, b, shared) = trashed_while_b_wrote(&baseline, false);
    convergence_helpers::sync_as_merger(
        &baseline,
        shared.folder(),
        &a,
        VetoPolicy::NoVetoExpected,
        MERGE_MS,
    );
    convergence_helpers::sync_as_adopter(&baseline, shared.folder(), &b, MERGE_MS + 1);
    assert!(
        shared.folder().join(A_MANIFEST_COPY).exists(),
        "A's copy lingers"
    );

    let mut opened = open(&baseline, shared.folder()).expect("open after the merge");
    let mut rng = ChaCha20Rng::from_seed([0xB2; 32]);
    restore_block(
        shared.folder(),
        &mut opened,
        X_BLOCK,
        B_UUID,
        RESTORE_MS,
        &mut rng,
    )
    .expect("restore X");
    drop(opened);

    std::fs::remove_file(sync_helpers::block_file_path(shared.folder(), &X_BLOCK))
        .expect("rm restored X");
    match open(&baseline, shared.folder()) {
        Err(VaultError::BlockFileMissing { block_uuid }) => assert_eq!(block_uuid, X_BLOCK),
        other => panic!("expected BlockFileMissing, got {:?}", other.err()),
    }
}

/// #788: the merge commit excuses no missing file beyond its own merged
/// trash. X's live version won and `prepare_merge` read its file; if that
/// file then vanishes, the commit is refused rather than signing a manifest
/// listing X with no file, though A's concurrent copy still trashes X.
#[test]
fn a_commit_refuses_a_live_block_whose_file_vanished_after_prepare() {
    let baseline = seeded();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, A_RECORD, "f", "a", 200);
    a.trash_block(X_BLOCK, TRASH_MS);
    b.edit_text_field(X_BLOCK, B_RECORD, "f", "b", 200);
    let shared = reconcile(&b, Some(&a), Y_BLOCK);
    apply_trash_move(&a, shared.folder(), X_BLOCK, true);
    let (identity, draft) = prepare_as(&baseline, shared.folder(), &a, MERGE_MS);
    let draft = draft.expect("prepare_merge");
    assert!(!draft.merged_trash.iter().any(|t| t.block_uuid == X_BLOCK));

    std::fs::remove_file(sync_helpers::block_file_path(shared.folder(), &X_BLOCK))
        .expect("X's file vanishes");
    let before = std::fs::read(shared.folder().join("manifest.cbor.enc")).expect("manifest");
    assert!(matches!(
        commit_with_decisions(shared.folder(), &identity, draft, Vec::new(), MERGE_MS),
        Err(SyncError::Vault(VaultError::BlockFileMissing { block_uuid })) if block_uuid == X_BLOCK
    ));
    assert_eq!(
        std::fs::read(shared.folder().join("manifest.cbor.enc")).expect("manifest"),
        before
    );
}
