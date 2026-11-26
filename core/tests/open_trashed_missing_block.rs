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

use convergence_helpers::{apply_trash_move, reconcile, Baseline, Device, VetoPolicy};
use secretary_core::vault::{open_vault, Unlocker, VaultError};

const A_UUID: [u8; 16] = [0x0A; 16];
const B_UUID: [u8; 16] = [0x0B; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];
const Y_BLOCK: [u8; 16] = [0xCC; 16];
const SEED_RECORD: [u8; 16] = [0xA0; 16];
const A_RECORD: [u8; 16] = [0xA1; 16];
const B_RECORD: [u8; 16] = [0xB1; 16];
const TRASH_MS: u64 = 300;
const MERGE_MS: u64 = 1_000;
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
