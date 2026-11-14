//! Session sync + refresh (#101, design spec §5.3), on writable fixture copies
//! opened into bridge handles.

use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncState;
use secretary_core::vault::VectorClockEntry;
use tempfile::TempDir;

use secretary_test_utils::copy_dir_to_tempdir;

use super::*;
use crate::test_support::{fixture_folder, open_writable_golden_001, VAULT_001_PASSWORD};
use crate::{open_vault_with_password, save_block, sync_vault_in, BlockInput, OpenVaultOutput};

fn random_16() -> [u8; 16] {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b
}

/// Write one fresh empty block through `out`; returns its uuid.
fn write_block(out: &OpenVaultOutput) -> Result<[u8; 16], FfiVaultError> {
    let block_uuid = random_16();
    let input = BlockInput {
        block_uuid,
        block_name: format!("block-{}", hex::encode(&block_uuid[..4])),
        records: vec![],
    };
    save_block(&out.identity, &out.manifest, input, random_16(), 1_000)?;
    Ok(block_uuid)
}

fn folder_of(tmp: &TempDir) -> PathBuf {
    tmp.path().to_path_buf()
}

fn block_path(folder: &Path, uuid: &[u8; 16]) -> PathBuf {
    folder.join("blocks").join(format!(
        "{}.cbor.enc",
        secretary_core::vault::format_uuid_hyphenated(uuid)
    ))
}

fn has_block(out: &OpenVaultOutput, uuid: &[u8; 16]) -> bool {
    out.manifest
        .block_summaries()
        .iter()
        .any(|b| &b.block_uuid == uuid)
}

/// Session handles plus a second writer that has advanced the disk.
fn session_and_other_writer() -> (TempDir, OpenVaultOutput, [u8; 16]) {
    let (tmp, session) = open_writable_golden_001();
    let other = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).expect("second open");
    let other_block = write_block(&other).expect("other writer saves a block");
    (tmp, session, other_block)
}

/// Seed `state_dir` with a clock that strictly dominates the disk manifest.
fn seed_dominating_state(state_dir: &Path, folder: &Path) {
    let disk = open_vault_with_password(folder, VAULT_001_PASSWORD).expect("open disk state");
    let body = disk.manifest.manifest_body().expect("live handle");
    let mut clock = body.vector_clock.clone();
    clock[0].counter += 1;
    let state = SyncState::new(body.vault_uuid, clock).expect("canonical clock");
    secretary_cli::state::save(state_dir, &state).expect("seed state");
}

/// Seed `state_dir` with a clock concurrent with any disk clock: one entry
/// for a device the disk has never seen, and none of the disk's entries.
fn seed_concurrent_state(state_dir: &Path, session: &OpenVaultOutput) {
    let vault_uuid: [u8; 16] = session.manifest.vault_uuid().try_into().unwrap();
    let clock = vec![VectorClockEntry {
        device_uuid: random_16(),
        counter: 2,
    }];
    let state = SyncState::new(vault_uuid, clock).expect("canonical clock");
    secretary_cli::state::save(state_dir, &state).expect("seed state");
}

#[test]
fn session_sync_silent_merge_refreshes_and_write_succeeds() {
    let (_tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_concurrent_state(state_dir.path(), &session);

    let outcome = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        2_000,
    )
    .expect("a silent merge refreshes");
    assert_eq!(outcome, SyncOutcomeDto::SilentMerge);
    assert!(has_block(&session, &other_block), "handle refreshed");
    write_block(&session).expect("write after silent merge");
}

const REFRESHING: [SyncOutcomeDto; 4] = [
    SyncOutcomeDto::AppliedAutomatically,
    SyncOutcomeDto::SilentMerge,
    SyncOutcomeDto::MergedClean,
    SyncOutcomeDto::NothingToDo,
];

#[test]
fn session_sync_then_write_succeeds() {
    let (_tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();

    let outcome = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        2_000,
    )
    .expect("session sync");
    // A fresh state dir is the lattice bottom, so the pass fast-forwards.
    assert_eq!(outcome, SyncOutcomeDto::AppliedAutomatically);

    write_block(&session).expect("write after session sync");
    assert!(
        has_block(&session, &other_block),
        "handle must see the other writer's block"
    );
}

#[test]
fn password_sync_then_refresh_then_write_succeeds() {
    let (tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();

    let outcome = sync_vault_in(
        state_dir.path(),
        &folder_of(&tmp),
        SecretBytes::new(VAULT_001_PASSWORD.to_vec()),
        2_000,
    )
    .expect("password sync");
    assert_eq!(outcome, SyncOutcomeDto::AppliedAutomatically);

    // Without the refresh, the stale handle's write is refused.
    let err = write_block(&session).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::VaultChangedOnDisk),
        "got {err:?}"
    );

    refresh_manifest_in(state_dir.path(), &session.identity, &session.manifest).expect("refresh");
    write_block(&session).expect("write after refresh");
    assert!(has_block(&session, &other_block));
}

#[test]
fn refresh_refuses_rollback_and_keeps_handle() {
    let (tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_dominating_state(state_dir.path(), &folder_of(&tmp));
    let before = session.manifest.block_summaries();

    let err =
        refresh_manifest_in(state_dir.path(), &session.identity, &session.manifest).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "got {err:?}"
    );
    assert_eq!(session.manifest.block_summaries(), before);
    assert!(!has_block(&session, &other_block));

    // Control: the same refresh of the same handle without the seeded
    // dominating clock succeeds, so the refusal above is the rollback check.
    let no_state = TempDir::new().unwrap();
    refresh_manifest_in(no_state.path(), &session.identity, &session.manifest)
        .expect("refresh without a dominating baseline");
    assert!(has_block(&session, &other_block));
}

/// An unreadable sync state fails the refresh closed (#384's posture): a
/// skipped §10 check here would let the next write re-sign a rolled-back
/// manifest.
#[test]
fn refresh_refuses_an_unreadable_state_file_and_keeps_handle() {
    let (_tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    let vault_uuid: [u8; 16] = session.manifest.vault_uuid().try_into().unwrap();
    let path = secretary_cli::state::state_file_path(state_dir.path(), vault_uuid);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut garbage = vec![0u8; 64];
    OsRng.fill_bytes(&mut garbage);
    std::fs::write(&path, &garbage).unwrap();
    let before = session.manifest.block_summaries();

    let err =
        refresh_manifest_in(state_dir.path(), &session.identity, &session.manifest).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "got {err:?}"
    );
    assert_eq!(session.manifest.block_summaries(), before);
    assert!(!has_block(&session, &other_block));
}

#[test]
fn rollback_rejected_does_not_refresh_and_writes_stay_refused() {
    let (tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_dominating_state(state_dir.path(), &folder_of(&tmp));
    let before = session.manifest.manifest_body();

    let outcome = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        2_000,
    )
    .expect("pass reports rollback as an outcome");
    assert_eq!(outcome, SyncOutcomeDto::RollbackRejected);
    assert_eq!(session.manifest.manifest_body(), before);
    assert!(!has_block(&session, &other_block));

    let err = write_block(&session).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::VaultChangedOnDisk),
        "got {err:?}"
    );
}

#[test]
fn session_sync_refresh_failure_leaves_handle_and_retry_succeeds() {
    let (tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    let path = block_path(&folder_of(&tmp), &other_block);
    let bytes = std::fs::read(&path).expect("other writer's block file");
    std::fs::remove_file(&path).unwrap();
    let count_before = session.manifest.block_count();

    // The pass itself does not read block files; the refresh's fingerprint
    // check does, and refuses.
    let err = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        2_000,
    )
    .expect_err("refresh must fail on a missing block file");
    // Core `BlockFileMissing` folds to `CorruptVault`; its detail names it.
    let FfiVaultError::CorruptVault { detail } = &err else {
        panic!("expected the refresh's missing-block error, got {err:?}");
    };
    assert!(
        detail.as_str().contains("file missing from blocks/"),
        "got {detail:?}"
    );
    // ...after the pass itself succeeded and persisted its state.
    let vault_uuid: [u8; 16] = session.manifest.vault_uuid().try_into().unwrap();
    let status = crate::sync_status_in(state_dir.path(), vault_uuid).expect("status");
    assert!(status.has_state, "the pass persisted before the refresh");
    assert_eq!(session.manifest.block_count(), count_before);
    assert!(!has_block(&session, &other_block));

    std::fs::write(&path, bytes).unwrap();
    let outcome = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        3_000,
    )
    .expect("retry succeeds once the block file is back");
    assert!(REFRESHING.contains(&outcome), "got {outcome:?}");
    assert!(has_block(&session, &other_block));
    write_block(&session).expect("write after retry");
}

/// Collision fixture (a pass there would merge and write) opened into bridge
/// handles: (vault tmp, state tmp, handles).
fn open_fixture(name: &str) -> (TempDir, TempDir, OpenVaultOutput) {
    let src = fixture_folder(name);
    let vault_tmp = copy_dir_to_tempdir(&src.join("vault"));
    let state_tmp = copy_dir_to_tempdir(&src.join("state"));
    let out = open_vault_with_password(vault_tmp.path(), VAULT_001_PASSWORD).expect("open fixture");
    (vault_tmp, state_tmp, out)
}

/// Every file under `dir`, path-sorted, with its bytes.
fn snapshot_tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn session_sync_on_wiped_identity_writes_nothing() {
    let (vault_tmp, state_tmp, out) = open_fixture("sync_collision_fixture");
    let vault_before = snapshot_tree(vault_tmp.path());
    let state_before = snapshot_tree(state_tmp.path());

    out.identity.wipe();
    let err =
        sync_vault_with_session_in(state_tmp.path(), &out.identity, &out.manifest, 1).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "got {err:?}"
    );
    let err = refresh_manifest_in(state_tmp.path(), &out.identity, &out.manifest).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "got {err:?}"
    );
    assert_eq!(snapshot_tree(vault_tmp.path()), vault_before);
    assert_eq!(snapshot_tree(state_tmp.path()), state_before);
}

#[test]
fn session_sync_on_wiped_manifest_writes_nothing() {
    let (vault_tmp, state_tmp, out) = open_fixture("sync_collision_fixture");
    let vault_before = snapshot_tree(vault_tmp.path());
    let state_before = snapshot_tree(state_tmp.path());

    out.manifest.wipe();
    let err =
        sync_vault_with_session_in(state_tmp.path(), &out.identity, &out.manifest, 1).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "got {err:?}"
    );
    assert_eq!(snapshot_tree(vault_tmp.path()), vault_before);
    assert_eq!(snapshot_tree(state_tmp.path()), state_before);
}

#[test]
fn conflicts_pending_does_not_refresh() {
    let (vault_tmp, state_tmp, out) = open_fixture("sync_conflict_fixture");
    // A second writer moves the canonical manifest after the session opened,
    // so a wrongful refresh at the pause would show its block.
    let other = open_vault_with_password(vault_tmp.path(), VAULT_001_PASSWORD).expect("open");
    let other_block = write_block(&other).expect("other writer saves a block");
    let before = out.manifest.manifest_body();

    let outcome = sync_vault_with_session_in(state_tmp.path(), &out.identity, &out.manifest, 1)
        .expect("inspect pass");
    let SyncOutcomeDto::ConflictsPending {
        vetoes,
        manifest_hash,
        ..
    } = outcome
    else {
        panic!("expected ConflictsPending, got {outcome:?}");
    };
    assert!(!vetoes.is_empty());
    assert_eq!(out.manifest.manifest_body(), before, "no refresh on pause");
    assert!(!has_block(&out, &other_block));

    let decisions = vetoes
        .iter()
        .map(|v| VetoDecisionDto {
            record_uuid_hex: v.record_uuid_hex.clone(),
            keep_local: true,
        })
        .collect();
    let outcome = sync_commit_decisions_with_session_in(
        state_tmp.path(),
        &out.identity,
        &out.manifest,
        decisions,
        manifest_hash,
        2,
    )
    .expect("commit");
    assert_eq!(outcome, SyncOutcomeDto::MergedClean);
    assert!(has_block(&out, &other_block), "commit refreshes");
    write_block(&out).expect("write after commit");
}

/// The session refresh after an `AppliedAutomatically` pass checks the disk
/// against the pass's POST-pass clock (§10). Here the disk is rolled back to
/// the session's own older, owner-signed manifest between the pass and the
/// refresh. Refreshing with no baseline, or with the (empty) pre-pass clock,
/// would adopt that older manifest; the post-pass clock refuses it.
#[test]
fn session_refresh_checks_the_disk_against_the_post_pass_clock() {
    let (tmp, session) = open_writable_golden_001();
    let manifest_path = folder_of(&tmp).join("manifest.cbor.enc");
    let older = std::fs::read(&manifest_path).expect("session's manifest envelope");
    let other = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).expect("second open");
    let other_block = write_block(&other).expect("other writer saves a block");
    let state_dir = TempDir::new().unwrap();
    let before = session.manifest.manifest_body();

    let err = run_session_pass(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        |folder, id, state| {
            let outcome = sync_pass_inspect(folder, id, state, 2_000)?;
            assert!(
                matches!(outcome, InspectOutcome::AppliedAutomatically),
                "fresh state fast-forwards"
            );
            std::fs::write(folder.join("manifest.cbor.enc"), &older).expect("roll back");
            Ok(outcome)
        },
        inspect_advanced,
        inspect_baseline,
    )
    .expect_err("a rolled-back disk must not be adopted");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "got {err:?}"
    );
    assert_eq!(session.manifest.manifest_body(), before, "handle unchanged");
    assert!(!has_block(&session, &other_block));
}

/// `refresh_manifest_in` (the desktop and Android path after a password sync)
/// runs open's block-fingerprint check, not just the manifest verify: a
/// tampered block file fails the refresh and leaves the handle, so writes stay
/// refused. Control: with the block restored the same refresh succeeds.
#[test]
fn refresh_refuses_a_tampered_block_and_keeps_handle() {
    let (tmp, session, other_block) = session_and_other_writer();
    let path = block_path(&folder_of(&tmp), &other_block);
    let good = std::fs::read(&path).expect("other writer's block file");
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    std::fs::write(&path, &bad).unwrap();
    let state_dir = TempDir::new().unwrap();
    let before = session.manifest.manifest_body();

    refresh_manifest_in(state_dir.path(), &session.identity, &session.manifest)
        .expect_err("a tampered block must fail the refresh");
    assert_eq!(session.manifest.manifest_body(), before, "handle unchanged");
    let err = write_block(&session).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::VaultChangedOnDisk),
        "got {err:?}"
    );

    std::fs::write(&path, &good).unwrap();
    refresh_manifest_in(state_dir.path(), &session.identity, &session.manifest)
        .expect("refresh succeeds once the block is intact");
    assert!(has_block(&session, &other_block));
}
