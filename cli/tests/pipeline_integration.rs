//! End-to-end tests for [`secretary_cli::pipeline::run_one`] against a
//! real `golden_vault_001`-backed on-disk vault.
//!
//! The cli unit tests in `src/pipeline.rs` cover [`RunOutcome`] shape
//! and equality; these integration tests exercise the actual
//! orchestration through the underlying `secretary_core` primitives
//! (`sync_once → prepare_merge → commit_with_decisions`).
//!
//! ## Why these tests live here, not in `core/`
//!
//! `run_one` is the seam consumed by both `once` (Task 9) and `run`
//! (Task 7) subcommands. The bottom half — the dispatch logic — is
//! cli-owned (it folds `SyncOutcome` into `RunOutcome` and threads the
//! `VetoUx` trait through). Putting orchestration tests here keeps the
//! contract close to its only caller; `core/tests/sync.rs` already
//! covers the lower-level `sync_once` dispatch on its own.
//!
//! ## Fixture access
//!
//! `cli/tests/` reaches the golden vault through the workspace-relative
//! path `../core/tests/data/golden_vault_001/`. The
//! `core/tests/fixtures/mod.rs` helpers are not cross-crate (per-test-
//! binary modules), so this file mirrors the minimum we need: read the
//! password out of `golden_vault_001_inputs.json`, then call
//! [`open_with_password`] on the on-disk vault.toml + bundle bytes.

use std::fs;
use std::path::PathBuf;

use secretary_cli::pipeline::{run_one, RunOutcome};
use secretary_cli::veto::noninteractive::AutoKeepLocalVetoUx;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::sync::SyncState;
use secretary_core::unlock::{open_with_password, vault_toml, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{open_vault, Unlocker};
use secretary_test_utils::{copy_dir_recursive, core_test_data_dir};

/// The merging device every `run_one` call here passes (#744).
const TEST_MERGING_DEVICE: [u8; 16] = [0x5E; 16];

/// Filename of the golden vault folder under `core/tests/data/`.
const GOLDEN_VAULT_DIRNAME: &str = "golden_vault_001";

/// Filenames inside the vault folder.
const VAULT_TOML_FILENAME: &str = "vault.toml";
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";

/// The golden-vault master password as `SecretBytes`, sourced from
/// `golden_vault_001_inputs.json` via the one canonical, fixture-derived
/// password helper ([`secretary_test_utils::golden_vault_001_password`],
/// #450) — so it cannot drift from the fixture it unlocks.
fn golden_vault_password() -> SecretBytes {
    SecretBytes::new(secretary_test_utils::golden_vault_001_password())
}

/// Stage a fresh writable copy of `golden_vault_001/` into a tempdir
/// and unlock it. Returns the tempdir (keep alive for the test's
/// lifetime), the vault folder path inside it, the unlocked identity,
/// and the vault's UUID (so the test can build a matching
/// [`SyncState`]).
fn stage_and_unlock_golden() -> (tempfile::TempDir, PathBuf, UnlockedIdentity, [u8; 16]) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join(GOLDEN_VAULT_DIRNAME);
    let golden_src = core_test_data_dir().join(GOLDEN_VAULT_DIRNAME);
    copy_dir_recursive(&golden_src, &vault_dir);

    let vault_toml_bytes = fs::read(vault_dir.join(VAULT_TOML_FILENAME)).expect("read vault.toml");
    let identity_bundle_bytes =
        fs::read(vault_dir.join(IDENTITY_BUNDLE_FILENAME)).expect("read identity.bundle.enc");

    let password = golden_vault_password();
    let identity = open_with_password(&vault_toml_bytes, &identity_bundle_bytes, &password)
        .expect("open_with_password on golden vault must succeed");

    // Recover the vault_uuid via the vault.toml — `UnlockedIdentity`
    // doesn't surface it directly (it carries the IBK + identity
    // bundle, both of which are the secret material), so we re-parse
    // the same vault.toml the unlock path already authenticated.
    let vt_str = std::str::from_utf8(&vault_toml_bytes).expect("vault.toml utf-8");
    let vt = vault_toml::decode(vt_str).expect("decode vault.toml");
    (tmp, vault_dir, identity, vt.vault_uuid)
}

/// `now_ms = 0` is the C.1-era convention for callers that don't need
/// a real wall clock (`sync_once` ignores it; `commit_with_decisions`
/// writes it into tombstone resurrection metadata but no path here
/// touches a tombstone).
const TEST_NOW_MS: u64 = 0;

/// Fresh state vs the populated golden vault → `AppliedAutomatically`,
/// and the state advances to the disk clock.
///
/// This is the canonical first-sync happy path: on a new device, the
/// caller hands [`run_one`] an empty [`SyncState`] (lattice bottom),
/// and the disk-side clock dominates trivially. Output: state's clock
/// becomes the disk clock so the next call returns `NothingToDo`.
#[test]
fn run_one_returns_applied_automatically_on_fresh_state() {
    let (_tmp, vault_dir, identity, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;

    let pre_clock = state.highest_vector_clock_seen.clone();
    let outcome = run_one(
        &vault_dir,
        &identity,
        &mut state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("run_one must succeed on golden vault");

    assert_eq!(outcome, RunOutcome::AppliedAutomatically);
    assert_ne!(
        state.highest_vector_clock_seen, pre_clock,
        "state.highest_vector_clock_seen must advance past the initial empty clock"
    );
    assert!(
        !state.highest_vector_clock_seen.is_empty(),
        "golden vault's disk clock is non-empty, so the advanced state's clock must be non-empty too"
    );
}

/// Second invocation with the state from the first → `NothingToDo`,
/// and the state is unchanged.
///
/// Pins the idempotence side of the contract: once the local clock
/// matches disk, a re-sync is a no-op with zero state mutation.
#[test]
fn run_one_returns_nothing_to_do_on_second_call() {
    let (_tmp, vault_dir, identity, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;

    let first = run_one(
        &vault_dir,
        &identity,
        &mut state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("first run_one must succeed");
    assert_eq!(first, RunOutcome::AppliedAutomatically);

    let clock_after_first = state.highest_vector_clock_seen.clone();
    let second = run_one(
        &vault_dir,
        &identity,
        &mut state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("second run_one must succeed");
    assert_eq!(second, RunOutcome::NothingToDo);
    assert_eq!(
        state.highest_vector_clock_seen, clock_after_first,
        "NothingToDo must not mutate state"
    );
}

/// State whose clock strictly dominates the disk's → `RollbackRejected`,
/// and the state is NOT advanced.
///
/// Pins the §10 reject path: a local clock that already saw a
/// strictly-later value rejects the older disk clock instead of
/// silently regressing. The caller's `state` survives byte-for-byte so
/// no persistence step accidentally records the older disk view.
#[test]
fn run_one_returns_rollback_rejected_when_state_dominates() {
    let (_tmp, vault_dir, identity, vault_uuid) = stage_and_unlock_golden();

    // First, advance state to disk's clock so we know what's there.
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;
    let first = run_one(
        &vault_dir,
        &identity,
        &mut state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("first run_one must succeed");
    assert_eq!(first, RunOutcome::AppliedAutomatically);

    // Inject a synthetic entry with a higher counter on a DIFFERENT
    // device_uuid than any disk entry, plus bump the counter on every
    // existing entry. The resulting clock strictly dominates disk's.
    let mut dominating_clock: Vec<VectorClockEntry> = state
        .highest_vector_clock_seen
        .iter()
        .map(|e| VectorClockEntry {
            device_uuid: e.device_uuid,
            counter: e.counter + 1,
        })
        .collect();
    // Insert a synthetic device whose UUID is guaranteed to be unique
    // (0xFF...FF — not a value any real generator would produce). Push
    // it to the back; SyncState::new will validate sort order.
    dominating_clock.push(VectorClockEntry {
        device_uuid: [0xFF; 16],
        counter: 999,
    });
    // Re-sort by device_uuid to satisfy the SyncState invariant.
    dominating_clock.sort_by_key(|e| e.device_uuid);
    let mut dominating_state = SyncState::new(vault_uuid, dominating_clock.clone())
        .expect("dominating clock must satisfy sorted+unique invariant");

    let outcome = run_one(
        &vault_dir,
        &identity,
        &mut dominating_state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("run_one must succeed (rollback returns Ok, not Err)");
    assert!(matches!(outcome, RunOutcome::RollbackRejected(_)));
    assert_eq!(
        dominating_state.highest_vector_clock_seen, dominating_clock,
        "RollbackRejected must NOT mutate state — the local clock stays dominating"
    );
}

/// `AutoKeepLocalVetoUx` is consumed through the `&mut dyn VetoUx`
/// boundary without panicking, even on a happy path where the trait
/// method never fires (the golden vault is non-concurrent, so the veto
/// UX is never invoked). This pins the trait-object boundary for the
/// non-interactive impl as part of the public API contract.
#[test]
fn run_one_threads_autokeeplocal_through_dyn_boundary() {
    let (_tmp, vault_dir, identity, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;
    let ux_ref: &mut dyn secretary_cli::veto::VetoUx = &mut ux;
    let outcome = run_one(
        &vault_dir,
        &identity,
        &mut state,
        ux_ref,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("run_one with dyn-trait UX must succeed");
    assert_eq!(outcome, RunOutcome::AppliedAutomatically);
}

/// #730 on the daemon's path: a concurrent state with no diverging block is a
/// `SilentMerge`, and it WRITES the merge. The disk clock then carries the
/// local entry the disk had never seen and equals the saved clock, so the next
/// pass is `NothingToDo`, not a rollback. Before the fix `run_one` advanced the
/// state without writing, and the repeat pass returned `RollbackRejected`.
#[test]
fn run_one_silent_merge_writes_the_merge_and_the_next_pass_is_nothing_to_do() {
    let (_tmp, vault_dir, identity, vault_uuid) = stage_and_unlock_golden();
    let local = VectorClockEntry {
        device_uuid: [0xEE; 16],
        counter: 2,
    };
    let mut state = SyncState::new(vault_uuid, vec![local.clone()]).expect("canonical clock");
    let mut ux = AutoKeepLocalVetoUx;

    let first = run_one(
        &vault_dir,
        &identity,
        &mut state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("first run_one must succeed");
    assert_eq!(first, RunOutcome::SilentMerge);

    let password = golden_vault_password();
    let opened = open_vault(&vault_dir, Unlocker::Password(&password), None).expect("open");
    let disk = &opened.manifest.vector_clock;
    assert!(
        disk.contains(&local),
        "disk clock {disk:?} lacks the local entry"
    );
    assert!(
        disk.contains(&VectorClockEntry {
            device_uuid: TEST_MERGING_DEVICE,
            counter: 1,
        }),
        "disk clock {disk:?} lacks the merging device's tick (#744)"
    );
    assert_eq!(
        &state.highest_vector_clock_seen, disk,
        "saved clock == disk clock"
    );

    let second = run_one(
        &vault_dir,
        &identity,
        &mut state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("second run_one must succeed");
    assert_eq!(second, RunOutcome::NothingToDo);
}

/// The merging device's tick lands AFTER the prior local clock is folded in
/// (#744): a prior entry for this device at 5 is written as 6. Ticking before
/// the fold would write max(1, 5) = 5, a merge clock with no +1 for its device.
#[test]
fn run_one_ticks_the_merging_device_after_folding_the_prior_clock() {
    let (_tmp, vault_dir, identity, vault_uuid) = stage_and_unlock_golden();
    let prior = vec![
        VectorClockEntry {
            device_uuid: TEST_MERGING_DEVICE,
            counter: 5,
        },
        VectorClockEntry {
            device_uuid: [0xEE; 16],
            counter: 2,
        },
    ];
    let mut state = SyncState::new(vault_uuid, prior).expect("canonical clock");
    let mut ux = AutoKeepLocalVetoUx;

    let outcome = run_one(
        &vault_dir,
        &identity,
        &mut state,
        &mut ux,
        TEST_MERGING_DEVICE,
        TEST_NOW_MS,
    )
    .expect("run_one must succeed");
    assert_eq!(outcome, RunOutcome::SilentMerge);

    let password = golden_vault_password();
    let opened = open_vault(&vault_dir, Unlocker::Password(&password), None).expect("open");
    let mine = opened
        .manifest
        .vector_clock
        .iter()
        .find(|e| e.device_uuid == TEST_MERGING_DEVICE)
        .expect("merging device entry on disk");
    assert_eq!(mine.counter, 6);
}
