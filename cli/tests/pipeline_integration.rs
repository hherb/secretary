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
use secretary_test_utils::{copy_dir_recursive, core_test_data_dir};

/// Filename of the golden-vault inputs JSON living alongside the
/// fixture directory; the password we need to drive `open_with_password`
/// is stored there.
const GOLDEN_INPUTS_FILENAME: &str = "golden_vault_001_inputs.json";

/// Filename of the golden vault folder under `core/tests/data/`.
const GOLDEN_VAULT_DIRNAME: &str = "golden_vault_001";

/// Filenames inside the vault folder.
const VAULT_TOML_FILENAME: &str = "vault.toml";
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";

/// Extract the password from `golden_vault_001_inputs.json`. We use a
/// lightweight string-scan rather than pulling in a `serde_json`
/// dev-dep just for this — `golden_vault_001_inputs.json` is a stable
/// fixture and the inputs schema is single-sourced in `core/tests/`.
fn golden_vault_password() -> SecretBytes {
    let raw = fs::read_to_string(core_test_data_dir().join(GOLDEN_INPUTS_FILENAME))
        .expect("golden_vault_001_inputs.json must exist");
    // The relevant line looks like `  "password": "correct horse battery staple",`
    // — extract the value between the colon and the trailing comma.
    let needle = "\"password\":";
    let start = raw.find(needle).expect("password key present");
    let after_key = &raw[start + needle.len()..];
    let first_quote = after_key
        .find('"')
        .expect("opening quote after password key");
    let rest = &after_key[first_quote + 1..];
    let closing_quote = rest.find('"').expect("closing quote after password value");
    let password = &rest[..closing_quote];
    SecretBytes::new(password.as_bytes().to_vec())
}

/// Stage a fresh writable copy of `golden_vault_001/` into a tempdir
/// and unlock it. Returns the tempdir (keep alive for the test's
/// lifetime), the vault folder path inside it, the unlocked identity,
/// the password (for `commit_with_decisions` if the test path reaches
/// it), and the vault's UUID (so the test can build a matching
/// [`SyncState`]).
fn stage_and_unlock_golden() -> (
    tempfile::TempDir,
    PathBuf,
    UnlockedIdentity,
    SecretBytes,
    [u8; 16],
) {
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
    (tmp, vault_dir, identity, password, vt.vault_uuid)
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
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;

    let pre_clock = state.highest_vector_clock_seen.clone();
    let outcome = run_one(
        &vault_dir,
        &identity,
        &password,
        &mut state,
        &mut ux,
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
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;

    let first = run_one(
        &vault_dir,
        &identity,
        &password,
        &mut state,
        &mut ux,
        TEST_NOW_MS,
    )
    .expect("first run_one must succeed");
    assert_eq!(first, RunOutcome::AppliedAutomatically);

    let clock_after_first = state.highest_vector_clock_seen.clone();
    let second = run_one(
        &vault_dir,
        &identity,
        &password,
        &mut state,
        &mut ux,
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
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();

    // First, advance state to disk's clock so we know what's there.
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;
    let first = run_one(
        &vault_dir,
        &identity,
        &password,
        &mut state,
        &mut ux,
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
        &password,
        &mut dominating_state,
        &mut ux,
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
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let mut ux = AutoKeepLocalVetoUx;
    let ux_ref: &mut dyn secretary_cli::veto::VetoUx = &mut ux;
    let outcome = run_one(
        &vault_dir,
        &identity,
        &password,
        &mut state,
        ux_ref,
        TEST_NOW_MS,
    )
    .expect("run_one with dyn-trait UX must succeed");
    assert_eq!(outcome, RunOutcome::AppliedAutomatically);
}
