//! Property tests for the C.1.1b merge layer.
//!
//! Four properties, one per [`proptest!`] block (separate blocks so the
//! per-property [`ProptestConfig::cases`] cap is explicit):
//!
//! 1. **Post-commit fixpoint** — after `commit_with_decisions` succeeds,
//!    re-running `sync_once` with the returned [`SyncState`] yields
//!    [`SyncOutcome::NothingToDo`]. Proves the commit's
//!    `post_merge_clock` matches the on-disk canonical manifest's new
//!    `vector_clock` (so the next dispatch sees `ClockRelation::Equal`).
//! 2. **Deterministic merge** — running the three-step
//!    `sync_once → prepare_merge → commit_with_decisions` on two
//!    independent vaults with identical inputs produces the same
//!    returned [`SyncState`] and the same decrypted canonical block
//!    records. AEAD nonces differ between the two commits (drawn from
//!    `OsRng` per rewrite), so envelope bytes diverge — the assertion
//!    is on the decrypted manifest body + records, not the ciphertext.
//! 3. **Decision-order independence** — given a draft with two vetoes
//!    (disjoint `record_id`s), committing with decisions `[d1, d2]` on
//!    one vault and `[d2, d1]` on an identically-built second vault
//!    produces the same returned [`SyncState`] and the same decrypted
//!    canonical block records. The two veto sets are non-overlapping by
//!    construction (`apply_decisions` indexes by `record_id`, which is
//!    unique per veto).
//! 4. **Bijection enforcement** — for random `(matching, stray_count)`
//!    inputs against a single-veto fixture, `commit_with_decisions`
//!    returns:
//!    - [`SyncError::MissingVetoDecision`] when the matching decision
//!      is omitted (whether or not strays are present — Missing is
//!      checked before Unknown in
//!      [`apply_decisions`](secretary_core::sync::__never_imported_apply_decisions)).
//!    - [`SyncError::UnknownVetoDecision`] when the matching decision is
//!      present AND at least one stray decision is present.
//!    - `Ok(_)` when the matching decision is present and no strays are
//!      present.
//!
//! ## Cost model
//!
//! Each case runs at least one `fresh_vault_two_concurrent_blocks` build
//! (open_vault Argon2 + two block encryptions + two manifest signs) plus
//! at least one `commit_with_decisions` (re-encrypt + re-sign). Properties
//! 2-3 build two fixtures per case. The per-property `cases` cap is set
//! so each property completes in well under a minute on the project's
//! reference hardware.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use proptest::prelude::*;
use secretary_core::crypto::secret::SecretString;
use secretary_core::sync::{commit_with_decisions, prepare_merge, sync_once, SyncOutcome, SyncState};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{open_vault, Record, RecordField, RecordFieldValue, Unlocker};

mod fixtures;
mod sync_helpers;

use fixtures::extract_vault_uuid;

// === Fixed (non-randomised) fixture inputs ===
//
// Property cases vary the manifest clock counters and (for prop 4) the
// stray decision UUIDs. Holding the other fixture inputs fixed avoids
// re-deriving record bodies / device UUIDs on every iteration and keeps
// each case's failure mode unambiguous (a flake names the same record
// UUIDs every time).

/// Record UUID for the FIRST veto-bearing record (canonical LIVE,
/// sibling TOMBSTONED at later death-clock).
const RECORD_A_UUID: [u8; 16] = [0xAA; 16];
/// Record UUID for the SECOND veto-bearing record. Strictly greater
/// than [`RECORD_A_UUID`] so `apply_decisions`'s canonical-sort error
/// reporting is deterministic (Missing fires on the smallest
/// un-adjudicated id). Consumed by property 3.
#[allow(dead_code)]
const RECORD_B_UUID: [u8; 16] = [0xBB; 16];
/// Record UUID for the FIRST non-conflicting record on the canonical
/// side (used in properties 1 & 2 where vetoes are not desired).
const NONCONFLICTING_RECORD_CANONICAL_UUID: [u8; 16] = [0xAA; 16];
/// Record UUID for the FIRST non-conflicting record on the sibling
/// side. Distinct from
/// [`NONCONFLICTING_RECORD_CANONICAL_UUID`] so the merge produces a
/// clean union with no vetoes.
const NONCONFLICTING_RECORD_SIBLING_UUID: [u8; 16] = [0xBB; 16];
/// Canonical device clock anchor. Records' `last_modifier_device` and
/// the canonical block's `vector_clock_summary` reference this device.
const CANONICAL_DEVICE_UUID: [u8; 16] = [0x0A; 16];
/// Sibling device clock anchor. Records' `last_modifier_device` and
/// the sibling block's `vector_clock_summary` reference this device.
const SIBLING_DEVICE_UUID: [u8; 16] = [0x0B; 16];
/// Local device clock anchor — the persisted `SyncState`'s clock entry.
/// Distinct from canonical / sibling so the pre-commit
/// `ClockRelation` is `Concurrent` (sync_once precondition for the
/// `ConcurrentDetected` arm).
const LOCAL_DEVICE_UUID: [u8; 16] = [0x0C; 16];
/// `last_mod_ms` on every canonical LIVE record. Constant; nothing else
/// fixes the value.
const LOCAL_LAST_MOD_MS: u64 = 100;
/// `last_mod_ms` AND `tombstoned_at_ms` on every sibling TOMBSTONED
/// record. Strictly greater than [`LOCAL_LAST_MOD_MS`] so the per-record
/// veto pass fires (`tombstone_veto_set`'s strict-greater branch).
/// Consumed by properties 3 and 4.
#[allow(dead_code)]
const SIBLING_TOMBSTONE_AT_MS: u64 = 200;
/// `last_mod_ms` on the non-conflicting sibling record (properties 1 &
/// 2). Same magnitude as [`SIBLING_TOMBSTONE_AT_MS`] but the record is
/// LIVE — only the UUID disjointness matters for vetoless merges.
const SIBLING_NONCONFLICTING_LAST_MOD_MS: u64 = 200;
/// Commit timestamp passed to `commit_with_decisions`. Reused across
/// every fixture's invocations so manifest `last_mod_ms` is uniform.
const COMMIT_NOW_MS: u64 = 1_000_000;
/// Sibling manifest filename — must start with `manifest.cbor.enc` per
/// `enumerate_manifest_siblings`. The Syncthing-style suffix is the
/// project convention across C.1.1a / C.1.1b tests.
const SIBLING_MANIFEST_FILENAME: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
/// Sibling block-file suffix — must start with a non-empty separator
/// so the resulting filename is recognised by
/// `enumerate_block_siblings`.
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";
/// `cases` cap shared across the four properties. Each case builds one
/// or two `fresh_vault_two_concurrent_blocks` fixtures (open_vault
/// Argon2 + two block encryptions + two manifest signs) and runs at
/// least one `commit_with_decisions` (re-encrypt + re-sign). 16 cases
/// per property keeps the whole file comfortably under a minute on the
/// project's reference hardware while still exploring two independent
/// dimensions per property (typically the canonical + sibling clock
/// counters).
const PROPTEST_CASES: u32 = 16;

/// Build a LIVE record with one field. `uuid` controls the
/// `record_uuid`; `device_uuid` + `last_mod_ms` flow into the field
/// envelope so the merge sees a coherent timestamp.
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

/// Build a TOMBSTONED record. `last_mod_ms == tombstoned_at_ms` per the
/// §11.5 invariant that tombstoned records pin both timestamps to the
/// death clock. Consumed by properties 3 and 4.
#[allow(dead_code)]
fn tombstoned_record(uuid: [u8; 16], device_uuid: [u8; 16], tombstoned_at_ms: u64) -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("ignored")),
            last_mod: tombstoned_at_ms,
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
        last_mod_ms: tombstoned_at_ms,
        tombstone: true,
        tombstoned_at_ms,
        unknown: BTreeMap::new(),
    }
}

/// Build a per-block-divergent fixture with NO veto-producing records.
/// The canonical block holds [`NONCONFLICTING_RECORD_CANONICAL_UUID`]
/// LIVE; the sibling block holds
/// [`NONCONFLICTING_RECORD_SIBLING_UUID`] LIVE. UUIDs are distinct, so
/// the merge produces a clean union and `draft.vetoes` is empty.
///
/// `counter_canonical` / `counter_sibling` are the per-device counters
/// at the canonical / sibling manifest level (the block-level
/// vector_clock_summary uses counter `1` because the records are local
/// edits from a single anchor; only the manifest-level clock varies).
fn build_no_veto_fixture(
    counter_canonical: u64,
    counter_sibling: u64,
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
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
    let canonical_manifest_clock = vec![VectorClockEntry {
        device_uuid: CANONICAL_DEVICE_UUID,
        counter: counter_canonical,
    }];
    let sibling_manifest_clock = vec![VectorClockEntry {
        device_uuid: SIBLING_DEVICE_UUID,
        counter: counter_sibling,
    }];

    let (folder, tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![live_record(
            NONCONFLICTING_RECORD_CANONICAL_UUID,
            CANONICAL_DEVICE_UUID,
            LOCAL_LAST_MOD_MS,
            "canonical",
        )],
        canonical_block_clock,
        canonical_manifest_clock,
        vec![live_record(
            NONCONFLICTING_RECORD_SIBLING_UUID,
            SIBLING_DEVICE_UUID,
            SIBLING_NONCONFLICTING_LAST_MOD_MS,
            "sibling",
        )],
        sibling_block_clock,
        sibling_manifest_clock,
        SIBLING_MANIFEST_FILENAME,
        SIBLING_BLOCK_SUFFIX,
        COMMIT_NOW_MS,
    );
    (folder, tmp, block_uuid)
}

/// Build a per-block-divergent fixture with a SINGLE veto. The veto
/// targets [`RECORD_A_UUID`] (canonical LIVE at
/// [`LOCAL_LAST_MOD_MS`], sibling TOMBSTONED at
/// [`SIBLING_TOMBSTONE_AT_MS`]). Consumed by property 4.
#[allow(dead_code)]
fn build_single_veto_fixture(
    counter_canonical: u64,
    counter_sibling: u64,
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
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
    let canonical_manifest_clock = vec![VectorClockEntry {
        device_uuid: CANONICAL_DEVICE_UUID,
        counter: counter_canonical,
    }];
    let sibling_manifest_clock = vec![VectorClockEntry {
        device_uuid: SIBLING_DEVICE_UUID,
        counter: counter_sibling,
    }];

    let (folder, tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![live_record(
            RECORD_A_UUID,
            CANONICAL_DEVICE_UUID,
            LOCAL_LAST_MOD_MS,
            "canonical",
        )],
        canonical_block_clock,
        canonical_manifest_clock,
        vec![tombstoned_record(
            RECORD_A_UUID,
            SIBLING_DEVICE_UUID,
            SIBLING_TOMBSTONE_AT_MS,
        )],
        sibling_block_clock,
        sibling_manifest_clock,
        SIBLING_MANIFEST_FILENAME,
        SIBLING_BLOCK_SUFFIX,
        COMMIT_NOW_MS,
    );
    (folder, tmp, block_uuid)
}

/// Build a per-block-divergent fixture with TWO disjoint vetoes. Both
/// records are LIVE on canonical, TOMBSTONED on sibling at the later
/// death clock. Used by property 3 to vary decision ordering.
#[allow(dead_code)]
fn build_two_veto_fixture(
    counter_canonical: u64,
    counter_sibling: u64,
) -> (std::path::PathBuf, tempfile::TempDir, [u8; 16]) {
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
    let canonical_manifest_clock = vec![VectorClockEntry {
        device_uuid: CANONICAL_DEVICE_UUID,
        counter: counter_canonical,
    }];
    let sibling_manifest_clock = vec![VectorClockEntry {
        device_uuid: SIBLING_DEVICE_UUID,
        counter: counter_sibling,
    }];

    let (folder, tmp) = sync_helpers::fresh_vault_two_concurrent_blocks(
        block_uuid,
        vec![
            live_record(
                RECORD_A_UUID,
                CANONICAL_DEVICE_UUID,
                LOCAL_LAST_MOD_MS,
                "canonical-a",
            ),
            live_record(
                RECORD_B_UUID,
                CANONICAL_DEVICE_UUID,
                LOCAL_LAST_MOD_MS,
                "canonical-b",
            ),
        ],
        canonical_block_clock,
        canonical_manifest_clock,
        vec![
            tombstoned_record(RECORD_A_UUID, SIBLING_DEVICE_UUID, SIBLING_TOMBSTONE_AT_MS),
            tombstoned_record(RECORD_B_UUID, SIBLING_DEVICE_UUID, SIBLING_TOMBSTONE_AT_MS),
        ],
        sibling_block_clock,
        sibling_manifest_clock,
        SIBLING_MANIFEST_FILENAME,
        SIBLING_BLOCK_SUFFIX,
        COMMIT_NOW_MS,
    );
    (folder, tmp, block_uuid)
}

/// Drive `sync_once` against a built fixture and unwrap the
/// `ConcurrentDetected` payload. Property cases use this once per
/// fixture; failures fail-fast with [`prop_assert!`] in the caller.
fn drive_sync_once_concurrent(
    folder: &std::path::Path,
) -> (
    secretary_core::sync::VaultBundle,
    secretary_core::sync::DiffPlan,
    SyncState,
) {
    let password = fixtures::golden_vault_001_password();
    let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle_bytes =
        std::fs::read(folder.join("identity.bundle.enc")).expect("read identity bundle");
    let identity =
        open_with_password(&vt_bytes, &bundle_bytes, &password).expect("open_with_password");

    let vault_uuid = extract_vault_uuid(folder);
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");
    let outcome = sync_once(folder, &identity, &state, 0u64).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    (bundle, plan, state)
}

/// Read the canonical block's decrypted records via a fresh `open_vault`
/// so the caller's stale state doesn't contaminate the assertion.
/// Consumed by properties 2 and 3.
#[allow(dead_code)]
fn read_canonical_block_records(folder: &std::path::Path, block_uuid: [u8; 16]) -> Vec<Record> {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    let block_path = sync_helpers::block_file_path(folder, &block_uuid);
    let bytes = std::fs::read(&block_path).expect("read block file");
    let plaintext = sync_helpers::decrypt_block_using_open(&open, &bytes).expect("decrypt block");
    plaintext.records
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_CASES,
        .. ProptestConfig::default()
    })]

    /// Property 1 — Post-commit, the returned [`SyncState`] is a
    /// fixpoint with respect to the disk's canonical manifest clock:
    /// re-running `sync_once` yields
    /// [`SyncOutcome::NothingToDo`].
    ///
    /// Inputs: two unsigned counters that vary the canonical + sibling
    /// manifest-level clocks. The fixture is per-block-divergent with
    /// disjoint record UUIDs (no vetoes), so the commit succeeds with
    /// an empty `decisions` vec.
    ///
    /// Why this is non-trivial: `commit_with_decisions` writes
    /// `post_merge_clock` (the component-wise max of canonical +
    /// sibling manifest clocks) into both the returned `SyncState` and
    /// the on-disk manifest. The next `sync_once` reads only the
    /// canonical manifest and dispatches purely on
    /// [`secretary_core::vault::conflict::clock_relation`] between
    /// state and disk — `Equal` triggers `NothingToDo`. The property
    /// pins that the two writes agree, so the relation cannot land in
    /// any other branch (Concurrent / IncomingDominates /
    /// IncomingDominated) post-commit.
    #[test]
    fn prop_commit_then_sync_once_yields_nothing_to_do(
        counter_canonical in 1u64..1000,
        counter_sibling in 1u64..1000,
    ) {
        let (folder, _tmp, _block_uuid) =
            build_no_veto_fixture(counter_canonical, counter_sibling);
        let (bundle, plan, _state_pre) = drive_sync_once_concurrent(&folder);

        let password = fixtures::golden_vault_001_password();
        let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
        let bundle_bytes =
            std::fs::read(folder.join("identity.bundle.enc")).expect("read identity bundle");
        let identity =
            open_with_password(&vt_bytes, &bundle_bytes, &password).expect("open_with_password");

        let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
        prop_assert!(
            draft.vetoes.is_empty(),
            "no_veto_fixture must produce zero vetoes (got {})",
            draft.vetoes.len(),
        );

        let new_state =
            commit_with_decisions(&folder, &password, draft, Vec::new(), COMMIT_NOW_MS)
                .expect("commit_with_decisions");

        // Re-run sync_once against the SAME identity using the returned
        // SyncState. Equal → NothingToDo is the only acceptable outcome.
        let outcome = sync_once(&folder, &identity, &new_state, 0u64).expect("sync_once post-commit");
        prop_assert_eq!(
            outcome,
            SyncOutcome::NothingToDo,
            "post-commit sync_once must report NothingToDo (state.clock vs disk.clock must be Equal)",
        );
    }
}
