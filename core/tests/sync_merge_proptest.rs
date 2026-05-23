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
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncError, SyncOutcome, SyncState,
    VetoDecision,
};
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

/// Map a boolean choice to a [`VetoDecision`] for a given `record_id`.
/// `true` → `KeepLocal`, `false` → `AcceptTombstone`. Used by property
/// 3 to vary the decision kind per veto across cases.
fn make_decision(record_id: [u8; 16], keep_local: bool) -> VetoDecision {
    if keep_local {
        VetoDecision::KeepLocal { record_id }
    } else {
        VetoDecision::AcceptTombstone { record_id }
    }
}

/// Build a per-block-divergent fixture with TWO disjoint vetoes. Both
/// records are LIVE on canonical, TOMBSTONED on sibling at the later
/// death clock. Used by property 3 to vary decision ordering.
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

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_CASES,
        .. ProptestConfig::default()
    })]

    /// Property 2 — The three-step
    /// `sync_once → prepare_merge → commit_with_decisions` is a
    /// deterministic function of its inputs: running it on two
    /// independent vaults built with identical fixture parameters
    /// produces:
    ///
    /// - The same returned [`SyncState`] (post_merge_clock is a pure
    ///   function of the input manifest clocks).
    /// - The same decrypted canonical block records (CRDT merge is a
    ///   pure function of its inputs).
    /// - DIFFERENT canonical block envelope bytes (AEAD nonces are
    ///   drawn from `OsRng` per rewrite — a deterministic-nonce
    ///   regression would emit identical ciphertext).
    ///
    /// The first two assertions are the idempotence claim: the merge
    /// surface has no hidden state that would let two equivalent
    /// invocations diverge in their observable output. The third
    /// assertion pins the AEAD-nonce-per-rewrite contract at the
    /// proptest level (the integration-test surface in
    /// `sync_merge_crash.rs` already covers the same contract for the
    /// retry path; this adds property-level coverage over a different
    /// dimension — across independent vaults).
    ///
    /// Inputs: same as property 1 (canonical + sibling manifest-clock
    /// counters).
    #[test]
    fn prop_three_step_idempotent_on_repeated_invocation(
        counter_canonical in 1u64..1000,
        counter_sibling in 1u64..1000,
    ) {
        // Two independent fixtures with identical inputs. The two
        // `tempfile::TempDir`s must stay alive until the test ends.
        let (folder_a, _tmp_a, block_uuid_a) =
            build_no_veto_fixture(counter_canonical, counter_sibling);
        let (folder_b, _tmp_b, block_uuid_b) =
            build_no_veto_fixture(counter_canonical, counter_sibling);
        prop_assert_eq!(
            block_uuid_a,
            block_uuid_b,
            "both fixtures must derive the same block_uuid from golden_vault_001",
        );

        let password = fixtures::golden_vault_001_password();

        let run_three_step = |folder: &std::path::Path| -> (SyncState, Vec<Record>, Vec<u8>) {
            let (bundle, plan, _state_pre) = drive_sync_once_concurrent(folder);
            let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
            let bundle_bytes = std::fs::read(folder.join("identity.bundle.enc"))
                .expect("read identity bundle");
            let identity = open_with_password(&vt_bytes, &bundle_bytes, &password)
                .expect("open_with_password");

            let draft = prepare_merge(folder, &identity, &bundle, &plan).expect("prepare_merge");
            assert!(
                draft.vetoes.is_empty(),
                "no_veto_fixture must produce zero vetoes (got {})",
                draft.vetoes.len(),
            );
            let new_state =
                commit_with_decisions(folder, &password, draft, Vec::new(), COMMIT_NOW_MS)
                    .expect("commit_with_decisions");
            let records = read_canonical_block_records(folder, block_uuid_a);
            let block_path = sync_helpers::block_file_path(folder, &block_uuid_a);
            let block_bytes = std::fs::read(&block_path).expect("read canonical block");
            (new_state, records, block_bytes)
        };

        let (state_a, records_a, bytes_a) = run_three_step(&folder_a);
        let (state_b, records_b, bytes_b) = run_three_step(&folder_b);

        // Pure function of inputs: SyncState matches.
        prop_assert_eq!(
            state_a,
            state_b,
            "two equivalent fixtures must yield the same post-commit SyncState",
        );
        // Pure function of inputs: decrypted block records match.
        prop_assert_eq!(
            records_a,
            records_b,
            "two equivalent fixtures must yield the same decrypted canonical block records",
        );
        // AEAD-nonce-per-rewrite contract: envelope bytes diverge.
        prop_assert_ne!(
            bytes_a,
            bytes_b,
            "two independent commits must produce different ciphertext (AEAD nonces from OsRng)",
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_CASES,
        .. ProptestConfig::default()
    })]

    /// Property 3 — Given a draft with two vetoes on disjoint
    /// `record_id`s, the order of decisions inside the
    /// `Vec<VetoDecision>` passed to `commit_with_decisions` does NOT
    /// affect the post-commit observable state. Two equivalent
    /// fixtures are built; one commits with decisions `[d_a, d_b]`,
    /// the other with `[d_b, d_a]`. Assert:
    ///
    /// - Same returned [`SyncState`].
    /// - Same decrypted canonical block records (set equality — both
    ///   come from `prepare_merge`'s BTreeMap-into-Vec output, so they
    ///   are already sorted by `record_uuid`; element-wise equality is
    ///   the strict check).
    ///
    /// Why this is non-trivial: `apply_decisions` iterates decisions
    /// in their input order to apply per-record `KeepLocal` restores.
    /// If the per-decision side effects were not commutative (e.g., a
    /// future refactor accidentally shared mutable state across
    /// per-decision steps), the two orderings would diverge. The
    /// property pins commutativity over the full decision set.
    ///
    /// Inputs: clock counters + two booleans (`keep_local_a`,
    /// `keep_local_b`) that vary the decision kind per veto. This
    /// covers the (KeepLocal, KeepLocal), (KeepLocal, AcceptTombstone),
    /// (AcceptTombstone, KeepLocal), and
    /// (AcceptTombstone, AcceptTombstone) decision pairings across the
    /// 16 case budget.
    #[test]
    fn prop_commit_associative_under_disjoint_vetoes(
        counter_canonical in 1u64..1000,
        counter_sibling in 1u64..1000,
        keep_local_a: bool,
        keep_local_b: bool,
    ) {
        let (folder_a, _tmp_a, block_uuid) =
            build_two_veto_fixture(counter_canonical, counter_sibling);
        let (folder_b, _tmp_b, _block_uuid_b) =
            build_two_veto_fixture(counter_canonical, counter_sibling);

        let password = fixtures::golden_vault_001_password();
        let decision_a = make_decision(RECORD_A_UUID, keep_local_a);
        let decision_b = make_decision(RECORD_B_UUID, keep_local_b);

        let commit = |folder: &std::path::Path, decisions: Vec<VetoDecision>| -> (SyncState, Vec<Record>) {
            let (bundle, plan, _state_pre) = drive_sync_once_concurrent(folder);
            let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
            let bundle_bytes = std::fs::read(folder.join("identity.bundle.enc"))
                .expect("read identity bundle");
            let identity = open_with_password(&vt_bytes, &bundle_bytes, &password)
                .expect("open_with_password");
            let draft = prepare_merge(folder, &identity, &bundle, &plan).expect("prepare_merge");
            assert_eq!(
                draft.vetoes.len(),
                2,
                "two_veto_fixture must produce exactly two vetoes (got {})",
                draft.vetoes.len(),
            );
            let new_state =
                commit_with_decisions(folder, &password, draft, decisions, COMMIT_NOW_MS)
                    .expect("commit_with_decisions");
            let records = read_canonical_block_records(folder, block_uuid);
            (new_state, records)
        };

        // Order 1: [d_a, d_b]
        let (state_ab, records_ab) =
            commit(&folder_a, vec![decision_a.clone(), decision_b.clone()]);
        // Order 2: [d_b, d_a] — swapped
        let (state_ba, records_ba) = commit(&folder_b, vec![decision_b, decision_a]);

        prop_assert_eq!(
            state_ab,
            state_ba,
            "decision order must not affect the returned SyncState",
        );
        prop_assert_eq!(
            records_ab,
            records_ba,
            "decision order must not affect the post-commit canonical block records",
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_CASES,
        .. ProptestConfig::default()
    })]

    /// Property 4 — `commit_with_decisions` enforces the strict
    /// `draft.vetoes` ↔ `decisions` bijection by `record_id`. For a
    /// fixture with exactly one veto on [`RECORD_A_UUID`], the test
    /// constructs `decisions` from random `(include_match, strays)`
    /// pairs and asserts the outcome class:
    ///
    /// - `!include_match` (matching decision omitted) →
    ///   `Err(SyncError::MissingVetoDecision { record_id: RECORD_A_UUID })`,
    ///   regardless of how many strays are present. `apply_decisions`'s
    ///   Missing check runs before Unknown, so Missing wins on
    ///   `(no_match, with_strays)`.
    /// - `include_match && !strays.is_empty()` →
    ///   `Err(SyncError::UnknownVetoDecision { record_id })` where
    ///   `record_id == min(strays)` (BTreeSet ordering — smallest
    ///   stray fires).
    /// - `include_match && strays.is_empty()` → `Ok(_)`.
    ///
    /// Strays are constructed as `[seed; 16]` from a random
    /// `seed: u8 in (0..=0xFF except 0xAA)`. Excluding 0xAA prevents
    /// a stray from coincidentally landing on
    /// [`RECORD_A_UUID = [0xAA; 16]`], which would collapse into the
    /// matching decision via the bijection's set-based dedupe
    /// semantics.
    ///
    /// Inputs: clock counters, `include_match: bool`, `strays`: a vec
    /// of distinct-from-0xAA seeds 0-2 entries long.
    #[test]
    fn prop_decision_bijection_enforced(
        counter_canonical in 1u64..1000,
        counter_sibling in 1u64..1000,
        include_match: bool,
        strays in prop::collection::vec(
            (0u8..=0xFF).prop_filter("stray must not equal RECORD_A_UUID first byte", |b| *b != 0xAA),
            0usize..=2,
        ),
    ) {
        let (folder, _tmp, _block_uuid) =
            build_single_veto_fixture(counter_canonical, counter_sibling);

        let (bundle, plan, _state_pre) = drive_sync_once_concurrent(&folder);
        let password = fixtures::golden_vault_001_password();
        let vt_bytes = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
        let bundle_bytes = std::fs::read(folder.join("identity.bundle.enc"))
            .expect("read identity bundle");
        let identity = open_with_password(&vt_bytes, &bundle_bytes, &password)
            .expect("open_with_password");

        let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
        prop_assert_eq!(
            draft.vetoes.len(),
            1,
            "single_veto_fixture must produce exactly one veto",
        );

        // Build the decisions vec. Matching decision (if requested)
        // first, then strays — but the bijection check is set-based, so
        // ordering inside the vec doesn't affect which error fires.
        let mut decisions = Vec::with_capacity((include_match as usize) + strays.len());
        if include_match {
            decisions.push(VetoDecision::KeepLocal { record_id: RECORD_A_UUID });
        }
        for seed in &strays {
            let stray_uuid = [*seed; 16];
            decisions.push(VetoDecision::KeepLocal { record_id: stray_uuid });
        }

        let result = commit_with_decisions(&folder, &password, draft, decisions, COMMIT_NOW_MS);

        if !include_match {
            // Matching decision omitted → Missing fires on
            // RECORD_A_UUID (the only veto). Strays, if any, do not
            // matter — Missing is checked before Unknown.
            match result {
                Err(SyncError::MissingVetoDecision { record_id }) => prop_assert_eq!(
                    record_id,
                    RECORD_A_UUID,
                    "Missing must report RECORD_A_UUID (the un-adjudicated veto)",
                ),
                other => prop_assert!(
                    false,
                    "expected MissingVetoDecision, got {other:?}",
                ),
            }
        } else if !strays.is_empty() {
            // Matching present + strays → Unknown fires on the
            // smallest stray. `strays` carries u8 seeds; the resulting
            // [u8; 16] UUIDs sort lexicographically by their first
            // byte (all 16 bytes equal in our construction), so the
            // smallest stray UUID corresponds to the smallest seed.
            let smallest_stray_seed = *strays.iter().min().expect("strays non-empty");
            let expected_stray_uuid = [smallest_stray_seed; 16];
            match result {
                Err(SyncError::UnknownVetoDecision { record_id }) => prop_assert_eq!(
                    record_id,
                    expected_stray_uuid,
                    "Unknown must report the smallest stray UUID",
                ),
                other => prop_assert!(
                    false,
                    "expected UnknownVetoDecision, got {other:?}",
                ),
            }
        } else {
            // Matching present + no strays → bijection holds, commit
            // succeeds.
            prop_assert!(
                result.is_ok(),
                "exact bijection must commit successfully, got {:?}",
                result,
            );
        }
    }
}
