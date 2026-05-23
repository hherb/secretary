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
//!    canonical block records.
//! 4. **Bijection enforcement** — for random `(matching, stray_count)`
//!    inputs against a single-veto fixture, `commit_with_decisions`
//!    returns `MissingVetoDecision` / `UnknownVetoDecision` / `Ok` per
//!    the bijection rules (Missing checked before Unknown).
//!
//! ## Cost model
//!
//! Each case runs at least one `fresh_vault_two_concurrent_blocks` build
//! (open_vault Argon2 + two block encryptions + two manifest signs) plus
//! at least one `commit_with_decisions` (re-encrypt + re-sign). Properties
//! 2-3 build two fixtures per case. The per-property `cases` cap
//! ([`sync_merge_proptest_helpers::PROPTEST_CASES`]) is set so each
//! property completes in well under a minute on the project's reference
//! hardware.
//!
//! ## File layout
//!
//! Helpers (constants, record builders, fixture builders, drivers) live
//! in [`sync_merge_proptest_helpers`] so this file holds only the four
//! `proptest!` blocks. See the helpers module for the fixture
//! parametrisation and the cost-budget rationale.

#![forbid(unsafe_code)]

use proptest::prelude::*;
use secretary_core::sync::{
    commit_with_decisions, prepare_merge, sync_once, SyncError, SyncOutcome, VetoDecision,
};

mod fixtures;
mod sync_helpers;
mod sync_merge_proptest_helpers;

use sync_merge_proptest_helpers::{
    build_no_veto_fixture, build_single_veto_fixture, build_two_veto_fixture,
    drive_sync_once_concurrent, make_decision, open_identity, read_canonical_block_records,
    COMMIT_NOW_MS, PROPTEST_CASES, RECORD_A_UUID, RECORD_B_UUID,
};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: PROPTEST_CASES,
        .. ProptestConfig::default()
    })]

    /// Property 1 — Post-commit, the returned `SyncState` is a fixpoint
    /// with respect to the disk's canonical manifest clock: re-running
    /// `sync_once` yields [`SyncOutcome::NothingToDo`].
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
    /// `clock_relation` between state and disk — `Equal` triggers
    /// `NothingToDo`. The property pins that the two writes agree, so
    /// the relation cannot land in any other branch (Concurrent /
    /// IncomingDominates / IncomingDominated) post-commit.
    #[test]
    fn prop_commit_then_sync_once_yields_nothing_to_do(
        counter_canonical in 1u64..1000,
        counter_sibling in 1u64..1000,
    ) {
        let (folder, _tmp, _block_uuid) =
            build_no_veto_fixture(counter_canonical, counter_sibling);
        let (bundle, plan) = drive_sync_once_concurrent(&folder);
        let identity = open_identity(&folder);

        let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
        prop_assert!(
            draft.vetoes.is_empty(),
            "no_veto_fixture must produce zero vetoes (got {})",
            draft.vetoes.len(),
        );

        let password = fixtures::golden_vault_001_password();
        let new_state =
            commit_with_decisions(&folder, &password, draft, Vec::new(), COMMIT_NOW_MS)
                .expect("commit_with_decisions");

        // Re-run sync_once with the returned SyncState. Equal →
        // NothingToDo is the only acceptable outcome.
        let outcome = sync_once(&folder, &identity, &new_state, 0u64)
            .expect("sync_once post-commit");
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
    /// - The same returned `SyncState` (`post_merge_clock` is a pure
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
    #[test]
    fn prop_three_step_idempotent_on_repeated_invocation(
        counter_canonical in 1u64..1000,
        counter_sibling in 1u64..1000,
    ) {
        // Both UUIDs come from the same deterministic
        // `golden_vault_001_first_block_uuid` probe inside the fixture
        // builder, so they are structurally identical and no runtime
        // equality check is needed.
        let (folder_a, _tmp_a, block_uuid) =
            build_no_veto_fixture(counter_canonical, counter_sibling);
        let (folder_b, _tmp_b, _block_uuid_b) =
            build_no_veto_fixture(counter_canonical, counter_sibling);

        // `assert!` (not `prop_assert!`) inside the closure: proptest's
        // `prop_assert!` macro expands to `return Err(...)` from the
        // enclosing test fn, which cannot cross a closure boundary.
        // Panics from `assert!` are still caught by proptest and
        // reported as case failures — only shrinking metadata is lost.
        let run = |folder: &std::path::Path| {
            let (bundle, plan) = drive_sync_once_concurrent(folder);
            let identity = open_identity(folder);
            let draft = prepare_merge(folder, &identity, &bundle, &plan).expect("prepare_merge");
            assert!(
                draft.vetoes.is_empty(),
                "no_veto_fixture must produce zero vetoes (got {})",
                draft.vetoes.len(),
            );
            let password = fixtures::golden_vault_001_password();
            let new_state =
                commit_with_decisions(folder, &password, draft, Vec::new(), COMMIT_NOW_MS)
                    .expect("commit_with_decisions");
            let records = read_canonical_block_records(folder, block_uuid);
            let block_path = sync_helpers::block_file_path(folder, &block_uuid);
            let block_bytes = std::fs::read(&block_path).expect("read canonical block");
            (new_state, records, block_bytes)
        };

        let (state_a, records_a, bytes_a) = run(&folder_a);
        let (state_b, records_b, bytes_b) = run(&folder_b);

        prop_assert_eq!(
            state_a,
            state_b,
            "two equivalent fixtures must yield the same post-commit SyncState",
        );
        prop_assert_eq!(
            records_a,
            records_b,
            "two equivalent fixtures must yield the same decrypted canonical block records",
        );
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
    /// - Same returned `SyncState`.
    /// - Same decrypted canonical block records.
    ///
    /// Why this is non-trivial: `apply_decisions` iterates decisions
    /// in their input order to apply per-record `KeepLocal` restores.
    /// If the per-decision side effects were not commutative (e.g., a
    /// future refactor accidentally shared mutable state across
    /// per-decision steps), the two orderings would diverge.
    ///
    /// Inputs: clock counters + two booleans (`keep_local_a`,
    /// `keep_local_b`) that vary the decision kind per veto, covering
    /// (KeepLocal, KeepLocal), (KeepLocal, AcceptTombstone),
    /// (AcceptTombstone, KeepLocal), and
    /// (AcceptTombstone, AcceptTombstone) pairings across the 16-case
    /// budget.
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

        // `assert_eq!` (not `prop_assert_eq!`) inside the closure: see
        // the same note on the property-2 `run` closure — proptest's
        // assertion macros can't cross a closure boundary, and a
        // panic-based check is functionally equivalent at the cost of
        // shrinking metadata.
        let commit = |folder: &std::path::Path, decisions: Vec<VetoDecision>| {
            let (bundle, plan) = drive_sync_once_concurrent(folder);
            let identity = open_identity(folder);
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

        let (state_ab, records_ab) =
            commit(&folder_a, vec![decision_a.clone(), decision_b.clone()]);
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
    /// `seed: u8 != 0xAA`. Excluding 0xAA prevents a stray from
    /// coincidentally landing on
    /// [`RECORD_A_UUID = [0xAA; 16]`], which would collapse into the
    /// matching decision via the bijection's set-based dedupe
    /// semantics.
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

        let (bundle, plan) = drive_sync_once_concurrent(&folder);
        let identity = open_identity(&folder);
        let password = fixtures::golden_vault_001_password();

        let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
        prop_assert_eq!(
            draft.vetoes.len(),
            1,
            "single_veto_fixture must produce exactly one veto",
        );

        // Matching decision (if requested) first, then strays — but
        // the bijection check is set-based, so ordering inside the vec
        // doesn't affect which error fires.
        let mut decisions = Vec::with_capacity((include_match as usize) + strays.len());
        if include_match {
            decisions.push(VetoDecision::KeepLocal { record_id: RECORD_A_UUID });
        }
        for seed in &strays {
            decisions.push(VetoDecision::KeepLocal { record_id: [*seed; 16] });
        }

        let result = commit_with_decisions(&folder, &password, draft, decisions, COMMIT_NOW_MS);

        if !include_match {
            // Matching decision omitted → Missing fires on
            // RECORD_A_UUID (the only veto). Strays, if any, don't
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
            let smallest_seed = *strays.iter().min().expect("strays non-empty");
            let expected_stray_uuid = [smallest_seed; 16];
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
