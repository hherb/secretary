//! Property tests for C.1.1a conflict-copy ingestion.
//!
//! Two properties:
//!   - `prop_ingest_idempotent`: calling `sync_once` twice with
//!     identical inputs yields equally-shaped outcomes (no hidden
//!     state mutation between invocations).
//!   - `prop_ingest_silently_rejects_junk`: arbitrary bytes written to
//!     a sibling-named `*.cbor.enc` file in the vault folder never
//!     authenticate (the resulting `bundle.copies` excludes the junk).
//!
//! A third property (N-way order independence) was prototyped in the
//! C.1.1a plan but proved fixture-heavy without commensurate coverage
//! gain over the integration tests in `sync_ingest.rs` — left as a
//! follow-up issue.

#![forbid(unsafe_code)]

mod fixtures;
mod sync_helpers;

use proptest::prelude::*;
use secretary_core::sync::{sync_once, SyncOutcome, SyncState};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;
use sync_helpers::{fresh_vault_two_concurrent_manifests, fresh_vault_with_clock};

fn open_identity(folder: &std::path::Path) -> secretary_core::unlock::UnlockedIdentity {
    let password = fixtures::golden_vault_001_password();
    let vault_toml = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    open_with_password(&vault_toml, &bundle, &password).unwrap()
}

use fixtures::extract_vault_uuid;

proptest! {
    // Cases reduced from the default 256 because each iteration runs
    // Argon2 + full sync_once + manifest re-signing. 16 cases × 2 calls
    // × ~few-seconds per invocation keeps the test under ~minute scope.
    #![proptest_config(ProptestConfig {
        cases: 16,
        .. ProptestConfig::default()
    })]

    /// Calling `sync_once` twice with identical inputs returns
    /// observationally-equal outcomes: same number of authenticated
    /// copies and the same diff-plan content.
    #[test]
    fn prop_ingest_idempotent(
        counter_a in 1u64..1000,
        counter_b in 1u64..1000,
    ) {
        let canonical_clock = vec![VectorClockEntry { device_uuid: [0xAA; 16], counter: counter_a }];
        let sibling_clock = vec![VectorClockEntry { device_uuid: [0xBB; 16], counter: counter_b }];
        let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
            canonical_clock,
            "manifest.cbor.enc.proptest-sibling",
            sibling_clock,
        );
        let identity = open_identity(&folder);
        let state = SyncState::new(
            extract_vault_uuid(&folder),
            vec![VectorClockEntry { device_uuid: [0x77; 16], counter: 1 }],
        )
        .unwrap();

        let out1 = sync_once(&folder, &identity, &state, 0).unwrap();
        let out2 = sync_once(&folder, &identity, &state, 0).unwrap();

        match (&out1, &out2) {
            (
                SyncOutcome::ConcurrentDetected { bundle: b1, plan: p1, .. },
                SyncOutcome::ConcurrentDetected { bundle: b2, plan: p2, .. },
            ) => {
                prop_assert_eq!(b1.copies.len(), b2.copies.len(),
                    "idempotent count of authenticated copies");
                prop_assert_eq!(p1.diverging_blocks.clone(), p2.diverging_blocks.clone(),
                    "idempotent diff-plan");
            }
            (a, b) => prop_assert!(false, "expected ConcurrentDetected on both runs, got {a:?} / {b:?}"),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    /// For any arbitrary byte string written to a sibling-named
    /// `*.cbor.enc` file in the vault folder, `sync_once` never
    /// panics and never falsely accepts the junk into
    /// `bundle.copies`. Authentication is the security boundary; the
    /// filename is just the discovery hook.
    #[test]
    fn prop_ingest_silently_rejects_junk(
        garbage in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let canonical_clock = vec![VectorClockEntry { device_uuid: [0xAA; 16], counter: 1 }];
        let (folder, _tmp) = fresh_vault_with_clock(canonical_clock);
        std::fs::write(
            folder.join("manifest.cbor.enc.junk-fuzz"),
            &garbage,
        ).unwrap();

        let identity = open_identity(&folder);
        // state device 0x77 is unrelated to the canonical clock's
        // device 0xAA, so dispatch fires Concurrent and ingestion
        // runs.
        let state = SyncState::new(
            extract_vault_uuid(&folder),
            vec![VectorClockEntry { device_uuid: [0x77; 16], counter: 1 }],
        )
        .unwrap();

        let outcome = sync_once(&folder, &identity, &state, 0).unwrap();
        match outcome {
            SyncOutcome::ConcurrentDetected { bundle, .. } => {
                prop_assert!(
                    bundle.copies.is_empty(),
                    "junk bytes must never authenticate (got {} copies)",
                    bundle.copies.len()
                );
            }
            other => prop_assert!(false, "expected ConcurrentDetected, got {other:?}"),
        }
    }
}
