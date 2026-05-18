//! Integration tests for C.1.1a conflict-copy ingestion.
//!
//! End-to-end coverage of `sync_once`'s Concurrent dispatch arm
//! using the `golden_vault_001` fixture, with sibling manifest files
//! constructed via `sync_helpers::fresh_vault_two_concurrent_manifests`
//! and `fresh_vault_four_concurrent_manifests`.
//!
//! Lib-level unit tests in `core/src/sync/ingest.rs::tests` cover the
//! pure-input rejection arms (empty / garbage / oversize bytes); this
//! integration file covers the happy paths + filename-convention
//! compatibility + the lazy-no-scan property for the three non-
//! concurrent dispatch outcomes.
//!
//! Deliberately deferred to follow-up issues:
//!   - wrong-vault_uuid silent rejection — needs `create_vault` to
//!     spin up a second authenticated vault and drop its manifest in
//!     the first vault's folder. Tracked in the C.1.1a spec §Risks.
//!   - wrong-owner-fingerprint silent rejection — similar second-vault
//!     fixture with a distinct owner identity.
//!   - block-divergence end-to-end — needs a block re-signing helper.

#![forbid(unsafe_code)]

mod fixtures;
mod sync_helpers;

use secretary_core::sync::{sync_once, SyncOutcome, SyncState};
use secretary_core::unlock::open_with_password;
use secretary_core::vault::block::VectorClockEntry;
use sync_helpers::{
    fresh_vault_four_concurrent_manifests, fresh_vault_two_concurrent_manifests,
    fresh_vault_with_clock,
};

/// Open the identity from a per-test vault tempdir. The vault is a
/// recursive copy of `golden_vault_001` with a possibly-rewritten
/// canonical clock; the identity is loaded by Argon2-unlocking the
/// bundle bytes inside that tempdir (so each test pays the unlock
/// cost — the lazy-no-scan tests below are deliberately independent
/// of any open_vault state across runs).
fn open_identity(folder: &std::path::Path) -> secretary_core::unlock::UnlockedIdentity {
    let password = fixtures::golden_vault_001_password();
    let vault_toml = std::fs::read(folder.join("vault.toml")).expect("read vault.toml");
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).expect("read bundle");
    open_with_password(&vault_toml, &bundle, &password).expect("open_with_password")
}

/// Read the vault_uuid from `golden_vault_001`'s `vault.toml` so test
/// SyncState values bind to the right vault.
fn extract_vault_uuid(folder: &std::path::Path) -> [u8; 16] {
    let s = std::fs::read_to_string(folder.join("vault.toml")).unwrap();
    let vt = secretary_core::unlock::vault_toml::decode(&s).unwrap();
    vt.vault_uuid
}

/// Build a SyncState whose `highest_vector_clock_seen` is concurrent
/// with `canonical_clock`: both clocks reference one device the other
/// does not, so `ClockRelation::Concurrent` is the dispatch outcome.
fn concurrent_state(folder: &std::path::Path) -> SyncState {
    SyncState::new(
        extract_vault_uuid(folder),
        vec![VectorClockEntry {
            device_uuid: [0x77; 16],
            counter: 1,
        }],
    )
    .expect("SyncState::new")
}

#[test]
fn sync_once_concurrent_no_conflict_copies_returns_bundle_zero_copies() {
    // Canonical-only vault state — fresh_vault_with_clock writes the
    // canonical manifest only. With a concurrent local clock, the
    // Concurrent dispatch fires but the bundle has zero copies
    // because there are no sibling files on disk.
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(canonical_clock);
    let identity = open_identity(&folder);
    let state = concurrent_state(&folder);

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => {
            assert!(bundle.copies.is_empty(), "no sibling files expected");
            assert!(
                plan.diverging_blocks.is_empty(),
                "no divergence without conflict-copy manifests"
            );
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_one_conflict_copy_authenticated() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.sync-conflict-from-device-bb",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    let state = concurrent_state(&folder);

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(bundle.copies.len(), 1, "exactly one authenticated copy");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_three_conflict_copies_authenticated() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let siblings = [
        (
            "manifest.cbor.enc.copy-1",
            vec![VectorClockEntry {
                device_uuid: [0xB1; 16],
                counter: 1,
            }],
        ),
        (
            "manifest.cbor.enc.copy-2",
            vec![VectorClockEntry {
                device_uuid: [0xB2; 16],
                counter: 2,
            }],
        ),
        (
            "manifest.cbor.enc.copy-3",
            vec![VectorClockEntry {
                device_uuid: [0xB3; 16],
                counter: 3,
            }],
        ),
    ];
    let (folder, _tmp) = fresh_vault_four_concurrent_manifests(canonical_clock, siblings);
    let identity = open_identity(&folder);
    let state = concurrent_state(&folder);

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(
                bundle.copies.len(),
                3,
                "all three N-way siblings should authenticate"
            );
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_invalid_signature_silently_ignored() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.tampered",
        sibling_clock,
    );

    // Flip the LAST byte of the sibling — last 3309 bytes are the
    // ML-DSA-65 signature region per the §4.1 envelope, so the very
    // last byte is definitely inside the signature suffix.
    let sibling_path = folder.join("manifest.cbor.enc.tampered");
    let mut bytes = std::fs::read(&sibling_path).expect("read sibling");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&sibling_path, &bytes).expect("write tampered");

    let identity = open_identity(&folder);
    let state = concurrent_state(&folder);

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert!(
                bundle.copies.is_empty(),
                "tampered sibling must be silently rejected"
            );
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_dropbox_naming_convention_accepted() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc (conflicted copy 2026-05-15)",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    let state = concurrent_state(&folder);

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(
                bundle.copies.len(),
                1,
                "Dropbox-naming sibling should authenticate"
            );
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_syncthing_naming_convention_accepted() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.sync-conflict-20260515-100000-ABCD1234",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    let state = concurrent_state(&folder);

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(
                bundle.copies.len(),
                1,
                "Syncthing-naming sibling should authenticate"
            );
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_junk_sibling_silently_ignored() {
    // Add a sibling file with random bytes — not a valid envelope.
    // Authentication MUST reject it; bundle.copies stays empty.
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(canonical_clock);
    std::fs::write(
        folder.join("manifest.cbor.enc.junk"),
        b"definitely not a manifest envelope",
    )
    .expect("write junk");

    let identity = open_identity(&folder);
    let state = concurrent_state(&folder);

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert!(
                bundle.copies.is_empty(),
                "junk-bytes sibling must be silently rejected"
            );
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_lazy_no_scan_when_disk_dominates() {
    // Lazy-no-scan invariant: when the dispatch outcome is
    // AppliedAutomatically (disk strictly dominates local), sync_once
    // MUST NOT scan the vault folder for conflict-copies — even if a
    // sibling file exists that would otherwise authenticate. Observed
    // behaviorally: the returned variant is AppliedAutomatically, not
    // ConcurrentDetected.
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.would-authenticate",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    // Empty state → IncomingDominates → AppliedAutomatically.
    let state = SyncState::empty(extract_vault_uuid(&folder));

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    assert!(
        matches!(outcome, SyncOutcome::AppliedAutomatically { .. }),
        "expected lazy fast-path AppliedAutomatically (no scan), got {outcome:?}"
    );
}

#[test]
fn sync_once_lazy_no_scan_when_clocks_equal() {
    // Symmetric to the above for the Equal arm: NothingToDo, no scan.
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock.clone(),
        "manifest.cbor.enc.would-authenticate",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    let state = SyncState::new(extract_vault_uuid(&folder), canonical_clock).expect("state");

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    assert!(
        matches!(outcome, SyncOutcome::NothingToDo),
        "expected lazy fast-path NothingToDo (no scan), got {outcome:?}"
    );
}
