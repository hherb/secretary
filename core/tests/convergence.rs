//! C.4 — cross-device convergence conformance. Two real device
//! identities edit one user's vault and reconcile through a shared
//! folder; the harness proves they converge to the same logical state
//! independent of sync order. See
//! docs/superpowers/specs/2026-06-15-c4-convergence-conformance-design.md.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use convergence_helpers::{baseline_from_seeded, decrypt_state, reconcile, Baseline, Device};
use convergence_helpers::{sync_as_adopter, sync_as_merger, LogicalRecord, VetoPolicy};

const A_UUID: [u8; 16] = [0x0A; 16];
const B_UUID: [u8; 16] = [0x0B; 16];
const X_RECORD: [u8; 16] = [0xAA; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];

#[test]
fn baseline_creates_an_empty_openable_vault() {
    let baseline = Baseline::create();
    let manifest = baseline.open_manifest();
    assert!(
        manifest.blocks.is_empty(),
        "fresh baseline must have no blocks"
    );
    assert!(
        manifest.vector_clock.is_empty(),
        "fresh baseline must have an empty manifest vector clock",
    );
}

#[test]
fn reconcile_lays_out_canonical_plus_conflict_copy() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 100);

    // A canonical, B merger (B's files become conflict-copies in S).
    let shared = reconcile(&a, Some(&b), X_BLOCK);

    let s = shared.folder();
    assert!(s.join("manifest.cbor.enc").exists());
    let manifest_siblings: Vec<_> = std::fs::read_dir(s)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("manifest.cbor.enc") && n != "manifest.cbor.enc")
        .collect();
    assert_eq!(
        manifest_siblings.len(),
        1,
        "expected exactly one manifest conflict-copy"
    );
}

#[test]
fn device_edit_writes_a_record_with_its_device_clock() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, /*seed*/ 0xA0);
    a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice", /*now_ms*/ 100);

    let records = a.decrypt_block_records(X_BLOCK);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_uuid, X_RECORD);
    assert!(!records[0].tombstone);

    let clock = a.manifest_clock();
    assert!(
        clock
            .iter()
            .any(|e| e.device_uuid == A_UUID && e.counter >= 1),
        "device A's edit must tick its own vector-clock entry",
    );
}

#[test]
fn merger_then_adopter_both_quiesce_on_disjoint_fields() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 100);

    // A canonical / B merger.
    let shared = reconcile(&a, Some(&b), X_BLOCK);

    // B merges (disjoint fields → no veto needed).
    let b_state = sync_as_merger(
        &baseline,
        shared.folder(),
        &b,
        VetoPolicy::NoVetoExpected,
        1_000,
    );
    // A adopts the merged LUB.
    let a_state = sync_as_adopter(&baseline, shared.folder(), &a, 1_001);

    // Quiescence: re-running sync on each device's final state is a no-op.
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &b_state,
        1_002
    ));
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &a_state,
        1_003
    ));
}

#[test]
fn decrypt_state_projects_records_to_comparable_shape() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    let shared = reconcile(&a, None, X_BLOCK); // one-editor; A canonical

    let state: Vec<LogicalRecord> = decrypt_state(&baseline, shared.folder(), X_BLOCK);
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].record_uuid, X_RECORD);
    assert!(!state[0].tombstone);
    assert_eq!(state[0].field_value_digests.len(), 1);
    assert_eq!(state[0].field_value_digests[0].0, "f1");
}

/// Scenario 1 (auto-apply): A edits record X; B never edits. After B
/// syncs it adopts A's state; both decrypt to A's record and re-syncing
/// is a no-op.
#[test]
fn scenario_auto_apply_converges() {
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    // B exists as a device but never edits; its sync is modelled by
    // sync_as_pure_adopter (empty clock), which doesn't take the Device handle.

    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
    let shared = reconcile(&a, None, X_BLOCK); // A canonical, no conflict copy

    // B is a pure adopter (empty clock).
    let b_state = convergence_helpers::sync_as_pure_adopter(&baseline, shared.folder(), 1_000);

    // Logical: shared folder contains exactly A's record, live.
    let state = decrypt_state(&baseline, shared.folder(), X_BLOCK);
    assert_eq!(state.len(), 1);
    assert_eq!(state[0].record_uuid, X_RECORD);
    assert!(!state[0].tombstone);

    // Quiescence on both devices.
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &b_state,
        1_001
    ));
    let a_state = device_post_edit_state(&baseline, &a);
    assert!(convergence_helpers::is_nothing_to_do(
        &baseline,
        shared.folder(),
        &a_state,
        1_002
    ));
}

/// A device's remembered sync state is its own post-edit manifest clock.
fn device_post_edit_state(baseline: &Baseline, device: &Device) -> secretary_core::sync::SyncState {
    secretary_core::sync::SyncState::new(
        baseline.open_manifest().vault_uuid,
        device.manifest_clock(),
    )
    .expect("SyncState")
}

/// Run a both-edit scenario in one ordering: `canonical` device's files
/// are canonical, `merger` device merges. Returns the converged logical
/// state of the named block.
fn run_both_edit_ordering(
    baseline: &Baseline,
    canonical: &Device,
    merger: &Device,
    policy: VetoPolicy,
    block_uuid: [u8; 16],
) -> Vec<LogicalRecord> {
    let shared = reconcile(canonical, Some(merger), block_uuid);
    let merger_state = sync_as_merger(baseline, shared.folder(), merger, policy, 1_000);
    let adopter_state = sync_as_adopter(baseline, shared.folder(), canonical, 1_001);
    assert!(convergence_helpers::is_nothing_to_do(
        baseline,
        shared.folder(),
        &merger_state,
        1_002
    ));
    assert!(convergence_helpers::is_nothing_to_do(
        baseline,
        shared.folder(),
        &adopter_state,
        1_003
    ));
    decrypt_state(baseline, shared.folder(), block_uuid)
}

/// Scenario 2 (concurrent disjoint): A edits X.f1, B edits X.f2 from a
/// shared seeded baseline. CRDT auto-merges both fields (no veto). The
/// converged record carries both fields (plus the seed field f0),
/// regardless of which device is canonical.
#[test]
fn scenario_concurrent_disjoint_fields_converges() {
    let baseline = Baseline::create();
    // Seed X so both devices edit the SAME record.
    let mut seed = Device::fork(&baseline, [0x00; 16], 0x55);
    seed.edit_text_field(X_BLOCK, X_RECORD, "f0", "seed", 10);
    let baseline = baseline_from_seeded(baseline, &seed);

    let edit = |canonical_first: bool| {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        a.edit_text_field(X_BLOCK, X_RECORD, "f1", "alice", 100);
        b.edit_text_field(X_BLOCK, X_RECORD, "f2", "bob", 101);
        if canonical_first {
            run_both_edit_ordering(&baseline, &a, &b, VetoPolicy::NoVetoExpected, X_BLOCK)
        } else {
            run_both_edit_ordering(&baseline, &b, &a, VetoPolicy::NoVetoExpected, X_BLOCK)
        }
    };

    let order_ab = edit(true);
    let order_ba = edit(false);

    // One logical record carrying both concurrent disjoint edits, auto-merged
    // by the field-union CRDT. (The seed field f0 is NOT retained: each device's
    // `edit_text_field` is a whole-record `save_block` overwrite, so a
    // single-field edit drops sibling fields on that device's own replica before
    // any sync — see the harness note in convergence_helpers/device.rs. The seed
    // exists only to give A and B a common-ancestor record UUID so they edit the
    // SAME record and stay mutually concurrent.)

    // Helper: assert every expected field name appears in the record's digest map.
    fn assert_has_fields(record: &convergence_helpers::LogicalRecord, expected: &[&str]) {
        for fname in expected {
            assert!(
                record.field_value_digests.iter().any(|(n, _)| n == fname),
                "missing field {fname}",
            );
        }
    }

    assert_eq!(order_ab.len(), 1);
    assert_eq!(
        order_ab[0].field_value_digests.len(),
        2,
        "expected exactly f1 and f2 (seed f0 is overwritten)"
    );
    assert_has_fields(&order_ab[0], &["f1", "f2"]);

    assert_eq!(order_ba.len(), 1);
    assert_eq!(
        order_ba[0].field_value_digests.len(),
        2,
        "expected exactly f1 and f2 (seed f0 is overwritten)"
    );
    assert_has_fields(&order_ba[0], &["f1", "f2"]);

    // Order-independence: both orderings converge to the same logical state.
    convergence_helpers::assert_converged(&order_ab, &order_ba);
}

/// Seed record X live in the X_BLOCK, then promote into a baseline whose
/// common-ancestor state already carries X. Both A and B fork from this
/// baseline so they edit / tombstone the SAME record X.
fn seed_baseline_with_live_x() -> Baseline {
    let baseline = Baseline::create();
    let mut seed = Device::fork(&baseline, [0x00; 16], 0x55);
    seed.edit_text_field(X_BLOCK, X_RECORD, "k", "seed", 10);
    baseline_from_seeded(baseline, &seed)
}

/// Scenario 4 — tombstone-veto, the ASYMMETRIC arm: `AcceptTombstone`.
///
/// Setup: A edits X live at now_ms=100; B tombstones X at now_ms=200.
/// Because the tombstone's death clock (`tombstoned_at_ms=200`) is
/// strictly later than A's edit (`last_mod=100`), the record-level death
/// clock in `conflict.rs::merge_record` makes the tombstone win the
/// merge **in either direction** (`decide_tombstone` → `*TombstoneWins`
/// when `T_d ≥ T_l`, symmetric over which side is local/remote).
///
/// So `AcceptTombstone` is **order-independent**: whether the live-editor
/// or the tombstoner is canonical, the merged record is X tombstoned.
/// - tombstoner is the merger (canonical=live-editor): a veto IS offered
///   (the veto pass in `prepare_merge` walks canonical *live* records),
///   and `AcceptTombstone` honours it → tombstoned.
/// - live-editor is the merger (canonical=tombstoner): NO veto is offered
///   (the canonical record is already tombstoned, so the veto pass
///   `continue`s past it), and the death clock auto-resolves to the
///   tombstone anyway.
///
/// Both orderings converge to X tombstoned.
#[test]
fn scenario_tombstone_veto_accept_delete_converges() {
    let baseline = seed_baseline_with_live_x();

    let run = |a_canonical: bool| {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0); // live editor
        let mut b = Device::fork(&baseline, B_UUID, 0xB0); // tombstoner
        a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice-live", 100);
        b.tombstone(X_BLOCK, X_RECORD, 200);
        if a_canonical {
            run_both_edit_ordering(&baseline, &a, &b, VetoPolicy::AcceptTombstone, X_BLOCK)
        } else {
            run_both_edit_ordering(&baseline, &b, &a, VetoPolicy::AcceptTombstone, X_BLOCK)
        }
    };

    let order_ab = run(true);
    let order_ba = run(false);

    for state in [&order_ab, &order_ba] {
        assert_eq!(state.len(), 1, "record X present (tombstoned)");
        assert_eq!(state[0].record_uuid, X_RECORD);
        assert!(
            state[0].tombstone,
            "AcceptTombstone (and the death clock) resolve X to tombstoned in both orderings",
        );
    }
    convergence_helpers::assert_converged(&order_ab, &order_ba);
}

/// Scenario 4 — tombstone-veto, the ASYMMETRIC arm: `KeepLocal`.
///
/// `KeepLocal` is a **per-ordering user override**, NOT order-independent.
/// The veto is offered ONLY to the replica whose sync observes the
/// canonical *live* record about to be deleted — `prepare_merge`'s veto
/// pass iterates `canonical_pt.records` and skips any record that is
/// already tombstoned on the canonical side
/// (`if canonical_rec.tombstone { continue }` in
/// `core/src/sync/prepare.rs`). So:
///
/// - **This ordering** (tombstoner is the MERGER, canonical=live-editor):
///   the canonical record X is LIVE → exactly one veto fires →
///   `KeepLocal` overrides the death clock and keeps X live. Both devices
///   converge to X live *within this ordering* (the merger commits X
///   live; the adopter then adopts that LUB; `run_both_edit_ordering`
///   asserts quiescence on both).
/// - The **mirrored** ordering (live-editor is the merger,
///   canonical=tombstoner) deterministically gets NO veto and the death
///   clock auto-resolves to the tombstone. That ordering is therefore
///   covered by `scenario_tombstone_veto_accept_delete_converges`'s
///   `a_canonical=false` arm, NOT here.
///
/// This asymmetry is the honest, correct behavior of the veto design:
/// `AcceptTombstone` (and the no-veto auto-resolution) is
/// order-independent; `KeepLocal` is intentionally order-dependent
/// because only the device offered the veto can override the death clock.
/// We therefore assert single-ordering convergence here and do NOT claim
/// order-independence for `KeepLocal`.
#[test]
fn scenario_tombstone_veto_keep_local_overrides_within_ordering() {
    let baseline = seed_baseline_with_live_x();

    let mut a = Device::fork(&baseline, A_UUID, 0xA0); // live editor — CANONICAL
    let mut b = Device::fork(&baseline, B_UUID, 0xB0); // tombstoner — MERGER (offered the veto)
    a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice-live", 100);
    b.tombstone(X_BLOCK, X_RECORD, 200);

    // canonical = a (live), merger = b (tombstoner). The veto IS offered
    // to the merger; KeepLocal overrides the death clock → X stays live.
    let state = run_both_edit_ordering(&baseline, &a, &b, VetoPolicy::KeepLocal, X_BLOCK);

    assert_eq!(state.len(), 1, "record X present (live)");
    assert_eq!(state[0].record_uuid, X_RECORD);
    assert!(
        !state[0].tombstone,
        "KeepLocal veto keeps X live; both devices converge to live within this ordering",
    );
}

/// Scenario 3 (LWW collision): A and B edit the SAME field of X with
/// different values and different last_mod. CRDT keeps the later
/// last_mod. The converged value digest equals the later writer's, in
/// both orderings.
#[test]
fn scenario_lww_collision_converges() {
    let baseline = Baseline::create();
    let mut seed = Device::fork(&baseline, [0x00; 16], 0x55);
    seed.edit_text_field(X_BLOCK, X_RECORD, "k", "seed", 10);
    let baseline = baseline_from_seeded(baseline, &seed);

    // Expected winning digest = the project hash of the later writer's plaintext.
    let later_value_digest = *secretary_core::crypto::hash::hash(b"bob-wins").as_bytes();

    let edit = |canonical_first: bool| {
        let mut a = Device::fork(&baseline, A_UUID, 0xA0);
        let mut b = Device::fork(&baseline, B_UUID, 0xB0);
        // B's last_mod (101) > A's (100), so LWW keeps B's "bob-wins".
        a.edit_text_field(X_BLOCK, X_RECORD, "k", "alice-loses", 100);
        b.edit_text_field(X_BLOCK, X_RECORD, "k", "bob-wins", 101);
        if canonical_first {
            run_both_edit_ordering(&baseline, &a, &b, VetoPolicy::NoVetoExpected, X_BLOCK)
        } else {
            run_both_edit_ordering(&baseline, &b, &a, VetoPolicy::NoVetoExpected, X_BLOCK)
        }
    };

    let order_ab = edit(true);
    let order_ba = edit(false);

    // The surviving "k" digest is the later writer's, in both orderings.
    for state in [&order_ab, &order_ba] {
        assert_eq!(state.len(), 1);
        assert_eq!(
            state[0].field_value_digests.len(),
            1,
            "only field k survives the LWW collision"
        );
        let digest = state[0]
            .field_value_digests
            .iter()
            .find(|(n, _)| n == "k")
            .map(|(_, d)| *d)
            .expect("field k present");
        assert_eq!(
            digest, later_value_digest,
            "LWW must keep the later writer's value"
        );
    }
    convergence_helpers::assert_converged(&order_ab, &order_ba);
}
