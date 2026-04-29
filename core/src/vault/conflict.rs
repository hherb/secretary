//! Vector-clock CRDT primitives — pure functions, no I/O, no scheduling.
//!
//! This module ships the building blocks for `docs/crypto-design.md` §11's
//! merge algorithm:
//!
//! - [`ClockRelation`] — the four-valued relation between two vector
//!   clocks (`Equal`, `IncomingDominates`, `IncomingDominated`,
//!   `Concurrent`).
//! - [`clock_relation`] — compute the relation from two clocks. Used by
//!   the manifest §10 rollback check (an `IncomingDominated` relation is
//!   the rollback signal) and by the per-block merge primitive (added in
//!   a subsequent commit) to decide whether to dispatch a per-record
//!   merge or a no-op pick.
//! - [`merge_vector_clocks`] — component-wise max of two clocks, sorted
//!   ascending by `device_uuid` per §6.1's wire-format invariant. Pure;
//!   does **not** add `+1` for any merging device. Tick is a separate
//!   concern owned by the orchestrator layer.
//!
//! The record-level and block-level merge functions land in subsequent
//! commits and compose on top of these primitives.
//!
//! ## Design intent
//!
//! Per the design anchor at
//! `/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md`
//! (Definition-of-Done item #3), the merge is required to be
//! commutative, associative, and idempotent over random sequences of
//! edits. These vector-clock primitives are the foundational layer:
//!
//! - `merge_vector_clocks` is itself commutative (`max` is symmetric),
//!   associative, and idempotent.
//! - `clock_relation` is *anti-symmetric*: swapping arguments swaps
//!   `IncomingDominates` ↔ `IncomingDominated` and leaves `Equal` /
//!   `Concurrent` fixed.
//!
//! ## Scope boundary
//!
//! These primitives **do not** orchestrate — they don't watch files,
//! schedule merges, talk to a cloud provider, or detect divergence on
//! their own. That layer is Sub-project C in the ROADMAP. See
//! `secretary_next_session.md` Phase A.6 for the line drawn here.

use std::collections::BTreeMap;

use super::block::VectorClockEntry;

// ---------------------------------------------------------------------------
// Clock relation
// ---------------------------------------------------------------------------

/// The four-valued relation between two vector clocks.
///
/// Convention: the first argument to [`clock_relation`] is the "local"
/// clock; the second is the "incoming" clock (typically a remote replica
/// or a manifest under load). The variants are named from the perspective
/// of the **incoming** clock so callers reading manifest-load code
/// (`docs/vault-format.md` §4.3 + `docs/crypto-design.md` §10) can map
/// directly onto the rollback-resistance check:
///
/// - [`Equal`](Self::Equal) — accept (no state change).
/// - [`IncomingDominates`](Self::IncomingDominates) — accept and update
///   "highest seen".
/// - [`IncomingDominated`](Self::IncomingDominated) — reject as
///   rollback (or accept under explicit user override).
/// - [`Concurrent`](Self::Concurrent) — trigger merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockRelation {
    /// Both clocks are component-wise identical (same device set, same
    /// counters). Implies `merge_vector_clocks(a, b) == a == b`.
    Equal,
    /// `incoming` dominates `local`: every device's counter in
    /// `incoming` is ≥ the corresponding counter in `local` (treating
    /// absent device entries as `0`), and at least one is strictly
    /// greater. The incoming clock is "newer" than the local one in the
    /// happens-before partial order.
    IncomingDominates,
    /// `local` dominates `incoming` (mirror of [`IncomingDominates`]).
    /// In a manifest-load context this is the rollback signal.
    IncomingDominated,
    /// Neither dominates the other: there exists a device where
    /// `local`'s counter is strictly greater than `incoming`'s, and
    /// another device where `incoming`'s is strictly greater than
    /// `local`'s. The two histories have diverged and a merge is
    /// required to make progress.
    Concurrent,
}

/// Compute the [`ClockRelation`] between two vector clocks.
///
/// Treats missing device entries as `0`: a device that appears in only
/// one of the two clocks contributes a `≥ / >` for that side.
///
/// Pure function: both inputs are borrowed; no allocation beyond a
/// single per-device counter map.
///
/// ```
/// use secretary_core::vault::{clock_relation, ClockRelation, VectorClockEntry};
///
/// let a = vec![VectorClockEntry { device_uuid: [1; 16], counter: 3 }];
/// let b = vec![VectorClockEntry { device_uuid: [1; 16], counter: 5 }];
/// assert_eq!(clock_relation(&a, &b), ClockRelation::IncomingDominates);
/// ```
pub fn clock_relation(local: &[VectorClockEntry], incoming: &[VectorClockEntry]) -> ClockRelation {
    let mut local_greater_anywhere = false;
    let mut incoming_greater_anywhere = false;

    let mut all_devices: BTreeMap<[u8; 16], (u64, u64)> = BTreeMap::new();
    for entry in local {
        all_devices.entry(entry.device_uuid).or_insert((0, 0)).0 = entry.counter;
    }
    for entry in incoming {
        all_devices.entry(entry.device_uuid).or_insert((0, 0)).1 = entry.counter;
    }

    for &(l, i) in all_devices.values() {
        match l.cmp(&i) {
            std::cmp::Ordering::Greater => local_greater_anywhere = true,
            std::cmp::Ordering::Less => incoming_greater_anywhere = true,
            std::cmp::Ordering::Equal => {}
        }
        if local_greater_anywhere && incoming_greater_anywhere {
            return ClockRelation::Concurrent;
        }
    }

    match (local_greater_anywhere, incoming_greater_anywhere) {
        (false, false) => ClockRelation::Equal,
        (false, true) => ClockRelation::IncomingDominates,
        (true, false) => ClockRelation::IncomingDominated,
        (true, true) => ClockRelation::Concurrent,
    }
}

// ---------------------------------------------------------------------------
// Vector-clock merge
// ---------------------------------------------------------------------------

/// Component-wise maximum of two vector clocks, sorted ascending by
/// `device_uuid` per `docs/vault-format.md` §6.1.
///
/// Pure function. Does **not** apply `+1` for any "merging device" —
/// that is an orchestrator concern (see
/// [`super::orchestrators`]'s private `tick_clock`). The merge primitive
/// here only computes the join in the lattice of vector clocks.
///
/// Properties (proved by `core/tests/proptest.rs` in a subsequent
/// commit):
///
/// - **Commutative**: `merge_vector_clocks(a, b) == merge_vector_clocks(b, a)`.
/// - **Associative**: `merge(merge(a, b), c) == merge(a, merge(b, c))`.
/// - **Idempotent**: `merge(a, a) == a` (after the canonical sort).
///
/// ```
/// use secretary_core::vault::{merge_vector_clocks, VectorClockEntry};
///
/// let a = vec![VectorClockEntry { device_uuid: [1; 16], counter: 3 }];
/// let b = vec![VectorClockEntry { device_uuid: [2; 16], counter: 7 }];
/// let merged = merge_vector_clocks(&a, &b);
/// assert_eq!(merged.len(), 2);
/// assert_eq!(merged[0].device_uuid, [1; 16]);
/// assert_eq!(merged[0].counter, 3);
/// assert_eq!(merged[1].device_uuid, [2; 16]);
/// assert_eq!(merged[1].counter, 7);
/// ```
pub fn merge_vector_clocks(
    a: &[VectorClockEntry],
    b: &[VectorClockEntry],
) -> Vec<VectorClockEntry> {
    let mut max_counters: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    for entry in a.iter().chain(b.iter()) {
        let cell = max_counters.entry(entry.device_uuid).or_insert(0);
        if entry.counter > *cell {
            *cell = entry.counter;
        }
    }
    max_counters
        .into_iter()
        .map(|(device_uuid, counter)| VectorClockEntry {
            device_uuid,
            counter,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(d: u8, c: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [d; 16],
            counter: c,
        }
    }

    // --- clock_relation ------------------------------------------------

    #[test]
    fn equal_empty_clocks() {
        assert_eq!(clock_relation(&[], &[]), ClockRelation::Equal);
    }

    #[test]
    fn equal_identical_clocks() {
        let c = vec![entry(1, 3), entry(2, 5)];
        assert_eq!(clock_relation(&c, &c), ClockRelation::Equal);
    }

    #[test]
    fn incoming_dominates_higher_counter() {
        let local = vec![entry(1, 3)];
        let incoming = vec![entry(1, 5)];
        assert_eq!(
            clock_relation(&local, &incoming),
            ClockRelation::IncomingDominates
        );
    }

    #[test]
    fn incoming_dominates_extra_device() {
        // Local has only device 1; incoming has device 1 (same counter)
        // and an additional device 2 (counter 7). Missing-device-as-zero
        // makes this an `IncomingDominates`.
        let local = vec![entry(1, 3)];
        let incoming = vec![entry(1, 3), entry(2, 7)];
        assert_eq!(
            clock_relation(&local, &incoming),
            ClockRelation::IncomingDominates
        );
    }

    #[test]
    fn incoming_dominated_lower_counter() {
        let local = vec![entry(1, 5)];
        let incoming = vec![entry(1, 3)];
        assert_eq!(
            clock_relation(&local, &incoming),
            ClockRelation::IncomingDominated
        );
    }

    #[test]
    fn incoming_dominated_extra_device_locally() {
        // Mirror of the IncomingDominates extra-device case.
        let local = vec![entry(1, 3), entry(2, 7)];
        let incoming = vec![entry(1, 3)];
        assert_eq!(
            clock_relation(&local, &incoming),
            ClockRelation::IncomingDominated
        );
    }

    #[test]
    fn concurrent_when_each_side_has_a_higher_counter() {
        let local = vec![entry(1, 5), entry(2, 3)];
        let incoming = vec![entry(1, 3), entry(2, 5)];
        assert_eq!(
            clock_relation(&local, &incoming),
            ClockRelation::Concurrent
        );
    }

    #[test]
    fn concurrent_when_each_side_has_a_unique_device() {
        let local = vec![entry(1, 3)];
        let incoming = vec![entry(2, 5)];
        assert_eq!(
            clock_relation(&local, &incoming),
            ClockRelation::Concurrent
        );
    }

    #[test]
    fn relation_is_anti_symmetric() {
        // Swapping arguments swaps Dominates ↔ Dominated, leaves
        // Equal / Concurrent fixed.
        let a = vec![entry(1, 3)];
        let b = vec![entry(1, 5)];
        assert_eq!(clock_relation(&a, &b), ClockRelation::IncomingDominates);
        assert_eq!(clock_relation(&b, &a), ClockRelation::IncomingDominated);

        let c = vec![entry(1, 5), entry(2, 3)];
        let d = vec![entry(1, 3), entry(2, 5)];
        assert_eq!(clock_relation(&c, &d), ClockRelation::Concurrent);
        assert_eq!(clock_relation(&d, &c), ClockRelation::Concurrent);
    }

    // --- merge_vector_clocks -------------------------------------------

    #[test]
    fn merge_empty_clocks_yields_empty() {
        assert_eq!(merge_vector_clocks(&[], &[]), Vec::new());
    }

    #[test]
    fn merge_takes_max_per_device() {
        let a = vec![entry(1, 3), entry(2, 9)];
        let b = vec![entry(1, 5), entry(2, 7)];
        let merged = merge_vector_clocks(&a, &b);
        assert_eq!(merged, vec![entry(1, 5), entry(2, 9)]);
    }

    #[test]
    fn merge_unions_devices() {
        let a = vec![entry(1, 3)];
        let b = vec![entry(2, 5)];
        let merged = merge_vector_clocks(&a, &b);
        assert_eq!(merged, vec![entry(1, 3), entry(2, 5)]);
    }

    #[test]
    fn merge_is_sorted_ascending_by_device_uuid() {
        // Inputs intentionally unsorted; output must be sorted.
        let a = vec![entry(5, 1), entry(2, 1), entry(8, 1)];
        let b = vec![entry(3, 1), entry(1, 1)];
        let merged = merge_vector_clocks(&a, &b);
        let device_uuids: Vec<[u8; 16]> = merged.iter().map(|e| e.device_uuid).collect();
        let mut sorted = device_uuids.clone();
        sorted.sort();
        assert_eq!(device_uuids, sorted);
        assert_eq!(merged.len(), 5);
    }

    #[test]
    fn merge_idempotent() {
        let a = vec![entry(1, 3), entry(2, 5)];
        // Output may be re-sorted vs input; sort the input the same way
        // before comparing so we test "merge yields the canonical form".
        let mut a_sorted = a.clone();
        a_sorted.sort_by(|x, y| x.device_uuid.cmp(&y.device_uuid));
        assert_eq!(merge_vector_clocks(&a, &a), a_sorted);
    }

    #[test]
    fn merge_commutative() {
        let a = vec![entry(1, 3), entry(2, 9)];
        let b = vec![entry(1, 5), entry(2, 7)];
        assert_eq!(merge_vector_clocks(&a, &b), merge_vector_clocks(&b, &a));
    }

    #[test]
    fn merge_associative() {
        let a = vec![entry(1, 3), entry(2, 1)];
        let b = vec![entry(1, 5), entry(3, 4)];
        let c = vec![entry(2, 8), entry(3, 2)];
        let left = merge_vector_clocks(&merge_vector_clocks(&a, &b), &c);
        let right = merge_vector_clocks(&a, &merge_vector_clocks(&b, &c));
        assert_eq!(left, right);
    }
}
