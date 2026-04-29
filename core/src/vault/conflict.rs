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

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use super::block::VectorClockEntry;
use super::record::{Record, RecordField, RecordFieldValue, UnknownValue};

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
// Per-record merge
// ---------------------------------------------------------------------------

/// A field where both sides held the field with differing values, and
/// the LWW resolution picked one. Surfaced as informational metadata so
/// a UI can offer the user explicit conflict resolution; the persisted
/// record in [`MergedRecord::merged`] always carries the LWW winner.
///
/// A [`FieldCollision`] is **not** serialised to disk in suite v1 — it
/// is a Rust API affordance only (`docs/crypto-design.md` §11.4).
#[derive(Debug, Clone, PartialEq)]
pub struct FieldCollision {
    /// The colliding field's name within its parent record.
    pub field_name: String,
    /// The LWW winner — also the value persisted in
    /// [`MergedRecord::merged`]'s `fields` map under `field_name`.
    pub winner: RecordField,
    /// The LWW loser — same `field_name`, different `value`. Preserved
    /// here so a UI can offer the user a choice between the two values.
    pub loser: RecordField,
}

/// The result of merging two [`Record`]s with the same `record_uuid`
/// per `docs/crypto-design.md` §11.
///
/// `merged` is the LWW-resolved record that an implementation persists.
/// `collisions` is an informational list of fields where both sides
/// held differing values — sorted ascending by `field_name` so the
/// equality `merge(a, b) == merge(b, a)` holds bit-identically.
///
/// A "concurrent value collision" (per §11.4) does **not** propagate
/// across multiple merges: once `merged` is persisted, downstream
/// merges see only the LWW winner, so `collisions` is meaningful only
/// for the current pairwise merge step. Associativity holds on
/// `.merged`; `.collisions` is a per-step informational view.
#[derive(Debug, Clone, PartialEq)]
pub struct MergedRecord {
    /// LWW-resolved record per §11. Persisted as-is.
    pub merged: Record,
    /// Informational list of collisions detected during this merge.
    /// Sorted ascending by `field_name`. Empty when no fields held
    /// differing values across the two sides.
    pub collisions: Vec<FieldCollision>,
}

/// Merge two records with the same `record_uuid` per §11.
///
/// **Precondition** (caller responsibility, not asserted at runtime):
/// `local.record_uuid == remote.record_uuid`. Calling with mismatched
/// UUIDs produces a nonsensical result; [`merge_block`](
/// super::merge_block) (added in a subsequent commit) iterates by UUID
/// and so never violates this.
///
/// Pure function. Total over well-formed inputs: returns a complete
/// [`MergedRecord`] with no error path.
pub fn merge_record(local: &Record, remote: &Record) -> MergedRecord {
    let tombstone_outcome = decide_tombstone(local, remote);
    let tombstone = matches!(
        tombstone_outcome,
        TombstoneOutcome::BothTombstoned | TombstoneOutcome::LocalTombstoneWins | TombstoneOutcome::RemoteTombstoneWins
    );

    let (merged_fields, collisions) = if tombstone {
        // §11.3: tombstoned records carry empty `fields` per §6.3.
        (BTreeMap::new(), Vec::new())
    } else {
        merge_fields_lww(&local.fields, &remote.fields)
    };

    let merged_record_type = merge_record_type(local, remote);
    let merged_tags = merge_tags(local, remote, tombstone_outcome);
    let merged_unknown = merge_unknown_map(&local.unknown, &remote.unknown);

    MergedRecord {
        merged: Record {
            record_uuid: local.record_uuid,
            record_type: merged_record_type,
            fields: merged_fields,
            tags: merged_tags,
            created_at_ms: local.created_at_ms.min(remote.created_at_ms),
            last_mod_ms: local.last_mod_ms.max(remote.last_mod_ms),
            tombstone,
            unknown: merged_unknown,
        },
        collisions,
    }
}

/// Outcome of the tombstone tie-break per §11.3. Captures who "won" so
/// downstream metadata picks (specifically `tags` per §11.3) can route
/// to the right side.
#[derive(Debug, Clone, Copy)]
enum TombstoneOutcome {
    /// Both sides live. Merged record is live; `tags` follow §11.1.
    BothLive,
    /// Both sides tombstoned. Merged record is tombstoned; `tags`
    /// follow §11.1 (greater `last_mod_ms` wins, set union on tie).
    BothTombstoned,
    /// Local is tombstoned, remote is live, and tombstone wins
    /// (`T_d ≥ T_l`). Merged record is tombstoned; `tags = local.tags`.
    LocalTombstoneWins,
    /// Mirror of [`Self::LocalTombstoneWins`].
    RemoteTombstoneWins,
    /// Local is tombstoned, remote is live, and **live** wins
    /// (`T_d < T_l`): the tombstone has been resurrected by a later
    /// edit on `remote`. Merged record is live; `tags = remote.tags`.
    LocalTombstoneLost,
    /// Mirror of [`Self::LocalTombstoneLost`].
    RemoteTombstoneLost,
}

fn decide_tombstone(local: &Record, remote: &Record) -> TombstoneOutcome {
    match (local.tombstone, remote.tombstone) {
        (false, false) => TombstoneOutcome::BothLive,
        (true, true) => TombstoneOutcome::BothTombstoned,
        (true, false) => {
            // §11.3: tombstone wins iff T_d ≥ T_l.
            if local.last_mod_ms >= remote.last_mod_ms {
                TombstoneOutcome::LocalTombstoneWins
            } else {
                TombstoneOutcome::LocalTombstoneLost
            }
        }
        (false, true) => {
            if remote.last_mod_ms >= local.last_mod_ms {
                TombstoneOutcome::RemoteTombstoneWins
            } else {
                TombstoneOutcome::RemoteTombstoneLost
            }
        }
    }
}

/// Per-field LWW with the §11 pseudocode rule: greater `last_mod` wins;
/// on `last_mod` tie, **smaller** `device_uuid` wins (matches the
/// pseudocode `lf.device_uuid < rf.device_uuid` predicate).
///
/// On a full tie (`last_mod` AND `device_uuid` both equal but `value`
/// differs) the merge picks the side with the lex-larger byte
/// representation of `(value-variant-tag, value-bytes)`. This is a
/// pathological corner case (a single device wrote two different values
/// at the same millisecond) and the rule's role is purely to keep the
/// merge total and deterministic. Well-formed inputs do not trigger it.
fn merge_fields_lww(
    l: &BTreeMap<String, RecordField>,
    r: &BTreeMap<String, RecordField>,
) -> (BTreeMap<String, RecordField>, Vec<FieldCollision>) {
    let mut out: BTreeMap<String, RecordField> = BTreeMap::new();
    let mut collisions: Vec<FieldCollision> = Vec::new();

    let all_keys: BTreeSet<&String> = l.keys().chain(r.keys()).collect();
    for key in all_keys {
        match (l.get(key), r.get(key)) {
            (Some(lf), Some(rf)) => {
                if lww_picks_local(lf, rf) {
                    if lf.value != rf.value {
                        collisions.push(FieldCollision {
                            field_name: key.clone(),
                            winner: lf.clone(),
                            loser: rf.clone(),
                        });
                    }
                    out.insert(key.clone(), lf.clone());
                } else {
                    if lf.value != rf.value {
                        collisions.push(FieldCollision {
                            field_name: key.clone(),
                            winner: rf.clone(),
                            loser: lf.clone(),
                        });
                    }
                    out.insert(key.clone(), rf.clone());
                }
            }
            (Some(lf), None) => {
                out.insert(key.clone(), lf.clone());
            }
            (None, Some(rf)) => {
                out.insert(key.clone(), rf.clone());
            }
            (None, None) => unreachable!("BTreeSet union excludes the absent-from-both case"),
        }
    }

    // The BTreeSet iteration is already sorted, so collisions are in
    // ascending field_name order without an explicit sort.
    (out, collisions)
}

/// True when the per-field LWW picks the local side over the remote
/// side, per the §11 pseudocode rule.
fn lww_picks_local(l: &RecordField, r: &RecordField) -> bool {
    match l.last_mod.cmp(&r.last_mod) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => match l.device_uuid.cmp(&r.device_uuid) {
            // Smaller device_uuid wins per the §11 pseudocode (`lf if
            // lf.device_uuid < rf.device_uuid else rf`).
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => {
                // Full tie. Lex-larger value bytes wins (deterministic
                // corner-case rule; see merge_fields_lww docs).
                value_lex_bytes(&l.value) >= value_lex_bytes(&r.value)
            }
        },
    }
}

/// Compute the lex-comparison bytes for a [`RecordFieldValue`].
///
/// Prefixes a one-byte variant tag (`0x00` for `Text`, `0x01` for
/// `Bytes`) so the same string-vs-bytes content cannot accidentally
/// compare equal across the two variants.
fn value_lex_bytes(v: &RecordFieldValue) -> Vec<u8> {
    match v {
        RecordFieldValue::Text(s) => {
            let mut out = Vec::with_capacity(1 + s.len());
            out.push(0x00);
            out.extend_from_slice(s.as_bytes());
            out
        }
        RecordFieldValue::Bytes(b) => {
            let mut out = Vec::with_capacity(1 + b.len());
            out.push(0x01);
            out.extend_from_slice(b);
            out
        }
    }
}

/// `record_type` LWW per §11.1: greater `last_mod_ms` wins; on tie,
/// lex-larger UTF-8 byte string wins.
fn merge_record_type(l: &Record, r: &Record) -> String {
    match l.last_mod_ms.cmp(&r.last_mod_ms) {
        Ordering::Greater => l.record_type.clone(),
        Ordering::Less => r.record_type.clone(),
        Ordering::Equal => {
            if l.record_type.as_bytes() >= r.record_type.as_bytes() {
                l.record_type.clone()
            } else {
                r.record_type.clone()
            }
        }
    }
}

/// `tags` merge per §11.1 with the §11.3 mixed-tombstone override:
/// greater `last_mod_ms` wins; on tie, the **set union** of both sides
/// is taken EXCEPT when one side is tombstoned and the other live, in
/// which case the tombstoning side's tags win (§11.3 override).
fn merge_tags(l: &Record, r: &Record, outcome: TombstoneOutcome) -> Vec<String> {
    match outcome {
        TombstoneOutcome::LocalTombstoneWins => l.tags.clone(),
        TombstoneOutcome::RemoteTombstoneWins => r.tags.clone(),
        TombstoneOutcome::LocalTombstoneLost => r.tags.clone(),
        TombstoneOutcome::RemoteTombstoneLost => l.tags.clone(),
        TombstoneOutcome::BothLive | TombstoneOutcome::BothTombstoned => {
            match l.last_mod_ms.cmp(&r.last_mod_ms) {
                Ordering::Greater => l.tags.clone(),
                Ordering::Less => r.tags.clone(),
                Ordering::Equal => {
                    // §11.1 set union, sorted lex.
                    let mut set: BTreeSet<String> = l.tags.iter().cloned().collect();
                    for tag in &r.tags {
                        set.insert(tag.clone());
                    }
                    set.into_iter().collect()
                }
            }
        }
    }
}

/// Per-key forward-compat unknown merge per §11.1 (record-level) and
/// §11.2 (block-level — same rule). A key present in only one side is
/// kept verbatim. A key present in both with differing values takes
/// the lex-larger canonical-CBOR-encoded value bytes.
fn merge_unknown_map(
    l: &BTreeMap<String, UnknownValue>,
    r: &BTreeMap<String, UnknownValue>,
) -> BTreeMap<String, UnknownValue> {
    let mut out: BTreeMap<String, UnknownValue> = BTreeMap::new();
    let all_keys: BTreeSet<&String> = l.keys().chain(r.keys()).collect();
    for key in all_keys {
        match (l.get(key), r.get(key)) {
            (Some(lv), Some(rv)) => {
                if lv == rv {
                    out.insert(key.clone(), lv.clone());
                } else {
                    let l_bytes = lv
                        .to_canonical_cbor()
                        .expect("ciborium serialize to Vec<u8> is structurally infallible");
                    let r_bytes = rv
                        .to_canonical_cbor()
                        .expect("ciborium serialize to Vec<u8> is structurally infallible");
                    if l_bytes >= r_bytes {
                        out.insert(key.clone(), lv.clone());
                    } else {
                        out.insert(key.clone(), rv.clone());
                    }
                }
            }
            (Some(lv), None) => {
                out.insert(key.clone(), lv.clone());
            }
            (None, Some(rv)) => {
                out.insert(key.clone(), rv.clone());
            }
            (None, None) => unreachable!("BTreeSet union excludes the absent-from-both case"),
        }
    }
    out
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

    // --- merge_record helpers -----------------------------------------

    fn rfield(value: RecordFieldValue, last_mod: u64, dev: u8) -> RecordField {
        RecordField {
            value,
            last_mod,
            device_uuid: [dev; 16],
            unknown: BTreeMap::new(),
        }
    }

    fn rec(record_uuid: [u8; 16]) -> Record {
        Record {
            record_uuid,
            record_type: "login".to_string(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: 1_000,
            last_mod_ms: 1_000,
            tombstone: false,
            unknown: BTreeMap::new(),
        }
    }

    // --- merge_record: basic field LWW --------------------------------

    #[test]
    fn merge_record_picks_field_with_greater_last_mod() {
        let mut a = rec([1; 16]);
        a.fields.insert(
            "username".to_string(),
            rfield(RecordFieldValue::Text("alice".into()), 100, 1),
        );
        a.last_mod_ms = 100;

        let mut b = rec([1; 16]);
        b.fields.insert(
            "username".to_string(),
            rfield(RecordFieldValue::Text("alice2".into()), 200, 2),
        );
        b.last_mod_ms = 200;

        let m = merge_record(&a, &b);
        assert_eq!(
            m.merged.fields["username"].value,
            RecordFieldValue::Text("alice2".into())
        );
        assert_eq!(m.merged.last_mod_ms, 200);
        assert_eq!(m.collisions.len(), 1);
        assert_eq!(m.collisions[0].field_name, "username");
        assert_eq!(
            m.collisions[0].winner.value,
            RecordFieldValue::Text("alice2".into())
        );
        assert_eq!(
            m.collisions[0].loser.value,
            RecordFieldValue::Text("alice".into())
        );
    }

    #[test]
    fn merge_record_field_tie_picks_smaller_device_uuid() {
        // Same last_mod, different device_uuid → smaller wins per §11
        // pseudocode (`lf if lf.device_uuid < rf.device_uuid else rf`).
        let mut a = rec([1; 16]);
        a.fields.insert(
            "f".to_string(),
            rfield(RecordFieldValue::Text("A".into()), 100, 5),
        );

        let mut b = rec([1; 16]);
        b.fields.insert(
            "f".to_string(),
            rfield(RecordFieldValue::Text("B".into()), 100, 2),
        );

        let m = merge_record(&a, &b);
        assert_eq!(
            m.merged.fields["f"].value,
            RecordFieldValue::Text("B".into()),
            "device_uuid 2 < 5, B wins"
        );
    }

    #[test]
    fn merge_record_no_collision_when_values_match() {
        let mut a = rec([1; 16]);
        a.fields.insert(
            "f".to_string(),
            rfield(RecordFieldValue::Text("same".into()), 100, 1),
        );

        let mut b = rec([1; 16]);
        b.fields.insert(
            "f".to_string(),
            rfield(RecordFieldValue::Text("same".into()), 200, 2),
        );

        let m = merge_record(&a, &b);
        assert!(m.collisions.is_empty(), "identical values do not collide");
    }

    #[test]
    fn merge_record_disjoint_fields_no_collisions() {
        let mut a = rec([1; 16]);
        a.fields.insert(
            "username".to_string(),
            rfield(RecordFieldValue::Text("alice".into()), 100, 1),
        );

        let mut b = rec([1; 16]);
        b.fields.insert(
            "password".to_string(),
            rfield(RecordFieldValue::Text("hunter2".into()), 200, 2),
        );

        let m = merge_record(&a, &b);
        assert_eq!(m.merged.fields.len(), 2);
        assert!(m.merged.fields.contains_key("username"));
        assert!(m.merged.fields.contains_key("password"));
        assert!(m.collisions.is_empty());
    }

    // --- merge_record: tombstone tie-break ----------------------------

    #[test]
    fn merge_record_tombstone_wins_on_tie() {
        // Both at last_mod_ms = 100, one tombstone, one live → tombstone
        // wins (§11.3). Merged record has empty fields.
        let mut a = rec([1; 16]);
        a.last_mod_ms = 100;
        a.tombstone = true;

        let mut b = rec([1; 16]);
        b.last_mod_ms = 100;
        b.fields.insert(
            "f".to_string(),
            rfield(RecordFieldValue::Text("v".into()), 100, 2),
        );

        let m = merge_record(&a, &b);
        assert!(m.merged.tombstone);
        assert!(m.merged.fields.is_empty());
        assert_eq!(m.merged.last_mod_ms, 100);
    }

    #[test]
    fn merge_record_live_resurrection_after_strictly_later_edit() {
        // Tombstone at last_mod_ms=5, live at last_mod_ms=9 → live wins.
        // Merged record is live with the live side's fields.
        let mut a = rec([1; 16]);
        a.last_mod_ms = 5;
        a.tombstone = true;

        let mut b = rec([1; 16]);
        b.last_mod_ms = 9;
        b.fields.insert(
            "f".to_string(),
            rfield(RecordFieldValue::Text("v".into()), 9, 2),
        );

        let m = merge_record(&a, &b);
        assert!(!m.merged.tombstone, "live edit after tombstone resurrects");
        assert_eq!(m.merged.last_mod_ms, 9);
        assert_eq!(
            m.merged.fields["f"].value,
            RecordFieldValue::Text("v".into())
        );
    }

    #[test]
    fn merge_record_both_tombstoned_stays_tombstoned() {
        let mut a = rec([1; 16]);
        a.last_mod_ms = 100;
        a.tombstone = true;
        let mut b = rec([1; 16]);
        b.last_mod_ms = 200;
        b.tombstone = true;
        let m = merge_record(&a, &b);
        assert!(m.merged.tombstone);
        assert_eq!(m.merged.last_mod_ms, 200);
        assert!(m.merged.fields.is_empty());
    }

    // --- merge_record: metadata -------------------------------------

    #[test]
    fn merge_record_created_at_ms_is_min() {
        let mut a = rec([1; 16]);
        a.created_at_ms = 50;
        let mut b = rec([1; 16]);
        b.created_at_ms = 100;
        let m = merge_record(&a, &b);
        assert_eq!(m.merged.created_at_ms, 50);
    }

    #[test]
    fn merge_record_last_mod_ms_is_max() {
        let mut a = rec([1; 16]);
        a.last_mod_ms = 50;
        let mut b = rec([1; 16]);
        b.last_mod_ms = 100;
        let m = merge_record(&a, &b);
        assert_eq!(m.merged.last_mod_ms, 100);
    }

    #[test]
    fn merge_record_tags_take_set_union_on_tie() {
        let mut a = rec([1; 16]);
        a.last_mod_ms = 100;
        a.tags = vec!["work".into(), "shared".into()];
        let mut b = rec([1; 16]);
        b.last_mod_ms = 100;
        b.tags = vec!["personal".into(), "shared".into()];
        let m = merge_record(&a, &b);
        assert_eq!(
            m.merged.tags,
            vec![
                "personal".to_string(),
                "shared".to_string(),
                "work".to_string()
            ],
            "set union sorted lex"
        );
    }

    #[test]
    fn merge_record_record_type_lex_larger_on_tie() {
        let mut a = rec([1; 16]);
        a.record_type = "abc".into();
        a.last_mod_ms = 100;
        let mut b = rec([1; 16]);
        b.record_type = "abd".into();
        b.last_mod_ms = 100;
        let m = merge_record(&a, &b);
        assert_eq!(m.merged.record_type, "abd", "abd > abc, abd wins on tie");
    }

    // --- merge_record: commutativity sanity --------------------------

    #[test]
    fn merge_record_commutative_basic() {
        // Hand-crafted example with two collisions and full metadata.
        let mut a = rec([7; 16]);
        a.record_type = "login".into();
        a.created_at_ms = 50;
        a.last_mod_ms = 200;
        a.tags = vec!["home".into()];
        a.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("alice".into()), 200, 1),
        );
        a.fields.insert(
            "p".to_string(),
            rfield(RecordFieldValue::Text("pass-a".into()), 100, 1),
        );

        let mut b = rec([7; 16]);
        b.record_type = "login".into();
        b.created_at_ms = 60;
        b.last_mod_ms = 300;
        b.tags = vec!["work".into()];
        b.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("ALICE".into()), 300, 2),
        );
        b.fields.insert(
            "p".to_string(),
            rfield(RecordFieldValue::Text("pass-b".into()), 200, 2),
        );

        let ab = merge_record(&a, &b);
        let ba = merge_record(&b, &a);
        assert_eq!(ab, ba, "merge_record is commutative");
    }

    #[test]
    fn merge_record_idempotent_basic() {
        let mut a = rec([3; 16]);
        a.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("alice".into()), 100, 1),
        );
        a.tags = vec!["x".into(), "y".into()];
        a.last_mod_ms = 100;
        let m = merge_record(&a, &a);
        assert_eq!(m.merged, a);
        assert!(m.collisions.is_empty(), "merge(a, a) yields no collisions");
    }
}
