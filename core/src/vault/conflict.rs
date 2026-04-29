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

use super::block::{BlockPlaintext, VectorClockEntry};
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
    ///
    /// **Interaction with the §11.3 staleness filter.** A field is
    /// reported only when both sides held the field with differing
    /// values *and* the LWW winner survived the staleness filter
    /// (i.e., its `last_mod > merged.tombstoned_at_ms`, or the
    /// merged record's death clock is zero). A field whose LWW
    /// winner would have been dropped by the filter is omitted from
    /// `collisions` rather than reported as a "phantom collision":
    /// the merged record carries no value for that field, so a UI
    /// has nothing to surface to the user. This is intentional —
    /// stale collisions belong to a deleted prior life of the
    /// record and are not a live conflict.
    pub collisions: Vec<FieldCollision>,
}

/// Merge two records with the same `record_uuid` per §11.
///
/// **Precondition** (caller responsibility, not asserted at runtime):
/// `local.record_uuid == remote.record_uuid`. Calling with mismatched
/// UUIDs produces a nonsensical result; [`merge_block`] iterates by
/// UUID and so never violates this.
///
/// **Idempotence precondition.** `merge(a, a) == a` holds bit-
/// identically only when `a` satisfies the §11.5 well-formedness
/// invariants: tags sorted+deduped; `last_mod_ms ≥ max(field.last_mod)`;
/// `tombstoned_at_ms ≤ last_mod_ms`; equality between
/// `tombstoned_at_ms` and `last_mod_ms` when `tombstone == true`;
/// `fields` empty when `tombstone == true`. Inputs that violate any
/// of these are still merged to a deterministic well-formed result
/// (the merge canonicalises opportunistically — see the defensive
/// clamp below for the death-clock invariant), but `merge(a, a)` may
/// produce a strictly *more* canonical record than `a` itself.
///
/// **Defense against malformed inputs.** A hostile sync peer could
/// in principle hand us a record violating §11.5's
/// `tombstoned_at_ms ≤ last_mod_ms` invariant in either direction:
///
/// * Tombstoned with `tombstoned_at_ms < last_mod_ms` (e.g.,
///   `tombstone = true, tombstoned_at_ms = 0`) — would suppress the
///   death clock's advance and let pre-tombstone stale fields slip
///   through the §11.3 staleness filter on a third replica.
/// * Live with `tombstoned_at_ms > last_mod_ms` — would inflate the
///   merged death clock and drop legitimate fields on the honest
///   side. With `tombstoned_at_ms = u64::MAX`, the merged death
///   clock would clamp every field with `last_mod < u64::MAX`,
///   wiping the merged record's fields while keeping it live —
///   a deniable data-loss attack.
///
/// To defend against both, [`merge_record`] canonicalises each
/// input's `tombstoned_at_ms` per §11.5 before computing the
/// lattice join: tombstoned inputs are forced to
/// `tombstoned_at_ms == last_mod_ms`, live inputs are clamped to
/// `tombstoned_at_ms ≤ last_mod_ms`. On well-formed inputs (where
/// the invariant already holds) the clamp is a no-op. See
/// [`clamp_death_clock`] for the helper.
///
/// Pure function. Total over all `Record` pairs that share a
/// `record_uuid`: returns a complete [`MergedRecord`] with no error
/// path.
pub fn merge_record(local: &Record, remote: &Record) -> MergedRecord {
    let tombstone_outcome = decide_tombstone(local, remote);
    let tombstone = matches!(
        tombstone_outcome,
        TombstoneOutcome::BothTombstoned
            | TombstoneOutcome::LocalTombstoneWins
            | TombstoneOutcome::RemoteTombstoneWins
    );

    // Defensive clamp: enforce the §11.5 invariants
    // `tombstoned_at_ms ≤ last_mod_ms` (always) and
    // `tombstone == true ⇒ tombstoned_at_ms == last_mod_ms` on each
    // input before the lattice join. Two malformations to defend
    // against:
    //
    // * Tombstoned input with `tombstoned_at_ms < last_mod_ms`
    //   (e.g., `tombstone = true, tombstoned_at_ms = 0`): would
    //   suppress the death clock's advance, letting pre-tombstone
    //   stale fields slip through the §11.3 staleness filter.
    // * Live input with `tombstoned_at_ms > last_mod_ms`: would inflate
    //   the merged death clock, dropping legitimate fields on the
    //   honest side. With `tombstoned_at_ms = u64::MAX` the merged
    //   death clock would clamp every field with `last_mod < u64::MAX`,
    //   wiping the merged record's fields while keeping it live —
    //   a deniable data-loss attack from a hostile sync peer.
    //
    // The clamp restores `tombstoned_at_ms ≤ last_mod_ms` (and
    // equality on tombstoned inputs) as a precondition of the join.
    // No-op on well-formed inputs.
    let local_tombstoned_at_ms = clamp_death_clock(local);
    let remote_tombstoned_at_ms = clamp_death_clock(remote);
    // The death clock — `merged.tombstoned_at_ms` per §11.3. Lattice
    // join on `max`: itself a CRDT (commutative, associative,
    // idempotent), so propagation is correct independent of the
    // staleness filter below.
    let merged_tombstoned_at_ms = local_tombstoned_at_ms.max(remote_tombstoned_at_ms);

    let (merged_fields, collisions) = if tombstone {
        // §11.3: a tombstoned merged record carries empty `fields`
        // regardless of either input's `fields` (which may be
        // non-empty per §6.3's "kept-for-undelete" allowance — the
        // staleness filter would clear them anyway, so we short-circuit
        // here for clarity).
        (BTreeMap::new(), Vec::new())
    } else {
        // §11.3 staleness filter, applied uniformly to the field
        // union: a field with `last_mod ≤ merged_tombstoned_at_ms`
        // was edited at or before an observed tombstone and is dead.
        // This is what makes the merge associative under arbitrary
        // tombstone histories.
        merge_fields_with_staleness(&local.fields, &remote.fields, merged_tombstoned_at_ms)
    };

    // §11.3 identity-metadata override: on the tombstoning-wins
    // outcomes, the merged record's record_type / tags / record-level
    // `unknown` come wholesale from the tombstoning side. The override
    // exists so a UI surfacing a tombstoned record (trash bin,
    // undelete prompt, audit log) reflects the deleter's view of the
    // record — not a concurrent edit they never saw, and not an
    // adversarial sync peer's same-millisecond identity flip. For
    // every other outcome (BothLive, BothTombstoned, both `*Lost`
    // outcomes), §11.1's per-field rules apply via the helpers below.
    let merged_record_type = match tombstone_outcome {
        TombstoneOutcome::LocalTombstoneWins => local.record_type.clone(),
        TombstoneOutcome::RemoteTombstoneWins => remote.record_type.clone(),
        _ => merge_record_type(local, remote),
    };
    let merged_tags = merge_tags(local, remote, tombstone_outcome);
    let merged_unknown = match tombstone_outcome {
        TombstoneOutcome::LocalTombstoneWins => local.unknown.clone(),
        TombstoneOutcome::RemoteTombstoneWins => remote.unknown.clone(),
        _ => merge_unknown_map(&local.unknown, &remote.unknown),
    };

    MergedRecord {
        merged: Record {
            record_uuid: local.record_uuid,
            record_type: merged_record_type,
            fields: merged_fields,
            tags: merged_tags,
            created_at_ms: local.created_at_ms.min(remote.created_at_ms),
            last_mod_ms: local.last_mod_ms.max(remote.last_mod_ms),
            tombstone,
            tombstoned_at_ms: merged_tombstoned_at_ms,
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

/// Canonicalise a record's `tombstoned_at_ms` to the §11.5 invariant
/// before the lattice join in [`merge_record`].
///
/// Returns `tombstoned_at_ms` clamped to `[0, last_mod_ms]`. For
/// tombstoned inputs (`tombstone == true`), additionally enforces
/// equality with `last_mod_ms` per §11.5: a currently-tombstoned
/// record was tombstoned at its most recent edit. The two clamps
/// collapse to the same `last_mod_ms` value on tombstoned inputs.
///
/// This is the input-canonicalisation step the merge needs to be
/// total over malformed inputs without violating well-formedness on
/// the output. See [`merge_record`]'s "Defense against malformed
/// inputs" section for the threat-model rationale.
fn clamp_death_clock(record: &Record) -> u64 {
    if record.tombstone {
        // §11.5: tombstone == true ⇒ tombstoned_at_ms == last_mod_ms.
        // The lattice-join semantics on the inputs reduce to picking
        // last_mod_ms regardless of whether the input claimed a
        // larger or smaller death clock.
        record.last_mod_ms
    } else {
        // §11.5: tombstoned_at_ms ≤ last_mod_ms always, even on live
        // records. A live record's death clock is the high-water
        // mark of every observed prior tombstone; the invariant
        // requires it lies in `[0, last_mod_ms]`.
        record.tombstoned_at_ms.min(record.last_mod_ms)
    }
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

/// Per-field LWW with §11.3 staleness filter applied uniformly.
///
/// Per-field LWW per the §11 pseudocode: greater `last_mod` wins; on
/// `last_mod` tie, **smaller** `device_uuid` wins (matches the
/// pseudocode `lf.device_uuid < rf.device_uuid` predicate). On a full
/// tie (`last_mod` AND `device_uuid` both equal but `value` differs)
/// the merge picks the side with the lex-larger byte representation
/// of `(value-variant-tag, value-bytes)` — a pathological corner-case
/// rule purely to keep the merge total and deterministic.
///
/// **Staleness filter (§11.3).** Any field with
/// `field.last_mod ≤ death_clock` was edited at or before an observed
/// tombstone and is dropped from the merged record. The filter
/// applies uniformly, before LWW evaluation: a side's field that is
/// stale on its own does not participate in collision detection. The
/// filter is what makes the merge associative under arbitrary
/// tombstone histories — a field that survives a tombstone in one
/// merge ordering survives it in every other ordering, because the
/// death clock propagates across merges via `max`.
fn merge_fields_with_staleness(
    l: &BTreeMap<String, RecordField>,
    r: &BTreeMap<String, RecordField>,
    death_clock: u64,
) -> (BTreeMap<String, RecordField>, Vec<FieldCollision>) {
    let mut out: BTreeMap<String, RecordField> = BTreeMap::new();
    let mut collisions: Vec<FieldCollision> = Vec::new();

    let all_keys: BTreeSet<&String> = l.keys().chain(r.keys()).collect();
    for key in all_keys {
        // `tombstoned_at_ms = 0` is the sentinel for "this record has
        // never been part of a tombstone observation" — there is no
        // before-tombstone era to filter against. With no death-clock
        // event, every present field is alive regardless of `last_mod`
        // (including `last_mod = 0`, which keeps `merge(a, a) == a`
        // idempotent on records carrying epoch-0 timestamps).
        let alive = |f: &&RecordField| death_clock == 0 || f.last_mod > death_clock;
        let lf = l.get(key).filter(alive);
        let rf = r.get(key).filter(alive);
        match (lf, rf) {
            (None, None) => {
                // Both absent or both stale. Nothing alive to keep.
            }
            (Some(lf), None) => {
                out.insert(key.clone(), lf.clone());
            }
            (None, Some(rf)) => {
                out.insert(key.clone(), rf.clone());
            }
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
///
/// Output is always sorted+deduped (§11.5 well-formedness invariant).
/// Even on the LWW-clone branches, the merge canonicalises the chosen
/// side's tags on output so that `merge_record(merged, merged)` is a
/// fixed point — independent of whether the chosen side's tags were
/// already canonical. Without this canonicalisation, a record carrying
/// non-canonical tags through an LWW-clone branch would re-order under
/// self-merge (the tie path's `BTreeSet` would canonicalise then),
/// breaking idempotence on the merge output and the
/// "canonicalises opportunistically" claim of §11.5.
fn merge_tags(l: &Record, r: &Record, outcome: TombstoneOutcome) -> Vec<String> {
    let source: &[String] = match outcome {
        TombstoneOutcome::LocalTombstoneWins | TombstoneOutcome::RemoteTombstoneLost => &l.tags,
        TombstoneOutcome::RemoteTombstoneWins | TombstoneOutcome::LocalTombstoneLost => &r.tags,
        TombstoneOutcome::BothLive | TombstoneOutcome::BothTombstoned => {
            match l.last_mod_ms.cmp(&r.last_mod_ms) {
                Ordering::Greater => &l.tags,
                Ordering::Less => &r.tags,
                Ordering::Equal => {
                    // §11.1 set union of both sides on tie.
                    let set: BTreeSet<String> =
                        l.tags.iter().chain(r.tags.iter()).cloned().collect();
                    return set.into_iter().collect();
                }
            }
        }
    };
    // Canonicalise the chosen side's tags (sort + dedup) on output.
    let set: BTreeSet<String> = source.iter().cloned().collect();
    set.into_iter().collect()
}

/// Per-key forward-compat unknown merge per §11.1 (record-level) and
/// §11.2 (block-level — same rule). A key present in only one side is
/// kept verbatim. A key present in both with differing values takes
/// the lex-larger canonical-CBOR-encoded value bytes.
///
/// The `to_canonical_cbor()` calls on the collision branch use
/// [`Result::expect`] because the chain is structurally infallible:
///
/// 1. Every [`UnknownValue`] is constructed via
///    [`UnknownValue::from_canonical_cbor`], which calls
///    `reject_floats_and_tags` — so `UnknownValue.0` is a
///    [`ciborium::Value`] drawn from the `{Bytes, Bool, Text, Null,
///    Integer, Array, Map}` subset, recursively float-and-tag-free.
/// 2. ciborium 0.2's `Serialize` impl on `Value` only synthesises an
///    `Error::Value("expected tag")` while encoding `Value::Tag`,
///    which (1) excludes by construction. The other variants delegate
///    to typed `serialize_*` methods that propagate writer errors only.
/// 3. The writer is `&mut Vec<u8>`. With ciborium-io's std-feature
///    blanket impl, its `write_all` is `<Vec<u8> as
///    std::io::Write>::write_all`, which calls `extend_from_slice` and
///    always returns `Ok(())` (Vec growth panics on OOM, never
///    `Err`s).
///
/// Combined: serialising a v1-canonical [`UnknownValue`] to a `Vec<u8>`
/// has no reachable error path, so `.expect()` here cannot fire on any
/// value [`merge_unknown_map`] is called with.
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
                    // See module-level rationale above: serialising a
                    // v1-canonical UnknownValue to Vec<u8> has no
                    // reachable error path (Value subset is float/tag-
                    // free; Vec<u8> writer never errs).
                    let l_bytes = lv
                        .to_canonical_cbor()
                        .expect("UnknownValue is float/tag-free; Vec<u8> writer is infallible");
                    let r_bytes = rv
                        .to_canonical_cbor()
                        .expect("UnknownValue is float/tag-free; Vec<u8> writer is infallible");
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
// Per-block merge
// ---------------------------------------------------------------------------

/// Errors emitted by [`merge_block`]. A typed surface so callers can
/// pattern-match on the failure mode rather than parsing strings.
#[derive(Debug, thiserror::Error)]
pub enum ConflictError {
    /// [`merge_block`] called with two blocks whose `block_uuid` fields
    /// differ. Per `docs/crypto-design.md` §11.2 a `block_uuid`
    /// mismatch is a programmer error (callers should iterate the
    /// manifest's `BlockEntry` table by UUID and only call merge_block
    /// on matching UUIDs), not a mergeable conflict.
    #[error("block_uuid mismatch: local has {local:?}, remote has {remote:?}")]
    BlockUuidMismatch {
        local: [u8; 16],
        remote: [u8; 16],
    },
    /// A vector-clock per-device counter would overflow `u64::MAX` when
    /// the merging device's component is incremented. Mirror of
    /// [`super::VaultError::ClockOverflow`] so the merge primitive can
    /// stay layer-typed without depending on `VaultError`. Practical
    /// reachability is ~10¹¹ years at one merge per nanosecond; the
    /// typed surface keeps the invariant explicit.
    #[error("vector-clock overflow on device {device_uuid:?}")]
    ClockOverflow { device_uuid: [u8; 16] },
}

/// A record where the per-record merge surfaced one or more
/// [`FieldCollision`]s. The per-record LWW winner is already in the
/// merged block plaintext; this struct is the informational view the
/// caller can hand to a UI for explicit conflict resolution.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordCollision {
    /// The record whose merge produced collisions.
    pub record_uuid: [u8; 16],
    /// Field-level collisions for this record. Sorted ascending by
    /// `field_name` (inherited from [`FieldCollision`]'s ordering).
    pub field_collisions: Vec<FieldCollision>,
}

/// The result of merging two block plaintexts.
///
/// `merged` and `vector_clock` are the persisted outputs (caller writes
/// these to disk via the orchestrator layer). `relation` records which
/// branch [`merge_block`] took so callers can introspect the merge.
/// `collisions` is the informational per-record collision list; sorted
/// ascending by `record_uuid`. Empty when `relation` is not
/// [`ClockRelation::Concurrent`] (no per-record merge happens for the
/// other relations — the dominant block is adopted as-is).
#[derive(Debug, Clone, PartialEq)]
pub struct MergedBlock {
    /// Merged plaintext. For non-Concurrent relations this is a clone
    /// of the dominant side (or `local` for `Equal`). For Concurrent
    /// relations this is the per-record merge output.
    pub merged: BlockPlaintext,
    /// Merged vector clock. For non-Concurrent relations this is the
    /// dominant side's clock unchanged. For Concurrent relations this
    /// is `merge_vector_clocks(local_clock, remote_clock)` with `+1`
    /// applied to `merging_device`'s component (a fresh entry inserted
    /// when the merging device has none).
    pub vector_clock: Vec<VectorClockEntry>,
    /// Which branch the merge took.
    pub relation: ClockRelation,
    /// Per-record collisions encountered during a Concurrent merge.
    /// Empty for the other relations.
    pub collisions: Vec<RecordCollision>,
}

/// Top-level per-block merge primitive (`docs/crypto-design.md` §11).
///
/// Inspects the [`ClockRelation`] between `local_clock` and
/// `remote_clock` and dispatches:
///
/// - [`Equal`](ClockRelation::Equal) — return `local` and
///   `local_clock` unchanged.
/// - [`IncomingDominates`](ClockRelation::IncomingDominates) — return
///   `remote` and `remote_clock` unchanged. The remote replica
///   captures all of local's history plus more.
/// - [`IncomingDominated`](ClockRelation::IncomingDominated) — return
///   `local` and `local_clock` unchanged. Mirror of the above.
/// - [`Concurrent`](ClockRelation::Concurrent) — run the per-record
///   union + per-record merge per §11; return a freshly-constructed
///   block plaintext, a vector clock equal to
///   `merge_vector_clocks(local_clock, remote_clock)` with `+1`
///   applied to `merging_device`, and the per-record collision list.
///
/// **Precondition** — `local.block_uuid == remote.block_uuid`. A
/// mismatch is surfaced as [`ConflictError::BlockUuidMismatch`] so the
/// caller can route a programmer error distinctly from a merge
/// outcome.
///
/// Pure function (no I/O, no `unsafe`). The only error path is
/// `BlockUuidMismatch` plus the `ClockOverflow` corner case during the
/// Concurrent branch's `+1` tick.
pub fn merge_block(
    local: &BlockPlaintext,
    local_clock: &[VectorClockEntry],
    remote: &BlockPlaintext,
    remote_clock: &[VectorClockEntry],
    merging_device: [u8; 16],
) -> Result<MergedBlock, ConflictError> {
    if local.block_uuid != remote.block_uuid {
        return Err(ConflictError::BlockUuidMismatch {
            local: local.block_uuid,
            remote: remote.block_uuid,
        });
    }

    let relation = clock_relation(local_clock, remote_clock);

    match relation {
        ClockRelation::Equal => Ok(MergedBlock {
            merged: local.clone(),
            vector_clock: local_clock.to_vec(),
            relation,
            collisions: Vec::new(),
        }),
        ClockRelation::IncomingDominates => Ok(MergedBlock {
            merged: remote.clone(),
            vector_clock: remote_clock.to_vec(),
            relation,
            collisions: Vec::new(),
        }),
        ClockRelation::IncomingDominated => Ok(MergedBlock {
            merged: local.clone(),
            vector_clock: local_clock.to_vec(),
            relation,
            collisions: Vec::new(),
        }),
        ClockRelation::Concurrent => {
            let (merged_pt, collisions) = concurrent_merge_plaintext(local, remote);
            let max_clock = merge_vector_clocks(local_clock, remote_clock);
            let bumped = tick_for_device(max_clock, merging_device)?;
            Ok(MergedBlock {
                merged: merged_pt,
                vector_clock: bumped,
                relation,
                collisions,
            })
        }
    }
}

/// Per-record union + per-record merge for the Concurrent branch of
/// [`merge_block`]. Records emerge sorted ascending by `record_uuid`
/// for canonical determinism.
fn concurrent_merge_plaintext(
    local: &BlockPlaintext,
    remote: &BlockPlaintext,
) -> (BlockPlaintext, Vec<RecordCollision>) {
    let mut local_lookup: BTreeMap<[u8; 16], &Record> = BTreeMap::new();
    let mut remote_lookup: BTreeMap<[u8; 16], &Record> = BTreeMap::new();
    for r in &local.records {
        local_lookup.insert(r.record_uuid, r);
    }
    for r in &remote.records {
        remote_lookup.insert(r.record_uuid, r);
    }

    let all_uuids: BTreeSet<[u8; 16]> = local_lookup
        .keys()
        .chain(remote_lookup.keys())
        .copied()
        .collect();

    let mut merged_records: Vec<Record> = Vec::with_capacity(all_uuids.len());
    let mut record_collisions: Vec<RecordCollision> = Vec::new();

    for uuid in all_uuids {
        let merged = match (local_lookup.get(&uuid), remote_lookup.get(&uuid)) {
            (Some(&l), Some(&r)) => {
                let m = merge_record(l, r);
                if !m.collisions.is_empty() {
                    record_collisions.push(RecordCollision {
                        record_uuid: uuid,
                        field_collisions: m.collisions,
                    });
                }
                m.merged
            }
            (Some(&l), None) => l.clone(),
            (None, Some(&r)) => r.clone(),
            (None, None) => unreachable!("BTreeSet union excludes the absent-from-both case"),
        };
        merged_records.push(merged);
    }

    let merged_pt = BlockPlaintext {
        block_version: local.block_version.max(remote.block_version),
        block_uuid: local.block_uuid,
        block_name: merge_block_name(&local.block_name, &remote.block_name),
        schema_version: local.schema_version.max(remote.schema_version),
        records: merged_records,
        unknown: merge_unknown_map(&local.unknown, &remote.unknown),
    };

    (merged_pt, record_collisions)
}

/// `block_name` LWW per §11.2: lex-larger UTF-8 byte string wins.
fn merge_block_name(l: &str, r: &str) -> String {
    if l.as_bytes() >= r.as_bytes() {
        l.to_string()
    } else {
        r.to_string()
    }
}

/// Apply `+1` to `device`'s component of `clock`, inserting a fresh
/// entry at counter `1` when the device has no current entry. The
/// result is sorted ascending by `device_uuid` to keep the §6.1
/// wire-format invariant in the in-memory representation.
///
/// Mirrors the orchestrator layer's private `tick_clock` but is pure
/// (takes `clock` by value, returns a new `Vec`) and produces a
/// layer-local error rather than `VaultError` so this module stays
/// independent of the umbrella enum.
fn tick_for_device(
    clock: Vec<VectorClockEntry>,
    device: [u8; 16],
) -> Result<Vec<VectorClockEntry>, ConflictError> {
    let mut clock = clock;
    let mut found = false;
    for entry in clock.iter_mut() {
        if entry.device_uuid == device {
            entry.counter = entry
                .counter
                .checked_add(1)
                .ok_or(ConflictError::ClockOverflow {
                    device_uuid: device,
                })?;
            found = true;
            break;
        }
    }
    if !found {
        let pos = clock
            .iter()
            .position(|e| e.device_uuid > device)
            .unwrap_or(clock.len());
        clock.insert(
            pos,
            VectorClockEntry {
                device_uuid: device,
                counter: 1,
            },
        );
    }
    Ok(clock)
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
            tombstoned_at_ms: 0,
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
        // §11.1 normal rule (no tombstone): lex-larger UTF-8 wins on
        // last_mod_ms tie.
        let mut a = rec([1; 16]);
        a.record_type = "abc".into();
        a.last_mod_ms = 100;
        let mut b = rec([1; 16]);
        b.record_type = "abd".into();
        b.last_mod_ms = 100;
        let m = merge_record(&a, &b);
        assert_eq!(m.merged.record_type, "abd", "abd > abc, abd wins on tie");
    }

    #[test]
    fn merge_record_type_tombstone_override_picks_tombstoning_side() {
        // §11.3 identity-metadata override: when one side tombstones
        // and last_mod_ms ties, the tombstoning side's record_type
        // wins regardless of lex order. Without the override, §11.1
        // would pick "secure_note" (lex-larger). With the override,
        // the local tombstoning side's "login" wins because the
        // merged record reflects the deleter's view of the record.
        let mut local = rec([1; 16]);
        local.record_type = "login".into();
        local.last_mod_ms = 100;
        local.tombstone = true;
        local.tombstoned_at_ms = 100;
        local.fields.clear();

        let mut remote = rec([1; 16]);
        remote.record_type = "secure_note".into();
        remote.last_mod_ms = 100;

        let m = merge_record(&local, &remote);
        assert!(m.merged.tombstone, "tombstone-on-tie wins");
        assert_eq!(
            m.merged.record_type, "login",
            "tombstoning side's record_type wins per §11.3 override, \
             even though §11.1 lex-larger would have picked 'secure_note'"
        );
    }

    #[test]
    fn merge_record_unknown_tombstone_override_picks_tombstoning_side() {
        use ciborium::Value;
        // §11.3 override extends to record-level `unknown`. The
        // tombstoning side's full unknown map is taken wholesale;
        // the live side's forward-compat keys do not survive into
        // the merged tombstoned record.
        let mut local = rec([1; 16]);
        local.last_mod_ms = 100;
        local.tombstone = true;
        local.tombstoned_at_ms = 100;
        local.fields.clear();
        let mut local_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Integer(7u64.into()), &mut local_bytes).unwrap();
        local.unknown.insert(
            "v2_local_only".to_string(),
            UnknownValue::from_canonical_cbor(&local_bytes).unwrap(),
        );

        let mut remote = rec([1; 16]);
        remote.last_mod_ms = 100;
        let mut remote_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Integer(99u64.into()), &mut remote_bytes).unwrap();
        remote.unknown.insert(
            "v2_remote_only".to_string(),
            UnknownValue::from_canonical_cbor(&remote_bytes).unwrap(),
        );

        let m = merge_record(&local, &remote);
        assert!(m.merged.tombstone);
        assert_eq!(
            m.merged.unknown.len(),
            1,
            "remote's unknown key dropped under §11.3 override"
        );
        assert!(
            m.merged.unknown.contains_key("v2_local_only"),
            "tombstoning side's unknown survives wholesale"
        );
    }

    #[test]
    fn merge_record_clamps_malformed_tombstone_dc_upward() {
        // A malformed input has `tombstone=true` but `tombstoned_at_ms=0`
        // (violating the §11.5 invariant that tombstoned_at_ms ==
        // last_mod_ms when tombstoned). Without the defensive clamp,
        // the death clock would not advance to local.last_mod_ms=200,
        // and remote's "u" field at last_mod=10 would survive the
        // staleness filter despite being below the (correct) death
        // clock of 200.
        let mut local = rec([1; 16]);
        local.tombstone = true;
        local.last_mod_ms = 200;
        local.tombstoned_at_ms = 0; // malformed: should equal last_mod_ms

        let mut remote = rec([1; 16]);
        remote.last_mod_ms = 200;
        remote.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("stale".into()), 10, 2),
        );

        let m = merge_record(&local, &remote);
        // Tombstone wins on tie. fields cleared regardless.
        assert!(m.merged.tombstone);
        assert!(m.merged.fields.is_empty());
        // Defensive clamp: merged.tombstoned_at_ms reflects the
        // tombstoning side's true death-clock (last_mod_ms=200), not
        // the malformed 0. This propagates to downstream merges.
        assert_eq!(
            m.merged.tombstoned_at_ms, 200,
            "death clock clamped upward from malformed 0"
        );
    }

    #[test]
    fn merge_record_clamp_subsequent_merge_drops_stale_field_correctly() {
        // Stronger version: confirm the clamp's effect propagates.
        // After merging a malformed tombstone with a live record,
        // the merged record's death clock should be high enough that
        // a subsequent merge with a third (live, tombstoned_at_ms=0)
        // replica drops stale pre-tombstone fields.
        let mut malformed_tomb = rec([1; 16]);
        malformed_tomb.tombstone = true;
        malformed_tomb.last_mod_ms = 200;
        malformed_tomb.tombstoned_at_ms = 0; // hostile: should be 200

        let mut second_replica = rec([1; 16]);
        second_replica.last_mod_ms = 300;
        // (No fields here — just establishes a live replica.)

        let mut third_replica = rec([1; 16]);
        third_replica.last_mod_ms = 200;
        third_replica.fields.insert(
            "stale".to_string(),
            rfield(RecordFieldValue::Text("pre-tombstone".into()), 50, 3),
        );

        // Merge tombstone with second_replica → should clamp DC to 200
        // and result in live(300) with tombstoned_at_ms=200.
        let step1 = merge_record(&malformed_tomb, &second_replica).merged;
        assert!(!step1.tombstone);
        assert_eq!(
            step1.tombstoned_at_ms, 200,
            "clamp propagates the corrected DC"
        );

        // Now merge with third_replica's stale field. The DC=200 must
        // drop the field (last_mod=50 ≤ 200).
        let step2 = merge_record(&step1, &third_replica).merged;
        assert!(
            step2.fields.is_empty(),
            "stale field correctly dropped because clamp ensured DC=200 propagated"
        );
    }

    #[test]
    fn merge_record_clamps_malformed_live_tombstoned_at_ms_downward() {
        // The mirror malformation of the tombstoned-input clamp: a
        // hostile peer ships a *live* record with
        // `tombstoned_at_ms > last_mod_ms`, violating the §11.5
        // invariant `tombstoned_at_ms ≤ last_mod_ms` (always). Without
        // a downward clamp, the merged death clock would propagate
        // the inflated value via `max`, and the §11.3 staleness
        // filter would drop legitimate fields on the honest side.
        //
        // With `tombstoned_at_ms = u64::MAX`, the inflation drops
        // every field with `last_mod < u64::MAX` — a deniable
        // data-loss attack from a single malformed sync packet.
        let mut hostile = rec([1; 16]);
        hostile.last_mod_ms = 1000;
        hostile.tombstoned_at_ms = u64::MAX; // malformed
        // Hostile carries no fields itself.

        let mut honest = rec([1; 16]);
        honest.last_mod_ms = 1000;
        honest.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("legit".into()), 500, 2),
        );

        let m = merge_record(&hostile, &honest);
        assert!(!m.merged.tombstone, "both live, merged is live");
        // Defensive clamp: hostile's tombstoned_at_ms was clamped
        // down to its own last_mod_ms (1000). Honest's was 0 (well-
        // formed). Merged death clock = max(1000, 0) = 1000.
        assert_eq!(
            m.merged.tombstoned_at_ms, 1000,
            "death clock clamped down from u64::MAX to last_mod_ms"
        );
        // The honest field at last_mod=500 is below the (clamped)
        // death clock of 1000, so it's still dropped — but the
        // *attack surface is bounded* by the hostile peer's own
        // last_mod_ms, not by their forged death clock. Without the
        // clamp, every field in the universe with last_mod < u64::MAX
        // would have been dropped.
        assert!(
            m.merged.fields.is_empty(),
            "field at last_mod=500 ≤ clamped DC=1000 dropped"
        );
    }

    #[test]
    fn merge_record_clamp_bounds_death_clock_attack_to_hostile_last_mod() {
        // Demonstrates that the live-record clamp bounds a hostile
        // peer's death-clock attack to their *own* last_mod_ms,
        // protecting any field with last_mod strictly greater than
        // the hostile peer's last_mod_ms — even when the hostile
        // peer claims `tombstoned_at_ms = u64::MAX`.
        let mut hostile = rec([1; 16]);
        hostile.last_mod_ms = 100;
        hostile.tombstoned_at_ms = u64::MAX; // malformed

        let mut honest = rec([1; 16]);
        honest.last_mod_ms = 1000;
        honest.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("survives".into()), 500, 2),
        );

        let m = merge_record(&hostile, &honest);
        assert!(!m.merged.tombstone);
        // Clamp: hostile's DC drops to its last_mod_ms = 100. Honest's
        // DC = 0. Merged DC = max(100, 0) = 100.
        assert_eq!(m.merged.tombstoned_at_ms, 100);
        // The honest field at last_mod=500 > clamped DC=100 SURVIVES.
        // Without the clamp, the merged DC would be u64::MAX and the
        // field would be wiped.
        assert_eq!(
            m.merged.fields["u"].value,
            RecordFieldValue::Text("survives".into()),
            "field at last_mod=500 > clamped DC=100 survives the attack"
        );
    }

    #[test]
    fn merge_record_clamps_malformed_tombstone_dc_above_last_mod_downward() {
        // §11.5: `tombstone == true ⇒ tombstoned_at_ms == last_mod_ms`.
        // A tombstoned input with `tombstoned_at_ms > last_mod_ms`
        // violates the invariant in the *upward* direction. Before
        // this commit the clamp was one-sided (`max(DC, last_mod_ms)`,
        // which never lowered DC), so an inflated DC on a tombstoned
        // input propagated through merge unchanged.
        //
        // The bidirectional clamp now forces tombstoned inputs to
        // exactly `tombstoned_at_ms == last_mod_ms`, defending against
        // hostile inflation in either direction.
        let mut hostile_tomb = rec([1; 16]);
        hostile_tomb.tombstone = true;
        hostile_tomb.last_mod_ms = 100;
        hostile_tomb.tombstoned_at_ms = u64::MAX - 1; // malformed: DC > last_mod_ms

        let mut honest_live = rec([1; 16]);
        honest_live.last_mod_ms = 1000;
        honest_live.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("survives".into()), 500, 2),
        );

        let m = merge_record(&hostile_tomb, &honest_live);
        // Live wins (T_l=1000 > T_d=100). Merged is live.
        assert!(!m.merged.tombstone, "live wins, T_l > T_d");
        // Tombstoned hostile input clamped to its own last_mod_ms=100.
        // Merged DC = max(100, 0) = 100.
        assert_eq!(
            m.merged.tombstoned_at_ms, 100,
            "tombstoned input clamped down to its last_mod_ms"
        );
        // Honest field at last_mod=500 > clamped DC=100 SURVIVES.
        assert_eq!(
            m.merged.fields["u"].value,
            RecordFieldValue::Text("survives".into()),
            "honest field at last_mod=500 > clamped DC=100 survives"
        );
    }

    #[test]
    fn merge_record_type_tombstone_lost_falls_back_to_lww() {
        // Override applies only to *Wins* outcomes. In a Lost outcome
        // (live wins, T_l > T_d strictly) the §11.1 normal rule
        // applies, which picks the side with greater last_mod_ms —
        // happens to coincide with "live side" in the Lost case but
        // the routing is via §11.1, not the override.
        let mut local = rec([1; 16]);
        local.record_type = "login".into();
        local.last_mod_ms = 50;
        local.tombstone = true;
        local.tombstoned_at_ms = 50;

        let mut remote = rec([1; 16]);
        remote.record_type = "secure_note".into();
        remote.last_mod_ms = 100;

        let m = merge_record(&local, &remote);
        assert!(!m.merged.tombstone, "live wins, T_l > T_d");
        assert_eq!(
            m.merged.record_type, "secure_note",
            "live side wins via §11.1 (greater last_mod_ms), not via override"
        );
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

    // --- §11.3 staleness filter (death clock) ------------------------

    #[test]
    fn merge_record_propagates_death_clock_via_max() {
        let mut a = rec([3; 16]);
        a.last_mod_ms = 100;
        a.tombstoned_at_ms = 50;
        let mut b = rec([3; 16]);
        b.last_mod_ms = 200;
        b.tombstoned_at_ms = 80;
        let m = merge_record(&a, &b);
        assert_eq!(
            m.merged.tombstoned_at_ms, 80,
            "max(50, 80) = 80; the death clock advances monotonically"
        );
    }

    #[test]
    fn merge_record_drops_stale_field_below_death_clock() {
        // local: live, last_mod_ms=200, fields={"u" with last_mod=10},
        // tombstoned_at_ms=0 (this device never observed a tombstone).
        // remote: live, last_mod_ms=200, fields={}, tombstoned_at_ms=100
        // (this device observed a tombstone at T=100).
        // After merge, the death clock advances to 100 and the local
        // "u" field (last_mod=10 ≤ 100) is dropped — it predates the
        // observed tombstone.
        let mut a = rec([3; 16]);
        a.last_mod_ms = 200;
        a.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("stale".into()), 10, 1),
        );
        let mut b = rec([3; 16]);
        b.last_mod_ms = 200;
        b.tombstoned_at_ms = 100;
        let m = merge_record(&a, &b);
        assert!(!m.merged.tombstone, "merged record is live");
        assert_eq!(m.merged.tombstoned_at_ms, 100, "death clock = 100");
        assert!(
            m.merged.fields.is_empty(),
            "field with last_mod=10 ≤ 100 dropped by staleness filter"
        );
    }

    #[test]
    fn merge_record_keeps_field_above_death_clock() {
        // Same setup as above, but the field's last_mod is *strictly
        // above* the merged death clock — it is a post-resurrection
        // edit that survives.
        let mut a = rec([3; 16]);
        a.last_mod_ms = 200;
        a.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("survives".into()), 150, 1),
        );
        let mut b = rec([3; 16]);
        b.last_mod_ms = 200;
        b.tombstoned_at_ms = 100;
        let m = merge_record(&a, &b);
        assert_eq!(
            m.merged.fields["u"].value,
            RecordFieldValue::Text("survives".into()),
            "field with last_mod=150 > 100 (death clock) survives"
        );
    }

    #[test]
    fn merge_record_field_at_death_clock_exactly_is_dropped() {
        // The boundary: `field.last_mod ≤ death_clock` drops the
        // field. A field with last_mod exactly equal to the death
        // clock is therefore stale (the tombstone observation
        // happened "at" this timestamp).
        let mut a = rec([3; 16]);
        a.last_mod_ms = 200;
        a.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("v".into()), 100, 1),
        );
        let mut b = rec([3; 16]);
        b.last_mod_ms = 200;
        b.tombstoned_at_ms = 100;
        let m = merge_record(&a, &b);
        assert!(
            m.merged.fields.is_empty(),
            "field.last_mod == death_clock is stale (≤ rule)"
        );
    }

    #[test]
    fn merge_record_resurrection_preserves_death_clock() {
        // Resurrection scenario: a tombstoned record meets a live
        // record edited *strictly after* the tombstone. The merged
        // record is live; its death clock equals the original
        // tombstone time (preserved across resurrection).
        let mut a = rec([3; 16]);
        a.last_mod_ms = 50;
        a.tombstone = true;
        a.tombstoned_at_ms = 50;
        let mut b = rec([3; 16]);
        b.last_mod_ms = 100;
        b.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("resurrected".into()), 100, 2),
        );
        let m = merge_record(&a, &b);
        assert!(!m.merged.tombstone);
        assert_eq!(m.merged.last_mod_ms, 100);
        assert_eq!(m.merged.tombstoned_at_ms, 50, "death clock preserved");
        assert_eq!(
            m.merged.fields["u"].value,
            RecordFieldValue::Text("resurrected".into()),
            "post-tombstone field survives the staleness filter"
        );
    }

    #[test]
    fn merge_record_three_way_associative_under_tombstone_history() {
        // The associativity gap that motivated the death-clock fix.
        // a: live with field "u" at last_mod=5.
        // b: tombstone at last_mod_ms=7, tombstoned_at_ms=7.
        // c: live at last_mod_ms=9, never observed b's tombstone
        //    (tombstoned_at_ms=0).
        // Path 1 — merge(merge(a, b), c): tombstone wins first,
        // collapsing "u". Then live wins over tombstone, but the
        // death clock advances to 7 in the intermediate state and
        // the staleness filter keeps "u" gone.
        // Path 2 — merge(a, merge(b, c)): live wins first, but the
        // intermediate state carries tombstoned_at_ms=7. Merging
        // with `a` then drops "u" (last_mod=5 ≤ 7).
        // Both paths converge on the same persisted record.
        let mut a = rec([3; 16]);
        a.last_mod_ms = 5;
        a.fields.insert(
            "u".to_string(),
            rfield(RecordFieldValue::Text("pre".into()), 5, 1),
        );

        let mut b = rec([3; 16]);
        b.last_mod_ms = 7;
        b.tombstone = true;
        b.tombstoned_at_ms = 7;

        let mut c = rec([3; 16]);
        c.last_mod_ms = 9;
        // c is live; never observed b → tombstoned_at_ms = 0.

        let path_1 = merge_record(&merge_record(&a, &b).merged, &c).merged;
        let path_2 = merge_record(&a, &merge_record(&b, &c).merged).merged;

        assert_eq!(path_1, path_2, "associative under mixed tombstone history");
        assert!(!path_1.tombstone);
        assert!(
            path_1.fields.is_empty(),
            "field 'u' (last_mod=5) is dropped by death clock = 7"
        );
        assert_eq!(path_1.tombstoned_at_ms, 7);
        assert_eq!(path_1.last_mod_ms, 9);
    }

    // --- merge_block helpers ------------------------------------------

    fn pt(block_uuid: [u8; 16]) -> BlockPlaintext {
        BlockPlaintext {
            block_version: 1,
            block_uuid,
            block_name: "vault".to_string(),
            schema_version: 1,
            records: Vec::new(),
            unknown: BTreeMap::new(),
        }
    }

    // --- merge_block: dispatch on relation ---------------------------

    #[test]
    fn merge_block_uuid_mismatch_is_typed_error() {
        let a = pt([1; 16]);
        let b = pt([2; 16]);
        let err = merge_block(&a, &[], &b, &[], [9; 16]).expect_err("should error");
        match err {
            ConflictError::BlockUuidMismatch { local, remote } => {
                assert_eq!(local, [1; 16]);
                assert_eq!(remote, [2; 16]);
            }
            ConflictError::ClockOverflow { .. } => panic!("wrong variant"),
        }
    }

    #[test]
    fn merge_block_equal_relation_returns_local_unchanged() {
        let a = pt([5; 16]);
        let clock = vec![entry(1, 3)];
        let m = merge_block(&a, &clock, &a, &clock, [9; 16]).expect("ok");
        assert_eq!(m.relation, ClockRelation::Equal);
        assert_eq!(m.merged, a);
        assert_eq!(m.vector_clock, clock);
        assert!(m.collisions.is_empty());
    }

    #[test]
    fn merge_block_incoming_dominates_returns_remote() {
        let a = pt([5; 16]);
        let mut b = pt([5; 16]);
        b.block_name = "newer".to_string();
        let local_clock = vec![entry(1, 3)];
        let remote_clock = vec![entry(1, 5)];
        let m = merge_block(&a, &local_clock, &b, &remote_clock, [9; 16]).expect("ok");
        assert_eq!(m.relation, ClockRelation::IncomingDominates);
        assert_eq!(m.merged, b, "remote (incoming) is the dominant side");
        assert_eq!(m.vector_clock, remote_clock);
        assert!(m.collisions.is_empty());
    }

    #[test]
    fn merge_block_incoming_dominated_returns_local() {
        let mut a = pt([5; 16]);
        a.block_name = "ours".to_string();
        let b = pt([5; 16]);
        let local_clock = vec![entry(1, 5)];
        let remote_clock = vec![entry(1, 3)];
        let m = merge_block(&a, &local_clock, &b, &remote_clock, [9; 16]).expect("ok");
        assert_eq!(m.relation, ClockRelation::IncomingDominated);
        assert_eq!(m.merged, a, "local is the dominant side");
        assert_eq!(m.vector_clock, local_clock);
    }

    #[test]
    fn merge_block_concurrent_unions_disjoint_records() {
        let mut a = pt([5; 16]);
        let mut record_a = rec([10; 16]);
        record_a
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("alice".into()), 50, 1));
        a.records.push(record_a);

        let mut b = pt([5; 16]);
        let mut record_b = rec([20; 16]);
        record_b
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("bob".into()), 60, 2));
        b.records.push(record_b);

        let local_clock = vec![entry(1, 1)];
        let remote_clock = vec![entry(2, 1)];
        let m = merge_block(&a, &local_clock, &b, &remote_clock, [9; 16]).expect("ok");
        assert_eq!(m.relation, ClockRelation::Concurrent);
        assert_eq!(m.merged.records.len(), 2);
        // Records sorted ascending by record_uuid: [10;16] before [20;16].
        assert_eq!(m.merged.records[0].record_uuid, [10; 16]);
        assert_eq!(m.merged.records[1].record_uuid, [20; 16]);
        assert!(m.collisions.is_empty(), "disjoint records do not collide");
        // vector_clock = max(local, remote) + 1 for merging device [9; 16].
        assert_eq!(m.vector_clock.len(), 3);
    }

    #[test]
    fn merge_block_concurrent_collision_surfaces_record_uuid() {
        // Same record_uuid in both sides with conflicting values.
        let mut a = pt([5; 16]);
        let mut record_a = rec([10; 16]);
        record_a
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("v1".into()), 100, 1));
        a.records.push(record_a);

        let mut b = pt([5; 16]);
        let mut record_b = rec([10; 16]);
        record_b
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("v2".into()), 200, 2));
        b.records.push(record_b);

        let local_clock = vec![entry(1, 1)];
        let remote_clock = vec![entry(2, 1)];
        let m = merge_block(&a, &local_clock, &b, &remote_clock, [9; 16]).expect("ok");
        assert_eq!(m.relation, ClockRelation::Concurrent);
        assert_eq!(m.merged.records.len(), 1);
        assert_eq!(
            m.merged.records[0].fields["u"].value,
            RecordFieldValue::Text("v2".into())
        );
        assert_eq!(m.collisions.len(), 1);
        assert_eq!(m.collisions[0].record_uuid, [10; 16]);
        assert_eq!(m.collisions[0].field_collisions.len(), 1);
        assert_eq!(m.collisions[0].field_collisions[0].field_name, "u");
    }

    #[test]
    fn merge_block_concurrent_ticks_merging_device() {
        let a = pt([5; 16]);
        let b = pt([5; 16]);
        let local_clock = vec![entry(1, 3)];
        let remote_clock = vec![entry(2, 4)];
        let merging_device = [9; 16];
        let m = merge_block(&a, &local_clock, &b, &remote_clock, merging_device).expect("ok");
        assert_eq!(m.relation, ClockRelation::Concurrent);
        // Merged clock has entries for devices 1, 2, and 9 — and
        // device 9's counter is 1 (fresh entry).
        let merging_entry = m
            .vector_clock
            .iter()
            .find(|e| e.device_uuid == merging_device)
            .expect("merging device is present");
        assert_eq!(merging_entry.counter, 1);
    }

    #[test]
    fn merge_block_concurrent_block_metadata_takes_max_and_lex_larger() {
        let mut a = pt([5; 16]);
        a.block_version = 1;
        a.schema_version = 2;
        a.block_name = "abc".into();
        let mut b = pt([5; 16]);
        b.block_version = 2;
        b.schema_version = 1;
        b.block_name = "abd".into();

        let local_clock = vec![entry(1, 1)];
        let remote_clock = vec![entry(2, 1)];
        let m = merge_block(&a, &local_clock, &b, &remote_clock, [9; 16]).expect("ok");
        assert_eq!(m.merged.block_version, 2, "max of versions");
        assert_eq!(m.merged.schema_version, 2, "max of schema versions");
        assert_eq!(m.merged.block_name, "abd", "lex-larger block_name");
    }

    #[test]
    fn merge_block_concurrent_commutative_basic() {
        // Hand-crafted: two records, one collision, two block-metadata
        // ties broken by deterministic rules → merge(a, b) == merge(b, a).
        let mut a = pt([5; 16]);
        a.block_name = "abc".into();
        let mut record_a1 = rec([10; 16]);
        record_a1
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("v1".into()), 100, 1));
        a.records.push(record_a1);

        let mut b = pt([5; 16]);
        b.block_name = "abd".into();
        let mut record_b1 = rec([10; 16]);
        record_b1
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("v2".into()), 200, 2));
        b.records.push(record_b1);
        let mut record_b2 = rec([20; 16]);
        record_b2
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("only-b".into()), 50, 2));
        b.records.push(record_b2);

        let local_clock = vec![entry(1, 1)];
        let remote_clock = vec![entry(2, 1)];
        let merging_device = [9; 16];
        let ab = merge_block(&a, &local_clock, &b, &remote_clock, merging_device).expect("ok");
        let ba = merge_block(&b, &remote_clock, &a, &local_clock, merging_device).expect("ok");
        assert_eq!(ab, ba, "merge_block is commutative for Concurrent relation");
    }

    #[test]
    fn merge_block_concurrent_idempotent_basic() {
        let mut a = pt([5; 16]);
        let mut record_a = rec([10; 16]);
        record_a
            .fields
            .insert("u".into(), rfield(RecordFieldValue::Text("v".into()), 100, 1));
        a.records.push(record_a);
        let clock = vec![entry(1, 1)];
        let m = merge_block(&a, &clock, &a, &clock, [9; 16]).expect("ok");
        // Equal relation, no clock tick, no collisions.
        assert_eq!(m.relation, ClockRelation::Equal);
        assert_eq!(m.merged, a);
        assert_eq!(m.vector_clock, clock);
        assert!(m.collisions.is_empty());
    }
}
