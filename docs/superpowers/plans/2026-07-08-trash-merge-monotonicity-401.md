# Conflict-copy trash-list reconciliation (#401) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile `manifest.trash` lists across conflict copies during the C-layer sync merge so purge markers (and plain tombstones) survive a concurrent-write merge, with purge-terminal live-vs-trash resolution.

**Architecture:** A new pure module `core/src/vault/trash_merge.rs` provides the block-level trash merge (union + latest-tombstone-wins triple + monotone `purged_at_ms` + unknown-map union) and the purge-terminal live-vs-trash resolver. `prepare_merge` folds canonical + every copy's trash into `DraftMerge.merged_trash` (mirroring the existing `post_merge_clock` fold); `commit_with_decisions` applies it and resolves collisions. The open-time purge sweep is extended to also unlink `blocks/` residue. Spec (`docs/crypto-design.md` §11.6, `docs/vault-format.md` §7), a new `trash_merge_kat.json`, and `conformance.py::py_merge_trash` keep the docs↔code contract.

**Tech Stack:** Rust (stable, `secretary-core`), `proptest`, JSON KATs, Python 3 clean-room (`conformance.py`, run via `uv`).

## Global Constraints

- **Core-only slice.** No FFI / bridge / desktop / mobile change; no new `FfiVaultError` variant.
- **No new crypto, no new signature/KEM site, no `manifest_version` bump.** Trash reconciliation is CRDT-merge logic over already-signed manifest fields.
- `#![forbid(unsafe_code)]` — do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings` (lib + tests). `cargo fmt --all` clean. `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean.
- **Spec is normative:** update `docs/` before/with the code; `conformance.py` proves docs alone suffice.
- **Do not weaken any proptest.** If a property must relax, that is a design bug — stop and escalate.
- **All commands run from the worktree:** `/Users/hherb/src/secretary/.worktrees/trash-merge-401`. Prefix cargo/uv with `cd` into it (shell state does not persist between calls).
- `--release` for all cargo test/clippy (crypto crates are slow in debug).
- **Merge semantics (verbatim, the contract every task implements):**
  - *Union* keyed by `block_uuid`; no entry dropped by the merge.
  - *Tombstone triple* `(tombstoned_at_ms, tombstoned_by, fingerprint)` — keep the coherent triple from the side that is greatest under the tuple total order (`tombstoned_at_ms` asc, then `tombstoned_by` asc as bytes, then `fingerprint` with `None < Some`, `Some` bytewise). Never mix fields across sides.
  - *Purge* `purged_at_ms` — merged independently: `Some` if either side is; `max` of the millis; `None` loses to `Some`; never un-purges.
  - *Unknown map* — per-key rule of §11.1 (present-in-one kept; equal kept once; differing → lex-larger canonical-CBOR bytes).
  - *Live-vs-trash collision* — purge-terminal: a purged trash entry whose `block_uuid` is live wins (remove the block, keep purged-in-trash); a non-purged one loses to live (drop the trash entry).

---

### Task 1: Normative spec — trash-merge semantics

**Files:**
- Modify: `docs/crypto-design.md` (add §11.6 in the §11 CRDT-merge section)
- Modify: `docs/vault-format.md` (extend the §7 trash/purge sweep description)

Docs first, per the "spec is normative" contract. No tests in this task (prose); it is the reference every later task implements against.

- [ ] **Step 1: Add §11.6 to `docs/crypto-design.md`**

Locate the §11 merge section (search for `## 11` / `§11.2` block-merge). After the block-merge subsection, insert:

```markdown
### 11.6 Trash-list reconciliation (conflict-copy merge)

When two conflict copies of a vault are merged, their `trash` lists are
reconciled by a block-level merge keyed by `block_uuid`. The merge is
commutative, associative, and idempotent.

- **Union.** Every `block_uuid` present in any copy's `trash` appears in the
  merged `trash`. The merge never drops an entry.
- **Tombstone triple.** For a `block_uuid` present with differing
  `(tombstoned_at_ms, tombstoned_by, fingerprint)` triples, the merged entry
  keeps the triple that is greatest under the total order comparing
  `tombstoned_at_ms` ascending, then `tombstoned_by` ascending (16 bytes,
  lexicographic), then `fingerprint` with `None < Some(_)` and `Some`
  compared bytewise. The three fields are always taken together from the
  winning side — never mixed.
- **Purge marker.** `purged_at_ms` is merged independently and monotonically:
  the merged value is `Some` if either side is `Some`, taking the maximum
  milliseconds; `None` loses to any `Some`. A purged entry never un-purges.
- **Unknown map.** Merged per the §11.1 per-key rule (a key in one side kept
  verbatim; a key in both with equal value kept once; differing values take
  the lex-larger canonical-CBOR value bytes).

Because each field merge is a join over a total order and the key set is
unioned, the reconciliation is commutative, associative, and idempotent.

**Live-vs-trash collision.** After reconciliation a `block_uuid` may be
simultaneously live in `blocks` (one copy kept or restored it) and present in
the merged `trash` (another copy trashed it). A signed manifest requires
`blocks` and `trash` to be disjoint, so the collision is resolved
**purge-terminally**:

- if the merged trash entry is purged (`purged_at_ms` is `Some`), **purge
  wins**: the block is removed from `blocks` and kept purged-in-`trash` — a
  permanent purge is terminal and beats a concurrent restore or edit;
- otherwise **live wins**: the trash entry is dropped and the block stays live.
```

- [ ] **Step 2: Extend the §7 sweep description in `docs/vault-format.md`**

Find the §7 open-time purge sweep paragraph (search `purged` / `sweep`). Append:

```markdown
The open-time purge sweep removes, for every purged `TrashEntry` whose
`block_uuid` is **not live** in `blocks`, both the `trash/<uuid>.cbor.enc.*`
residue and the `blocks/<uuid>.cbor.enc` residue. A `blocks/` residue arises
only from a conflict-copy merge in which a concurrent restore on the merging
device left the block file under `blocks/` after purge won at the manifest
level (§11.6); removing it completes the purge on that device. The sweep runs
only after the manifest signature is verified, so a forged purge marker can
never drive a deletion, and the "not live in `blocks`" gate means a restore
that legitimately won is never touched.
```

- [ ] **Step 3: Verify docs build clean**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core 2>&1 | tail -5`
Expected: no warnings (these are `.md` edits; this just confirms nothing else regressed).

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add docs/crypto-design.md docs/vault-format.md
git commit -m "docs(core): normative trash-list merge + purge-terminal collision (#401)"
```

---

### Task 2: Pure `trash_merge` module

**Files:**
- Create: `core/src/vault/trash_merge.rs`
- Modify: `core/src/vault/conflict.rs:673` (widen `merge_unknown_map` to `pub(crate)`)
- Modify: `core/src/vault/mod.rs` (register `pub mod trash_merge;` + re-export)
- Test: inline `#[cfg(test)] mod tests` in `trash_merge.rs`

**Interfaces:**
- Consumes: `crate::vault::manifest::TrashEntry`, `crate::vault::conflict::merge_unknown_map`.
- Produces:
  - `pub fn merge_trash_entry(a: &TrashEntry, b: &TrashEntry) -> TrashEntry`
  - `pub fn merge_trash_lists(lists: &[&[TrashEntry]]) -> Vec<TrashEntry>`
  - `pub fn resolve_live_vs_trash(live_block_uuids: &BTreeSet<[u8; 16]>, trash: Vec<TrashEntry>) -> (BTreeSet<[u8; 16]>, Vec<TrashEntry>)`

- [ ] **Step 1: Widen `merge_unknown_map` visibility**

In `core/src/vault/conflict.rs`, change line 673 from:

```rust
fn merge_unknown_map(
```
to:
```rust
pub(crate) fn merge_unknown_map(
```

- [ ] **Step 2: Write the module with failing unit tests**

Create `core/src/vault/trash_merge.rs`:

```rust
//! Block-level trash-list reconciliation for conflict-copy merges (#401).
//!
//! When two conflict copies of a vault are merged, their `manifest.trash`
//! lists must be unioned and each entry's lifecycle fields reconciled. This
//! is the block-level analog of the record-level CRDT merge in
//! [`super::conflict`]; it lives in its own module because it is a distinct
//! concept (block tombstone lifecycle, not record field LWW) and because
//! `conflict.rs` is already large.
//!
//! All functions are pure. The merge is commutative, associative, and
//! idempotent (proved by `core/tests/proptest.rs`). Normative semantics:
//! `docs/crypto-design.md` §11.6. Cross-language witness:
//! `core/tests/python/conformance.py::py_merge_trash`.

use std::collections::{BTreeMap, BTreeSet};

use crate::vault::conflict::merge_unknown_map;
use crate::vault::manifest::TrashEntry;

/// Merge two [`TrashEntry`] that share a `block_uuid` (§11.6).
///
/// - Tombstone triple `(tombstoned_at_ms, tombstoned_by, fingerprint)`:
///   the coherent triple from the side greatest under the tuple total order
///   (latest tombstone wins; ties by `tombstoned_by` then `fingerprint`,
///   `None < Some`). Never mixed across sides.
/// - `purged_at_ms`: independent + monotone — `Some` if either side is,
///   `max` millis, `None` loses to `Some`. `Option<u64>`'s `Ord` (`None <
///   Some`) makes `max` yield exactly this.
/// - `unknown`: §11.1 per-key union via [`merge_unknown_map`].
pub fn merge_trash_entry(a: &TrashEntry, b: &TrashEntry) -> TrashEntry {
    debug_assert_eq!(
        a.block_uuid, b.block_uuid,
        "merge_trash_entry called on differing block_uuid"
    );
    let a_key = (a.tombstoned_at_ms, a.tombstoned_by, a.fingerprint);
    let b_key = (b.tombstoned_at_ms, b.tombstoned_by, b.fingerprint);
    let winner = if a_key >= b_key { a } else { b };
    TrashEntry {
        block_uuid: a.block_uuid,
        tombstoned_at_ms: winner.tombstoned_at_ms,
        tombstoned_by: winner.tombstoned_by,
        fingerprint: winner.fingerprint,
        purged_at_ms: a.purged_at_ms.max(b.purged_at_ms),
        unknown: merge_unknown_map(&a.unknown, &b.unknown),
    }
}

/// Union + reconcile trash lists across conflict copies (§11.6).
///
/// Folds every entry of every input list into a
/// `BTreeMap<block_uuid, TrashEntry>` via [`merge_trash_entry`], so the
/// output is sorted ascending by `block_uuid` with no duplicate `block_uuid`
/// — even if an individual input list is itself malformed (duplicate uuids).
/// Never drops an entry.
pub fn merge_trash_lists(lists: &[&[TrashEntry]]) -> Vec<TrashEntry> {
    let mut acc: BTreeMap<[u8; 16], TrashEntry> = BTreeMap::new();
    for list in lists {
        for entry in *list {
            acc.entry(entry.block_uuid)
                .and_modify(|existing| *existing = merge_trash_entry(existing, entry))
                .or_insert_with(|| entry.clone());
        }
    }
    acc.into_values().collect()
}

/// Purge-terminal live-vs-trash collision resolution (§11.6).
///
/// Given the live block uuids and the reconciled trash list, returns
/// `(blocks_to_remove, trash)`:
///
/// - `blocks_to_remove` — block uuids the caller must drop from
///   `manifest.blocks` because a **purged** trash entry collides with them
///   (purge wins).
/// - `trash` — the trash list with **non-purged** live collisions dropped
///   (live wins). Purged entries are always kept.
///
/// The result guarantees `blocks` and `trash` are disjoint after the caller
/// applies `blocks_to_remove`.
pub fn resolve_live_vs_trash(
    live_block_uuids: &BTreeSet<[u8; 16]>,
    trash: Vec<TrashEntry>,
) -> (BTreeSet<[u8; 16]>, Vec<TrashEntry>) {
    let blocks_to_remove: BTreeSet<[u8; 16]> = trash
        .iter()
        .filter(|t| t.purged_at_ms.is_some() && live_block_uuids.contains(&t.block_uuid))
        .map(|t| t.block_uuid)
        .collect();
    let trash = trash
        .into_iter()
        .filter(|t| t.purged_at_ms.is_some() || !live_block_uuids.contains(&t.block_uuid))
        .collect();
    (blocks_to_remove, trash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::record::UnknownValue;

    fn te(uuid: u8, t_at: u64, by: u8, fp: Option<u8>, purged: Option<u64>) -> TrashEntry {
        TrashEntry {
            block_uuid: [uuid; 16],
            tombstoned_at_ms: t_at,
            tombstoned_by: [by; 16],
            fingerprint: fp.map(|b| [b; 32]),
            purged_at_ms: purged,
            unknown: BTreeMap::new(),
        }
    }

    #[test]
    fn union_of_disjoint_uuids_sorted() {
        let a = te(0x02, 100, 1, None, None);
        let b = te(0x01, 100, 1, None, None);
        let merged = merge_trash_lists(&[&[a][..], &[b][..]]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].block_uuid, [0x01; 16]);
        assert_eq!(merged[1].block_uuid, [0x02; 16]);
    }

    #[test]
    fn collision_keeps_latest_triple() {
        let a = te(0x05, 100, 0xAA, Some(0x11), None);
        let b = te(0x05, 200, 0xBB, Some(0x22), None);
        let m = merge_trash_entry(&a, &b);
        assert_eq!(m.tombstoned_at_ms, 200);
        assert_eq!(m.tombstoned_by, [0xBB; 16]);
        assert_eq!(m.fingerprint, Some([0x22; 32]));
    }

    #[test]
    fn purge_some_if_either_and_max() {
        assert_eq!(
            merge_trash_entry(&te(1, 10, 0, None, None), &te(1, 10, 0, None, Some(50))).purged_at_ms,
            Some(50)
        );
        assert_eq!(
            merge_trash_entry(&te(1, 10, 0, None, Some(30)), &te(1, 10, 0, None, Some(70)))
                .purged_at_ms,
            Some(70)
        );
        assert_eq!(
            merge_trash_entry(&te(1, 10, 0, None, None), &te(1, 10, 0, None, None)).purged_at_ms,
            None
        );
    }

    #[test]
    fn purge_marker_independent_of_triple_winner() {
        // a has the later triple but is unpurged; b is earlier but purged.
        // Merged keeps a's triple AND b's purge marker.
        let a = te(0x07, 200, 0xAA, Some(0x11), None);
        let b = te(0x07, 100, 0xBB, Some(0x22), Some(50));
        let m = merge_trash_entry(&a, &b);
        assert_eq!(m.tombstoned_at_ms, 200);
        assert_eq!(m.fingerprint, Some([0x11; 32]));
        assert_eq!(m.purged_at_ms, Some(50));
    }

    #[test]
    fn unknown_maps_union() {
        let mut a = te(0x09, 100, 0, None, None);
        a.unknown
            .insert("ka".into(), UnknownValue::from_canonical_cbor(&[0x0a]).unwrap());
        let mut b = te(0x09, 100, 0, None, None);
        b.unknown
            .insert("kb".into(), UnknownValue::from_canonical_cbor(&[0x0b]).unwrap());
        let m = merge_trash_entry(&a, &b);
        assert_eq!(m.unknown.len(), 2);
        assert!(m.unknown.contains_key("ka") && m.unknown.contains_key("kb"));
    }

    #[test]
    fn resolve_purge_terminal_removes_live_block() {
        let live: BTreeSet<[u8; 16]> = [[0x0A; 16]].into_iter().collect();
        let (remove, trash) = resolve_live_vs_trash(&live, vec![te(0x0A, 100, 0, None, Some(50))]);
        assert_eq!(remove, [[0x0A; 16]].into_iter().collect());
        assert_eq!(trash.len(), 1, "purged entry kept");
    }

    #[test]
    fn resolve_live_wins_over_nonpurged() {
        let live: BTreeSet<[u8; 16]> = [[0x0A; 16]].into_iter().collect();
        let (remove, trash) = resolve_live_vs_trash(&live, vec![te(0x0A, 100, 0, None, None)]);
        assert!(remove.is_empty());
        assert!(trash.is_empty(), "non-purged live collision dropped");
    }

    #[test]
    fn resolve_no_collision_keeps_everything() {
        let live: BTreeSet<[u8; 16]> = [[0x0B; 16]].into_iter().collect();
        let (remove, trash) = resolve_live_vs_trash(&live, vec![te(0x0A, 100, 0, None, Some(50))]);
        assert!(remove.is_empty());
        assert_eq!(trash.len(), 1);
    }
}
```

- [ ] **Step 3: Register + export the module**

In `core/src/vault/mod.rs`, add after `pub mod record;` (line ~32):

```rust
pub mod trash_merge;
```

And after the `pub use purge::{...}` line (~59), add:

```rust
pub use trash_merge::{merge_trash_entry, merge_trash_lists, resolve_live_vs_trash};
```

Then confirm `TrashEntry` is re-exported: check the `pub use manifest::{...}` block (~line 46) includes `TrashEntry`. If it does not, add it.

- [ ] **Step 4: Run the unit tests**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release -p secretary-core trash_merge -- --nocapture`
Expected: all `trash_merge::tests::*` pass (8 tests).

- [ ] **Step 5: Clippy + fmt**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo fmt --all && cargo clippy --release -p secretary-core --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add core/src/vault/trash_merge.rs core/src/vault/mod.rs core/src/vault/conflict.rs
git commit -m "feat(core): pure trash-list merge + purge-terminal resolver (#401)"
```

---

### Task 3: Proptests — 5 CRDT properties

**Files:**
- Modify: `core/tests/proptest.rs` (add a `mod trash_merge_props` near the record CRDT proptests, ~line 1200)

**Interfaces:**
- Consumes: `secretary_core::vault::trash_merge::{merge_trash_entry, merge_trash_lists}`, `secretary_core::vault::manifest::TrashEntry`, `secretary_core::vault::record::UnknownValue`.

- [ ] **Step 1: Add the proptest module**

Append to `core/tests/proptest.rs` (after the record CRDT proptest block, before end of file):

```rust
// ---------------------------------------------------------------------------
// #401 — trash-list merge CRDT invariants on merge_trash_entry / _lists.
// Mirrors the record-merge properties: commutativity, associativity,
// idempotence, well-formedness, plus purge monotonicity.
// ---------------------------------------------------------------------------
mod trash_merge_props {
    use super::*;
    use secretary_core::vault::manifest::TrashEntry;
    use secretary_core::vault::record::UnknownValue;
    use secretary_core::vault::trash_merge::{merge_trash_entry, merge_trash_lists};
    use std::collections::BTreeMap;

    fn arb_unknown_map() -> impl Strategy<Value = BTreeMap<String, UnknownValue>> {
        // Values are canonical single-byte CBOR ints (0..=23 encode as one
        // byte equal to the value), always valid `UnknownValue`s.
        prop::collection::btree_map(
            "[a-z]{1,4}",
            (0u8..=23u8)
                .prop_map(|n| UnknownValue::from_canonical_cbor(&[n]).expect("tiny CBOR int")),
            0..3,
        )
    }

    fn arb_trash_entry() -> impl Strategy<Value = TrashEntry> {
        (
            any::<[u8; 16]>(),
            any::<u64>(),
            any::<[u8; 16]>(),
            prop::option::of(any::<[u8; 32]>()),
            prop::option::of(any::<u64>()),
            arb_unknown_map(),
        )
            .prop_map(
                |(block_uuid, tombstoned_at_ms, tombstoned_by, fingerprint, purged_at_ms, unknown)| {
                    TrashEntry {
                        block_uuid,
                        tombstoned_at_ms,
                        tombstoned_by,
                        fingerprint,
                        purged_at_ms,
                        unknown,
                    }
                },
            )
    }

    proptest! {
        /// Commutativity: merge_trash_entry(a, b) == merge_trash_entry(b, a).
        #[test]
        fn trash_merge_entry_commutativity(
            uuid in any::<[u8; 16]>(),
            a in arb_trash_entry(),
            b in arb_trash_entry(),
        ) {
            let mut a = a; let mut b = b;
            a.block_uuid = uuid; b.block_uuid = uuid;
            prop_assert_eq!(merge_trash_entry(&a, &b), merge_trash_entry(&b, &a));
        }

        /// Associativity: merge(merge(a,b),c) == merge(a,merge(b,c)).
        #[test]
        fn trash_merge_entry_associativity(
            uuid in any::<[u8; 16]>(),
            a in arb_trash_entry(),
            b in arb_trash_entry(),
            c in arb_trash_entry(),
        ) {
            let mut a = a; let mut b = b; let mut c = c;
            a.block_uuid = uuid; b.block_uuid = uuid; c.block_uuid = uuid;
            let left = merge_trash_entry(&merge_trash_entry(&a, &b), &c);
            let right = merge_trash_entry(&a, &merge_trash_entry(&b, &c));
            prop_assert_eq!(left, right);
        }

        /// Idempotence: merge_trash_entry(a, a) == a.
        #[test]
        fn trash_merge_entry_idempotence(a in arb_trash_entry()) {
            prop_assert_eq!(merge_trash_entry(&a, &a), a);
        }

        /// Purge monotonicity: merged purge marker is Some iff either side is,
        /// and never decreases below either input.
        #[test]
        fn trash_merge_entry_purge_monotone(
            uuid in any::<[u8; 16]>(),
            a in arb_trash_entry(),
            b in arb_trash_entry(),
        ) {
            let mut a = a; let mut b = b;
            a.block_uuid = uuid; b.block_uuid = uuid;
            let m = merge_trash_entry(&a, &b);
            if a.purged_at_ms.is_some() || b.purged_at_ms.is_some() {
                prop_assert!(m.purged_at_ms.is_some());
            } else {
                prop_assert!(m.purged_at_ms.is_none());
            }
            prop_assert!(m.purged_at_ms >= a.purged_at_ms);
            prop_assert!(m.purged_at_ms >= b.purged_at_ms);
        }

        /// Well-formedness: merge_trash_lists output is sorted ascending by
        /// block_uuid with no duplicates, for arbitrary (possibly malformed)
        /// input lists.
        #[test]
        fn trash_merge_lists_well_formed(
            lists in prop::collection::vec(
                prop::collection::vec(arb_trash_entry(), 0..4), 0..4
            ),
        ) {
            let refs: Vec<&[TrashEntry]> = lists.iter().map(|l| l.as_slice()).collect();
            let merged = merge_trash_lists(&refs);
            for w in merged.windows(2) {
                prop_assert!(w[0].block_uuid < w[1].block_uuid, "sorted, no dup");
            }
        }
    }
}
```

- [ ] **Step 2: Run the proptests**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release --workspace --test proptest trash_merge_props 2>&1 | tail -15`
Expected: 5 properties pass.

- [ ] **Step 3: Clippy on tests**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add core/tests/proptest.rs
git commit -m "test(core): trash-merge CRDT proptests (commut/assoc/idempot/purge-monotone/well-formed) (#401)"
```

---

### Task 4: `trash_merge_kat.json` + Rust replay

**Files:**
- Create: `core/tests/data/trash_merge_kat.json`
- Modify: `core/tests/conflict.rs` (add `trash_merge_kat_replays_match_rust` + parse helpers)

**Interfaces:**
- Consumes: `merge_trash_lists`, `TrashEntry`.

- [ ] **Step 1: Write the KAT fixture**

Create `core/tests/data/trash_merge_kat.json`. Each vector has `inputs` (a list of trash lists) and `expected` (the merged list). A trash entry: `block_uuid_hex` (32 hex), `tombstoned_at_ms`, `tombstoned_by_hex` (32 hex), `fingerprint_hex` (64 hex or `null`), `purged_at_ms` (int or `null`), optional `unknown_hex` (`{key: hex}`).

```json
{
  "version": 1,
  "comment": "#401 block-level trash-list merge KAT (docs/crypto-design.md §11.6). Replayed by core/tests/conflict.rs::trash_merge_kat_replays_match_rust and core/tests/python/conformance.py::py_merge_trash. Pins union, latest-tombstone-wins triple, monotone purged_at_ms (Some-if-either / max / None<Some), and unknown-map union.",
  "vectors": [
    {
      "name": "union_disjoint",
      "description": "Two lists with distinct block_uuids union into a sorted 2-entry list.",
      "inputs": [
        [
          {"block_uuid_hex": "02020202020202020202020202020202", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": null}
        ],
        [
          {"block_uuid_hex": "01010101010101010101010101010101", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": null}
        ]
      ],
      "expected": [
        {"block_uuid_hex": "01010101010101010101010101010101", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": null},
        {"block_uuid_hex": "02020202020202020202020202020202", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": null}
      ]
    },
    {
      "name": "latest_triple_wins_purge_independent",
      "description": "Same block_uuid: side A later triple but unpurged; side B earlier triple but purged. Merged keeps A's triple and B's purge marker.",
      "inputs": [
        [
          {"block_uuid_hex": "07070707070707070707070707070707", "tombstoned_at_ms": 200, "tombstoned_by_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "fingerprint_hex": "1111111111111111111111111111111111111111111111111111111111111111", "purged_at_ms": null}
        ],
        [
          {"block_uuid_hex": "07070707070707070707070707070707", "tombstoned_at_ms": 100, "tombstoned_by_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "fingerprint_hex": "2222222222222222222222222222222222222222222222222222222222222222", "purged_at_ms": 50}
        ]
      ],
      "expected": [
        {"block_uuid_hex": "07070707070707070707070707070707", "tombstoned_at_ms": 200, "tombstoned_by_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "fingerprint_hex": "1111111111111111111111111111111111111111111111111111111111111111", "purged_at_ms": 50}
      ]
    },
    {
      "name": "purge_max_millis",
      "description": "Both sides purged at different times: merged takes the max.",
      "inputs": [
        [
          {"block_uuid_hex": "09090909090909090909090909090909", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": 30}
        ],
        [
          {"block_uuid_hex": "09090909090909090909090909090909", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": 70}
        ]
      ],
      "expected": [
        {"block_uuid_hex": "09090909090909090909090909090909", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": 70}
      ]
    },
    {
      "name": "unknown_union",
      "description": "Disjoint unknown keys on the same block_uuid union together.",
      "inputs": [
        [
          {"block_uuid_hex": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": null, "unknown_hex": {"ka": "0a"}}
        ],
        [
          {"block_uuid_hex": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": null, "unknown_hex": {"kb": "0b"}}
        ]
      ],
      "expected": [
        {"block_uuid_hex": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "tombstoned_at_ms": 100, "tombstoned_by_hex": "01010101010101010101010101010101", "fingerprint_hex": null, "purged_at_ms": null, "unknown_hex": {"ka": "0a", "kb": "0b"}}
      ]
    }
  ]
}
```

- [ ] **Step 2: Add the Rust replay test + parse helper to `core/tests/conflict.rs`**

Append (the module already has `parse_hex_array` from Task-independent code at line 424; reuse it):

```rust
fn parse_trash_entry(spec: &serde_json::Value) -> secretary_core::vault::manifest::TrashEntry {
    let fingerprint = spec["fingerprint_hex"]
        .as_str()
        .map(|h| parse_hex_array::<32>(h));
    let purged_at_ms = spec["purged_at_ms"].as_u64();
    secretary_core::vault::manifest::TrashEntry {
        block_uuid: parse_hex_array(spec["block_uuid_hex"].as_str().expect("block_uuid_hex")),
        tombstoned_at_ms: spec["tombstoned_at_ms"].as_u64().expect("tombstoned_at_ms"),
        tombstoned_by: parse_hex_array(spec["tombstoned_by_hex"].as_str().expect("tombstoned_by_hex")),
        fingerprint,
        purged_at_ms,
        unknown: parse_unknown_map(spec),
    }
}

#[test]
fn trash_merge_kat_replays_match_rust() {
    use secretary_core::vault::manifest::TrashEntry;
    use secretary_core::vault::trash_merge::merge_trash_lists;

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("trash_merge_kat.json");
    let raw = std::fs::read_to_string(&path).expect("read trash_merge_kat.json");
    let kat: serde_json::Value = serde_json::from_str(&raw).expect("parse trash_merge_kat.json");
    assert_eq!(kat["version"], 1);

    let vectors = kat["vectors"].as_array().expect("vectors[]");
    assert!(!vectors.is_empty(), "KAT has at least one vector");

    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let input_lists: Vec<Vec<TrashEntry>> = vector["inputs"]
            .as_array()
            .expect("inputs[]")
            .iter()
            .map(|l| l.as_array().expect("list[]").iter().map(parse_trash_entry).collect())
            .collect();
        let refs: Vec<&[TrashEntry]> = input_lists.iter().map(|l| l.as_slice()).collect();
        let got = merge_trash_lists(&refs);

        let expected: Vec<TrashEntry> = vector["expected"]
            .as_array()
            .expect("expected[]")
            .iter()
            .map(parse_trash_entry)
            .collect();
        assert_eq!(got, expected, "vector {name}: merged trash list");
    }
}
```

Note: `parse_unknown_map` (line 462) and `parse_hex_array` (line 424) already exist in this file — reuse them, do not redefine.

- [ ] **Step 3: Run the replay**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release --workspace --test conflict trash_merge_kat 2>&1 | tail -10`
Expected: `trash_merge_kat_replays_match_rust` passes.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add core/tests/data/trash_merge_kat.json core/tests/conflict.rs
git commit -m "test(core): trash_merge_kat.json + Rust replay (#401)"
```

---

### Task 5: Clean-room `py_merge_trash` + conformance section

**Files:**
- Modify: `core/tests/python/conformance.py` (add `py_merge_trash`, `trash_merge_kat_path`, `section4b_trash_merge_kat`, wire into `main`)

**Interfaces:**
- Consumes: the `trash_merge_kat.json` from Task 4; existing `load_json_fixture`, `py_merge_unknown_map`.

- [ ] **Step 1: Add the clean-room merge + path helper**

In `core/tests/python/conformance.py`, after `conflict_kat_path()` (~line 2354), add:

```python
def trash_merge_kat_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "trash_merge_kat.json"


def _trash_triple_key(e: dict) -> tuple:
    """Total order for the tombstone triple (docs §11.6): tombstoned_at_ms
    asc, then tombstoned_by bytes asc, then fingerprint with None < Some
    and Some bytewise. Encode fingerprint as (0, b"") for None and
    (1, bytes) for Some so None sorts first."""
    fp = e.get("fingerprint_hex")
    fp_key = (0, b"") if fp is None else (1, bytes.fromhex(fp))
    return (e["tombstoned_at_ms"], bytes.fromhex(e["tombstoned_by_hex"]), fp_key)


def py_merge_trash_entry(a: dict, b: dict) -> dict:
    """Merge two trash entries with the same block_uuid (docs §11.6)."""
    winner = a if _trash_triple_key(a) >= _trash_triple_key(b) else b
    # purged: Some-if-either, max millis, None loses to Some.
    pa, pb = a.get("purged_at_ms"), b.get("purged_at_ms")
    if pa is None and pb is None:
        purged = None
    elif pa is None:
        purged = pb
    elif pb is None:
        purged = pa
    else:
        purged = max(pa, pb)
    merged = {
        "block_uuid_hex": a["block_uuid_hex"],
        "tombstoned_at_ms": winner["tombstoned_at_ms"],
        "tombstoned_by_hex": winner["tombstoned_by_hex"],
        "fingerprint_hex": winner.get("fingerprint_hex"),
        "purged_at_ms": purged,
    }
    unk = py_merge_unknown_map(a.get("unknown_hex", {}), b.get("unknown_hex", {}))
    if unk:
        merged["unknown_hex"] = unk
    return merged


def py_merge_trash(lists: list[list[dict]]) -> list[dict]:
    """Union + reconcile trash lists (docs §11.6). Output sorted ascending
    by block_uuid, no duplicates."""
    acc: dict[bytes, dict] = {}
    for lst in lists:
        for entry in lst:
            key = bytes.fromhex(entry["block_uuid_hex"])
            acc[key] = py_merge_trash_entry(acc[key], entry) if key in acc else dict(entry)
    return [acc[k] for k in sorted(acc.keys())]
```

- [ ] **Step 2: Add the section replay**

After `section4_conflict_kat()` (~line 2899), add:

```python
def _normalise_trash_entry(e: dict) -> dict:
    """Canonical comparison shape: fingerprint/purged/unknown normalised so
    absent-key and explicit-null compare equal, and unknown-hex is lowercase."""
    out = {
        "block_uuid_hex": e["block_uuid_hex"].lower(),
        "tombstoned_at_ms": e["tombstoned_at_ms"],
        "tombstoned_by_hex": e["tombstoned_by_hex"].lower(),
        "fingerprint_hex": (e.get("fingerprint_hex") or None),
        "purged_at_ms": (e.get("purged_at_ms") if e.get("purged_at_ms") is not None else None),
    }
    unk = e.get("unknown_hex") or {}
    out["unknown_hex"] = {k: bytes.fromhex(v).hex() for k, v in sorted(unk.items())}
    if out["fingerprint_hex"] is not None:
        out["fingerprint_hex"] = out["fingerprint_hex"].lower()
    return out


def section4b_trash_merge_kat() -> tuple[bool, list[str]]:
    lines: list[str] = []
    path = trash_merge_kat_path()
    if not path.exists():
        print(f"MISSING: trash_merge_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "trash_merge_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        lines.append(f"FAIL  trash_merge_kat.json version={kat.get('version')}, expected 1")
        return False, lines
    vectors = kat.get("vectors") or []
    if not vectors:
        lines.append("FAIL  trash_merge_kat.json has no vectors")
        return False, lines

    all_ok = True
    for vector in vectors:
        name = vector["name"]
        try:
            got = py_merge_trash(vector["inputs"])
        except Exception as exc:  # noqa: BLE001
            lines.append(f"FAIL  vector {name!r}: merge raised {exc!r}")
            all_ok = False
            continue
        got_n = [_normalise_trash_entry(e) for e in got]
        exp_n = [_normalise_trash_entry(e) for e in vector["expected"]]
        if got_n != exp_n:
            lines.append(f"FAIL  vector {name!r}: merged trash mismatch")
            lines.append(f"  got:      {json.dumps(got_n, sort_keys=True)}")
            lines.append(f"  expected: {json.dumps(exp_n, sort_keys=True)}")
            all_ok = False
            continue
        lines.append(f"PASS  trash_merge_kat.json {name!r}")
    return all_ok, lines
```

- [ ] **Step 3: Wire into `main`**

In `main()` (~line 4034), immediately after the Section 4 block:

```python
    print("--- Section 4: conflict_kat.json CRDT merge cross-language replay ---")
    section4_ok, section4_lines = section4_conflict_kat()
```

add:

```python
    print("--- Section 4b: trash_merge_kat.json trash-list merge replay ---")
    section4b_ok, section4b_lines = section4b_trash_merge_kat()
    for line in section4b_lines:
        print(line)
```

Then find the aggregate pass/fail gate near line ~4090 (`if not section4_ok: ... print("FAIL: conflict_kat.json ...")`). Add an analogous gate: include `section4b_ok` in the overall success `and` chain and print `FAIL: trash_merge_kat.json trash-list merge cross-language replay` when `not section4b_ok`. (Match the exact style of the surrounding `section4_ok` handling — locate `section4_ok` usages and add `section4b_ok` beside each.)

- [ ] **Step 4: Run conformance**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && uv run core/tests/python/conformance.py 2>&1 | grep -A6 "Section 4b"`
Expected: `Section 4b` prints `PASS  trash_merge_kat.json ...` for every vector; the script exits 0 overall.

- [ ] **Step 5: Differential replay (Rust↔Python agreement)**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release --workspace --features differential-replay 2>&1 | tail -5`
Expected: green.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add core/tests/python/conformance.py
git commit -m "test(core): clean-room py_merge_trash + conformance replay (#401)"
```

---

### Task 6: `DraftMerge.merged_trash` + `prepare_merge` fold

**Files:**
- Modify: `core/src/sync/draft.rs` (add field ~line 124; fix test constructor ~line 334)
- Modify: `core/src/sync/prepare.rs` (fold trash ~line 526; construct field ~line 545)
- Modify: `core/src/sync/commit/apply.rs:153` (fix `draft_with_vetoes` test helper)

**Interfaces:**
- Consumes: `merge_trash_lists`, `TrashEntry`, `bundle.canonical.manifest.trash`, `bundle.copies[*].manifest.trash`.
- Produces: `DraftMerge.merged_trash: Vec<TrashEntry>`.

- [ ] **Step 1: Add the field to `DraftMerge`**

In `core/src/sync/draft.rs`, after the `per_block_records` field (~line 124), add:

```rust
    /// Union of `bundle.canonical.manifest.trash` and every
    /// `bundle.copies[*].manifest.trash`, reconciled by
    /// `trash_merge::merge_trash_lists` (#401). `commit_with_decisions`
    /// applies it as `new_manifest.trash` after the purge-terminal
    /// live-vs-trash resolution. `#[zeroize(skip)]` — `TrashEntry` carries
    /// no secret material (UUIDs, timestamps, fingerprint, unknown-map),
    /// same as the vector-clock fields.
    #[zeroize(skip)]
    pub merged_trash: Vec<crate::vault::manifest::TrashEntry>,
```

- [ ] **Step 2: Fix the two test `DraftMerge {}` constructors**

In `core/src/sync/draft.rs` (~line 334, the `zeroize`-test constructor), add `merged_trash: Vec::new(),` alongside the other fields.

In `core/src/sync/commit/apply.rs` (~line 153, `draft_with_vetoes`), add `merged_trash: Vec::new(),` alongside the other fields.

- [ ] **Step 3: Write the failing prepare_merge test**

In `core/src/sync/prepare.rs`, the `#[cfg(test)] mod tests` uses only `tombstone_veto_set` today. The trash-fold is better tested at the integration level (Task 7), but add a focused unit assertion here that the field is populated. Add to the `tests` module:

```rust
    #[test]
    fn merge_trash_lists_is_wired_into_prepare_merge_shape() {
        // Compile-level guard: the fold helper is reachable from this module
        // and produces a sorted union. Full integration coverage is in
        // core/tests/ (Task 7). This pins that prepare_merge builds
        // `merged_trash` via the pure fn rather than dropping peer trash.
        use crate::vault::manifest::TrashEntry;
        use crate::vault::trash_merge::merge_trash_lists;
        use std::collections::BTreeMap;
        let a = TrashEntry {
            block_uuid: [2; 16],
            tombstoned_at_ms: 1,
            tombstoned_by: [0; 16],
            fingerprint: None,
            purged_at_ms: None,
            unknown: BTreeMap::new(),
        };
        let b = TrashEntry {
            block_uuid: [1; 16],
            tombstoned_at_ms: 1,
            tombstoned_by: [0; 16],
            fingerprint: None,
            purged_at_ms: Some(9),
            unknown: BTreeMap::new(),
        };
        let merged = merge_trash_lists(&[&[a][..], &[b][..]]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].block_uuid, [1; 16]);
        assert_eq!(merged[0].purged_at_ms, Some(9));
    }
```

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release -p secretary-core merge_trash_lists_is_wired 2>&1 | tail -5`
Expected: FAIL to compile until Step 4 adds the import path is unnecessary (the test imports locally) — it should actually PASS already since it only uses public fns; run it to confirm GREEN. (This step exists to lock the fold semantics in this module's test surface.)

- [ ] **Step 4: Fold trash in `prepare_merge`**

In `core/src/sync/prepare.rs`, after the `post_merge_clock` fold (~line 526, the `for copy in &bundle.copies { post_merge_clock = ... }` loop), add:

```rust
    // #401: reconcile trash lists across canonical + every conflict copy,
    // the exact analog of the post_merge_clock fold above. Carried on the
    // draft; commit_with_decisions applies it (with purge-terminal
    // live-vs-trash resolution).
    let trash_lists: Vec<&[crate::vault::manifest::TrashEntry]> =
        std::iter::once(bundle.canonical.manifest.trash.as_slice())
            .chain(bundle.copies.iter().map(|c| c.manifest.trash.as_slice()))
            .collect();
    let merged_trash = crate::vault::trash_merge::merge_trash_lists(&trash_lists);
```

Then in the `Ok(DraftMerge { ... })` construction (~line 536), add `merged_trash,` alongside `post_merge_clock,`.

- [ ] **Step 5: Run + clippy + fmt**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release -p secretary-core --lib sync 2>&1 | tail -8 && cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: sync lib tests pass; clippy clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add core/src/sync/draft.rs core/src/sync/prepare.rs core/src/sync/commit/apply.rs
git commit -m "feat(core): fold conflict-copy trash lists into DraftMerge.merged_trash (#401)"
```

---

### Task 7: Apply reconciled trash in `commit_with_decisions` + integration test

**Files:**
- Modify: `core/src/sync/commit/write.rs:154-162` (apply merged_trash + resolve collisions)
- Create: `core/tests/sync_trash_merge.rs` (integration test over the convergence harness)
- Modify: `core/tests/convergence_helpers/device.rs` (add `trash_block` / `purge_block` / `restore_block` device ops if absent)

**Interfaces:**
- Consumes: `draft.merged_trash`, `resolve_live_vs_trash`.

- [ ] **Step 1: Apply merged_trash + purge-terminal resolution in commit**

In `core/src/sync/commit/write.rs`, in Step 6 (after the `for entry in new_manifest.blocks.iter_mut() { ... }` loop that updates fingerprints, ~line 162), add:

```rust
    // #401: apply the reconciled trash list and resolve any live-vs-trash
    // collision so the signed manifest stays well-formed (disjoint
    // blocks/trash). Purge is terminal — a purged trash entry whose block
    // is (concurrently) live wins: the block is dropped, the entry kept.
    // A non-purged collision loses to the live block. commit never deletes
    // block *files*; the open-time sweep destroys purged ciphertext.
    let live_uuids: BTreeSet<[u8; 16]> =
        new_manifest.blocks.iter().map(|b| b.block_uuid).collect();
    let (blocks_to_remove, reconciled_trash) =
        crate::vault::resolve_live_vs_trash(&live_uuids, draft.merged_trash.clone());
    if !blocks_to_remove.is_empty() {
        new_manifest
            .blocks
            .retain(|b| !blocks_to_remove.contains(&b.block_uuid));
    }
    new_manifest.trash = reconciled_trash;
```

`BTreeSet` is already imported at the top of `write.rs` (line 16: `use std::collections::{BTreeMap, BTreeSet};`).

- [ ] **Step 2: Add device trash/purge/restore ops to the convergence harness**

Open `core/tests/convergence_helpers/device.rs`. It already has `edit_text_field` (line 57) and `tombstone` (line 71) which open the vault, mutate, and re-sign. **Mirror their exact open+call pattern** (same `open_vault` unlocker, same error handling) to add three thin wrappers that call the core block lifecycle ops. Use the existing callers in `core/tests/trash_restore.rs` and `core/tests/purge.rs` as the authoritative signatures for `trash_block`, `restore_block`, `purge_block` (do not guess — copy the call shape from those files):

```rust
    /// Trash a whole block (blocks/ -> trash/) at `now_ms`.
    pub fn trash_block(&mut self, block_uuid: [u8; 16], now_ms: u64) {
        // Mirror edit_text_field's open pattern; call the core op with the
        // signature used in core/tests/trash_restore.rs.
        // <implement by copying the open+call shape from that test file>
    }

    /// Restore a trashed block (trash/ -> blocks/).
    pub fn restore_block(&mut self, block_uuid: [u8; 16], now_ms: u64) {
        // Signature per core/tests/trash_restore.rs.
    }

    /// Permanently purge a trashed block (marks purged_at_ms, unlinks bytes).
    pub fn purge_block(&mut self, block_uuid: [u8; 16], now_ms: u64) {
        // Signature per core/tests/purge.rs.
    }
```

If these ops are already exercised by an existing convergence test, reuse that helper instead of adding new ones.

- [ ] **Step 3: Write the integration test**

Create `core/tests/sync_trash_merge.rs`. It stages a block trashed on both devices, purged on A, restored on B, reconciles, and asserts purge-terminal convergence. Model the fixture on `core/tests/convergence.rs` (`Baseline`, `Device::fork`, `reconcile`):

```rust
//! #401 — conflict-copy trash-list reconciliation end-to-end. A block is
//! trashed on both devices, purged on A, restored concurrently on B; after
//! reconciliation the merged manifest must have the block purged-in-trash
//! and absent from `blocks` (purge is terminal), and re-open + sweep must
//! remove the restoring device's leftover `blocks/` ciphertext.
#![forbid(unsafe_code)]

mod convergence_helpers;
mod fixtures;
mod sync_helpers;

use convergence_helpers::{reconcile, Baseline, Device};

const A_UUID: [u8; 16] = [0x0A; 16];
const B_UUID: [u8; 16] = [0x0B; 16];
const X_BLOCK: [u8; 16] = [0xBB; 16];
const X_RECORD: [u8; 16] = [0xAA; 16];

#[test]
fn purge_beats_concurrent_restore_across_conflict_copy() {
    // Baseline with one block X that both devices share.
    let baseline = Baseline::create();
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    a.edit_text_field(X_BLOCK, X_RECORD, "f1", "seed", 100);
    let baseline = convergence_helpers::baseline_from_seeded(baseline, &a);

    // Both fork from a baseline where X is live, then both trash X.
    let mut a = Device::fork(&baseline, A_UUID, 0xA0);
    let mut b = Device::fork(&baseline, B_UUID, 0xB0);
    a.trash_block(X_BLOCK, 200);
    b.trash_block(X_BLOCK, 200);
    // A purges X (permanent); B restores X (live again).
    a.purge_block(X_BLOCK, 300);
    b.restore_block(X_BLOCK, 300);

    // A canonical, B merger — B's manifest becomes the conflict copy.
    let shared = reconcile(&a, Some(&b), X_BLOCK);

    // Re-open the reconciled vault and assert purge-terminal outcome.
    let merged = Baseline::from_folder(shared.folder(), baseline.password().clone());
    let manifest = merged.open_manifest();
    assert!(
        manifest.blocks.iter().all(|blk| blk.block_uuid != X_BLOCK),
        "purge is terminal: X must not be live in blocks"
    );
    let entry = manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == X_BLOCK)
        .expect("X present as a trash entry");
    assert!(entry.purged_at_ms.is_some(), "X must remain purged");

    // The open above ran the sweep; the restoring device's blocks/X
    // ciphertext must be gone.
    let blocks_x = sync_helpers::block_file_path(shared.folder(), &X_BLOCK);
    assert!(!blocks_x.exists(), "purge sweep removed blocks/ residue");
}
```

Notes for the implementer:
- The exact `reconcile` / merger direction and whether it drives `commit_with_decisions` is defined in `convergence_helpers/reconcile.rs` + `sync_drive.rs` — read them; if `reconcile` does not itself run the merge-commit, drive it via `sync_as_merger` as `convergence.rs` does.
- If `Baseline::from_folder` / `block_file_path` signatures differ, adjust to the real ones (both exist: `baseline.rs:138`, `sync_helpers/mod.rs:290`).
- The test asserts observable manifest + filesystem state only — no internals.

- [ ] **Step 4: Run the integration test**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release --workspace --test sync_trash_merge 2>&1 | tail -20`
Expected: `purge_beats_concurrent_restore_across_conflict_copy` passes. (Note: `blocks/X` residue removal depends on Task 8's sweep extension; if this sub-assertion fails, complete Task 8 first, then re-run — the manifest assertions must pass regardless.)

- [ ] **Step 5: Full suite + clippy + fmt**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release --workspace 2>&1 | tail -8 && cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5`
Expected: full suite green; clippy clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add core/src/sync/commit/write.rs core/tests/sync_trash_merge.rs core/tests/convergence_helpers/device.rs
git commit -m "feat(core): apply reconciled trash + purge-terminal resolution at commit (#401)"
```

---

### Task 8: Sweep `blocks/` residue extension

**Files:**
- Modify: `core/src/vault/repair/sweep.rs:92-140` (`sweep_purged_trash_files`)
- Modify: `core/tests/purge.rs` (or `core/tests/crash_recovery.rs`) — add a `blocks/`-orphan sweep test

**Interfaces:**
- Consumes: existing `sweep_purged_trash_files(folder, manifest)`.

- [ ] **Step 1: Extend the sweep to unlink `blocks/` residue**

In `core/src/vault/repair/sweep.rs::sweep_purged_trash_files`, the target set (`targets`, line 105) is `(prefix, uuid_hex)` per purged-and-not-live entry. After the existing `trash_dir` read-and-remove loop (ends line 139), add a `blocks/` removal pass keyed by exact filename (the block file has no timestamp suffix):

```rust
    // #401: a purged, not-live entry may also have a leftover
    // `blocks/<uuid>.cbor.enc` — the residue of a conflict-copy merge in
    // which this device concurrently restored the block before a peer's
    // purge won at the manifest level (§11.6). Remove it to complete the
    // purge on this device. Exact filename (no tombstone suffix), so no
    // read_dir scan is needed.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for (_prefix, uuid_hex) in &targets {
        let blocks_path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        match std::fs::remove_file(&blocks_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // no residue — normal
            Err(e) => {
                tracing::warn!(
                    block_uuid = %uuid_hex,
                    error = %e,
                    "purge sweep: failed to remove purged blocks/ residue; benign orphan remains"
                );
            }
        }
    }
```

`BLOCKS_SUBDIR` and `BLOCK_FILE_EXTENSION` are already imported at the top of `sweep.rs` (line 5-6).

Also update the doc comment on `sweep_purged_trash_files` (line 72-91): note it now removes **both** `trash/<uuid>.cbor.enc.*` and `blocks/<uuid>.cbor.enc` residue for purged, not-live entries.

- [ ] **Step 2: Write the failing sweep unit/integration test**

Add to `core/tests/purge.rs` (mirror how its existing tests stage a vault + purged manifest; reuse that file's helpers):

```rust
#[test]
fn sweep_removes_purged_blocks_residue() {
    // Stage a vault whose signed manifest marks block X purged-in-trash and
    // NOT live in blocks, but with a leftover blocks/<X>.cbor.enc file
    // (the conflict-copy-restore residue). Re-open must unlink it.
    //
    // Build on this file's existing purge fixture helpers: create a vault,
    // trash + purge a block, then re-plant a blocks/<X> file to simulate the
    // merge residue, then open_vault and assert the file is gone.
    // <stage per the existing purge.rs fixture pattern>
}
```

The implementer completes the fixture using the same helpers the other `purge.rs` tests use (create vault → `trash_block` → `purge_block` → write a dummy `blocks/<uuid>.cbor.enc` → `open_vault` → assert `!blocks_path.exists()`).

- [ ] **Step 3: Run the sweep test**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release --workspace --test purge sweep_removes_purged_blocks_residue 2>&1 | tail -10`
Expected: passes.

- [ ] **Step 4: Re-run the Task 7 integration test (now the residue assertion holds)**

Run: `cd /Users/hherb/src/secretary/.worktrees/trash-merge-401 && cargo test --release --workspace --test sync_trash_merge 2>&1 | tail -10`
Expected: passes including the `blocks/X` residue assertion.

- [ ] **Step 5: Full acceptance gate**

Run each and confirm green:
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
cargo test --release --workspace
cargo test --release --workspace --features differential-replay
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
```

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
git add core/src/vault/repair/sweep.rs core/tests/purge.rs
git commit -m "feat(core): sweep purged blocks/ residue to complete cross-copy purge (#401)"
```

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-07-08-trash-merge-monotonicity-401-design.md`):
- Pure `trash_merge.rs` module (merge_trash_entry / merge_trash_lists / resolve_live_vs_trash) → Task 2. ✓
- `DraftMerge.merged_trash` + prepare fold → Task 6. ✓
- Commit apply + purge-terminal live-vs-trash → Task 7. ✓
- Sweep `blocks/` extension → Task 8. ✓
- Spec §11.6 + §7 → Task 1. ✓
- `trash_merge_kat.json` + Rust replay → Task 4. ✓
- `py_merge_trash` clean-room → Task 5. ✓
- 5 proptests → Task 3. ✓
- Integration (purge-vs-restore) → Task 7; `blocks/`-orphan sweep test → Task 8. ✓
- No FFI/manifest_version/crypto change → Global Constraints, honored throughout. ✓

**Type consistency:** `merge_trash_entry`, `merge_trash_lists`, `resolve_live_vs_trash` signatures are identical across Tasks 2, 3, 6, 7. `TrashEntry` fields (`block_uuid`, `tombstoned_at_ms`, `tombstoned_by`, `fingerprint: Option<[u8;32]>`, `purged_at_ms: Option<u64>`, `unknown`) match `core/src/vault/manifest.rs`. `resolve_live_vs_trash` returns `(BTreeSet<[u8;16]>, Vec<TrashEntry>)` consumed correctly in Task 7 Step 1.

**Placeholder scan:** The only intentionally-deferred code bodies are the harness wrappers in Task 7 Step 2 and the fixture in Task 8 Step 2, where the exact core-op signatures live in existing test files (`trash_restore.rs`, `purge.rs`) — the implementer is directed to copy the real call shape rather than have this plan guess a signature it could get wrong. All semantic/risk-bearing code (the merge, resolver, sweep, guard, KAT, clean-room) is fully concrete.
