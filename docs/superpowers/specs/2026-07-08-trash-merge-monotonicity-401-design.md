# Design: conflict-copy trash-list reconciliation — purged-marker merge monotonicity (#401)

**Date:** 2026-07-08
**Issue:** #401 — *Conflict-copy trash-list reconciliation (purged-marker merge monotonicity)*
**Refs:** #399 (purge / empty-trash — split this out), #350 (manifest-first `trash_block` + repair sweep), #293 (signed content commitment)
**Scope (this slice):** Rust `core` only — a new pure merge module (`core/src/vault/trash_merge.rs`), the C-layer sync merge (`core/src/sync/prepare.rs` + `core/src/sync/commit/write.rs`), the open-time sweep (`core/src/vault/repair/sweep.rs`), the normative specs (`docs/crypto-design.md §11`, `docs/vault-format.md §7`), and the cross-language witnesses (`conflict_kat.json` + `conformance.py`). **No FFI / bridge / desktop / mobile change** — the merged manifest is an internal sync product, not a new binding surface.

## Problem

The concurrent-write / conflict-copy merge path does **not** reconcile trash lists at all today. `commit_with_decisions` builds `new_manifest = open.manifest.clone()` ([`core/src/sync/commit/write.rs:154`](../../../core/src/sync/commit/write.rs)) — the *local* (canonical) trash list, verbatim. Peer `TrashEntry` records in `bundle.copies[*].manifest.trash` are never unioned in.

Two consequences:

1. **A pre-existing gap that predates purge.** Plain (unpurged) tombstones do not merge across conflict copies either — a block trashed only on a peer copy is silently dropped from the merged manifest, and the surviving trash list depends on *which* device's manifest happened to be canonical (non-deterministic).
2. **#399's `purged_at_ms` marker is not guaranteed to survive a conflict-copy merge.** If device A purges a trashed block and device B does not, a merge that adopts B's canonical trash list drops A's purge marker — the purge "did not stick" for that device pairing.

Why this is a **durability** gap, not a security hole: a dropped purge marker at worst means the purge did not propagate across one specific conflict merge. No plaintext or key is exposed to anyone who did not already hold a copy. Cross-device purge propagation for the common single-writer case is already delivered by #399's open-time purge-cleanup sweep. This slice closes the conflict-copy path.

## Design decisions (resolved during brainstorming)

1. **Reconcile in `prepare_merge`, carry on the draft — mirror `post_merge_clock`.** `prepare_merge` already folds `post_merge_clock` as a component-wise max over canonical + every copy ([`prepare.rs:523`](../../../core/src/sync/prepare.rs)). Trash reconciliation is the exact analog: fold canonical + every copy's `.trash` into a merged list, stored on `DraftMerge`. The draft is the carrier because `commit_with_decisions` only re-opens the *local* vault — the peer trash lists live in `bundle.copies`, which only `prepare_merge` sees.
2. **A dedicated pure module `core/src/vault/trash_merge.rs`.** The merge layer `conflict.rs` is already **2097 lines** — well past the 500-line split threshold. Block-level trash reconciliation is a distinct concept from record-level CRDT merge, so it gets its own focused, host-testable, side-effect-free module (pure functions, one concept).
3. **Purge is terminal — purge beats a concurrent restore.** When the merge produces a `block_uuid` that is live in `blocks` **and** purged in the unioned trash (the two copies disagreed), purge wins: the block is removed from `blocks` and kept purged-in-trash. This honors #399's "purged never un-purges" contract; letting a concurrent restore silently un-purge would violate the very monotonicity this issue exists to guarantee. **Accepted cost:** concurrent edits/restore of that block on the other device are discarded — the honest meaning of a permanent purge.
4. **Latest tombstone wins for the non-purged triple.** When the same `block_uuid` carries two *different* tombstone events, the merged entry keeps the coherent triple (`tombstoned_at_ms`, `tombstoned_by`, `fingerprint`) with the lexicographically-greatest key — a total order that guarantees a unique winner (⇒ commutative + associative). `purged_at_ms` is merged **independently** and monotonically on top.

## The pure merge — `core/src/vault/trash_merge.rs`

Two pure functions, no I/O, host-testable in isolation. This is the **normative** part covered by the KAT + clean-room + proptests.

```rust
/// Union + monotone merge of trash lists across conflict copies.
///
/// Folds every input list into a `BTreeMap<block_uuid, TrashEntry>`
/// (⇒ output sorted ascending by `block_uuid`, the manifest encoding
/// order), merging colliding `block_uuid`s pairwise via
/// [`merge_trash_entry`]. Never drops an entry; only reconciles fields.
pub fn merge_trash_lists(lists: &[&[TrashEntry]]) -> Vec<TrashEntry>;

/// Pairwise merge of two `TrashEntry` for the same `block_uuid`.
pub fn merge_trash_entry(a: &TrashEntry, b: &TrashEntry) -> TrashEntry;
```

`merge_trash_entry(a, b)` field rules:

- **Tombstone triple** — `(tombstoned_at_ms, tombstoned_by, fingerprint)` kept **coherent** (never mixed across sides) from the lexicographic-**max** of the tuple `(tombstoned_at_ms, tombstoned_by, fingerprint_key)`, where `fingerprint_key` orders `None < Some(bytes)` and `Some` compares bytewise. Latest tombstone wins; the full-tuple total order makes the winner unique regardless of argument order.
- **`purged_at_ms`** — merged **independently**: `Some` if *either* side is; take `max` of the millis; `None` loses to any `Some`. **Never un-purges.** (So an entry can keep side A's *later* tombstone triple *and* side B's purge marker — the correct monotone union.)
- **`unknown`** — unioned via the established `§11` unknown-map rule, mirroring `conformance.py::py_merge_unknown_map` (the same rule the record merge uses).

Because `merge_trash_entry` is a commutative, associative, idempotent binary merge over a total order, `merge_trash_lists` (a fold of it) inherits those properties — the same CRDT discipline as `merge_record`.

### `DraftMerge` change

Add to [`core/src/sync/draft.rs`](../../../core/src/sync/draft.rs):

```rust
    /// Union of `bundle.canonical.manifest.trash` and every
    /// `bundle.copies[*].manifest.trash`, reconciled via
    /// `trash_merge::merge_trash_lists`. Becomes `new_manifest.trash`
    /// at commit (after the live-vs-trash disjointness guard).
    /// `#[zeroize(skip)]` — `TrashEntry` carries no secret material
    /// (UUIDs, timestamps, fingerprint, unknown-map), same as the
    /// vector-clock fields already skipped.
    #[zeroize(skip)]
    pub merged_trash: Vec<TrashEntry>,
```

`prepare_merge` computes it right after `post_merge_clock`:

```rust
let trash_lists: Vec<&[TrashEntry]> = std::iter::once(bundle.canonical.manifest.trash.as_slice())
    .chain(bundle.copies.iter().map(|c| c.manifest.trash.as_slice()))
    .collect();
let merged_trash = trash_merge::merge_trash_lists(&trash_lists);
```

## Commit-level live-vs-trash resolution — purge-terminal (§3 of the brainstorm)

The invariant: in any *signed* manifest, a `block_uuid` lives in exactly one of `blocks` / `trash`. Across conflict copies the two can disagree (block live on one copy, trashed on another), so `commit_with_decisions` resolves the collision after applying `merged_trash`:

For each entry in `draft.merged_trash` whose `block_uuid` is **also live** in `new_manifest.blocks`:

- **Purged (`purged_at_ms.is_some()`) → purge wins.** Remove the `block_uuid` from `new_manifest.blocks`; keep it as a purged trash entry. (Terminal purge beats a concurrent restore/edit.)
- **Non-purged (`purged_at_ms.is_none()`) → live wins.** Drop the trash entry; keep the block live. (Delete-vs-edit: err toward never silently losing data; deterministic, unlike today's canonical-dependent flip.)

Either way the signed manifest stays well-formed (disjoint `blocks` / `trash`). `new_manifest.trash` is then set to the surviving reconciled list. This is the **only** touch of block-list logic in this slice.

### Physical-file completion — the sweep extension

Purge-terminal at the manifest level leaves the *merging* device (the one that had the block restored-live) still holding `blocks/<uuid>.cbor.enc` — an orphan the purge was supposed to destroy. Leaving it would be an incomplete purge (ciphertext lingering on that device).

`commit_with_decisions` continues to do **only** manifest work (it never deletes block files — the block-first/manifest-last atomic ordering is preserved). Physical destruction stays the sweep's job, exactly as in #399. So extend the existing open-time sweep [`repair/sweep.rs::sweep_purged_trash_files`](../../../core/src/vault/repair/sweep.rs): for a `TrashEntry` with `purged_at_ms.is_some()` whose `block_uuid` is **not live** in `manifest.blocks`, best-effort unlink **both** the `trash/<uuid>.cbor.enc.*` residue (today's behavior) **and** the `blocks/<uuid>.cbor.enc` residue (new). The sweep runs *after* manifest authentication, so a forged marker cannot drive a delete, and it is gated on "not live in `manifest.blocks`" so a concurrent restore that legitimately won is never touched.

Walking a purge-vs-restore race end to end (device L purges block X while device P concurrently restores it):

1. On L: X was trashed→purged; `trash/X` already unlinked; L's manifest has X purged-in-trash. L holds no X ciphertext.
2. On P: X restored trash→blocks; P holds `blocks/X`; P's manifest has X live.
3. Merge (purge-terminal): merged manifest = X purged-in-trash, **not** in `blocks`. Well-formed. Syncs to both.
4. Next open on L: X purged & not-live → sweep tries `trash/X` (gone) + `blocks/X` (gone) → no-op. Consistent.
5. Next open on P: X purged & not-live → sweep unlinks the orphan `blocks/X`. Now P honors the purge too.

Result: consistent, well-formed, purge-honored on both devices — the guarantee choice A promises.

## Normative spec updates

Per the "docs are the contract" rule, the spec is updated first:

- **`docs/crypto-design.md §11` (merge):** add the trash-list merge semantics — union keyed by `block_uuid`; latest-tombstone-wins total order for the triple; independent monotone `purged_at_ms` (`Some`-if-either, max millis, `None`<`Some`, never un-purges); `unknown`-map union. State the four CRDT properties hold.
- **`docs/vault-format.md §7`:** document the commit-level purge-terminal live-vs-trash collision rule and the sweep's extension to `blocks/` residue for purged, not-live entries.

## Testing (TDD — tests first)

**Split by layer.** The *list-level* semantics are pure and get the KAT + clean-room + proptest treatment; the *commit-level* purge-terminal guard + sweep extension exercise fs + manifest signing and get Rust integration tests.

**Pure merge (`core/src/vault/trash_merge.rs` unit tests + `core/tests/proptest.rs`):**
- Unit: union of disjoint lists; collision with different tombstone triples → latest wins; `purged` Some-if-either + max millis; `None` loses to `Some`; a later-triple side that is *unpurged* still inherits the other side's purge marker; `unknown`-map union.
- Proptest — the same 4 the record merge holds, plus purge monotonicity:
  1. **commutativity** `merge(a,b) == merge(b,a)`
  2. **associativity** `merge(merge(a,b),c) == merge(a,merge(b,c))`
  3. **idempotence** `merge(a,a) == a`
  4. **well-formedness** output sorted ascending by `block_uuid`, no duplicate `block_uuid`
  5. **purge monotonicity** merge never clears a `Some(purged)` and never lowers its millis
  over arbitrary trash lists incl. colliding `block_uuid`s and arbitrary `unknown` keys.

**KAT (`core/tests/data/trash_merge_kat.json` — a new, separate file):** trash-merge vector(s) covering union, purged Some-if-either + max millis, `None`-loses-to-`Some`, and the triple tie-break. Kept out of `conflict_kat.json` to keep both files small and single-purpose (record/block CRDT vs. block-level trash reconciliation). Replayed in Rust by a new `trash_merge_kat_replays_match_rust` test in [`core/tests/conflict.rs`](../../../core/tests/conflict.rs) (sibling to `kat_replays_match_rust_merge`) driving the vectors through `merge_trash_lists`.

**Clean-room (`core/tests/python/conformance.py`):** add `py_merge_trash` implementing the §11 trash-merge from the docs alone, and replay the new `trash_merge_kat.json` vectors — the cross-language witness proving the spec is self-sufficient.

**Commit-level integration (`core/tests/conflict.rs`):**
- Purge-vs-restore conflict fixture: X purged on one copy, live on the other → merged manifest has X purged-in-trash, absent from `blocks`, signature verifies, and re-open + sweep unlinks the `blocks/X` orphan.
- Non-purged delete-vs-live collision → live wins (X live, trash entry dropped), well-formed manifest.
- Purge propagation with no live collision (both sides trashed, one purged) → merged trash carries the purge marker (the primary #401 win).
- `blocks/`-orphan sweep unit test: a purged, not-live entry with a `blocks/<uuid>` residue → sweep removes it.

## Non-goals / guardrails

- **No FFI / bridge / desktop / mobile change.** The merged manifest is internal to the sync merge; no binding surface moves, so no `FfiVaultError` variant, no conformance-harness churn.
- **No new crypto, no new signature/KEM site, no `manifest_version` bump.** Trash reconciliation is CRDT-merge logic over already-signed manifest fields; `#![forbid(unsafe_code)]` intact.
- **Block-list reconciliation stays as-is beyond the disjointness guard.** Copy-only block adoption and general live-vs-trash resurrection remain pre-existing merge limitations, untouched — the purge-terminal guard is the *only* block-list mutation, and only to preserve disjointness + purge monotonicity.
- **`commit_with_decisions` never deletes block files.** Physical purge destruction stays the crash-safe, manifest-authenticated sweep's job (guard comment at the sweep site preserved). The commit remains block-first/manifest-last.
- **Do not weaken any proptest.** If the trash-merge properties require a proptest to relax, that is a design problem — push back (same rule as the record merge).

## Acceptance

```bash
cd /Users/hherb/src/secretary/.worktrees/trash-merge-401
cargo test --release -p secretary-core trash_merge              # pure merge unit tests
cargo test --release --workspace --test conflict                # KAT replay + commit integration
cargo test --release --workspace --test proptest                # 5 trash-merge properties
cargo test --release --workspace                                # full suite green
cargo test --release --workspace --features differential-replay # cross-language replay green
cargo clippy --release --workspace --tests -- -D warnings       # clean
cargo fmt --all --check                                         # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace      # clean
uv run core/tests/python/conformance.py                        # py_merge_trash replays the new KAT
```

Close #401 on merge. No deferred non-actions beyond the pre-existing block-list reconciliation limitations noted under guardrails (unchanged by this slice).
