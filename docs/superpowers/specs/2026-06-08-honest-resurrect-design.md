# Honest resurrect for no-content tombstones — design (#196)

**Date:** 2026-06-08
**Issue:** [#196](https://github.com/hherb/secretary/issues/196)
**Scope:** desktop-only (no `core`, no FFI, no on-disk-format change)

## Problem

The per-record **resurrect** control (the D.1.5 "Show deleted" → Restore surface)
behaves differently depending on how the record was tombstoned, with no signal to
the user:

- **Local delete** keeps the record's fields (`tombstone_record` in
  `ffi/secretary-ffi-bridge/src/edit/tombstone.rs`: *"Fields are NOT cleared — the
  record stays fully resurrectable."*). Resurrect restores the content — lossless.
- **Merge tombstone** (accepting a sync delete) empties the fields per §11.3
  (`core/src/vault/conflict.rs`: *"a tombstoned merged record carries empty `fields`
  regardless of either input's fields"* → `(BTreeMap::new(), Vec::new())`).
  Resurrect then brings back an **empty shell** (uuid + type + tags only).

The same Restore button yields content in one case and an empty record in the other,
and the user can't tell which they are looking at. An empty result with no explanation
reads as data loss / a broken undelete. This is **§11.3-correct** behavior — "Accept
delete" means the other device's deletion wins and the local payload is intentionally
discarded — but the UX hides that from the user.

## Key reframe: detect content-emptiness, not tombstone provenance

The issue frames the hard part as *distinguishing a merge-tombstone from a local
tombstone* — which would require recording provenance on the **frozen** on-disk record
format and risk perturbing the CRDT merge proptests.

That distinction is not actually needed. What we want to tell the user is *"will
resurrect give you back something useful?"* — and that is answerable directly from data
the desktop **already has on the wire**. `RecordDto` carries both `tombstoned` and
`fieldCount`:

- a merge-tombstoned record arrives with `fieldCount === 0` (§11.3 dropped its fields);
- a locally-deleted record keeps `fieldCount > 0`.

So the signal is simply **`tombstoned === true && fieldCount === 0`**. No `core` change,
no on-disk-format perturbation, no CRDT proptest risk. The slice is desktop-only, and
therefore does **not** require the cross-language conformance run (Swift/Kotlin/Python) —
only the desktop gauntlet.

> Edge note: a genuinely-empty record that was *locally* deleted also matches this
> predicate. That is acceptable and in fact correct — resurrecting it would equally yield
> an empty shell, so warning is honest. The user-facing copy is therefore phrased around
> *content-emptiness*, not around an asserted "deleted on another device" provenance.

## Design

### 1. Pure predicate — new reusable module `desktop/src/lib/records.ts`

A new one-concept module for record-display derivations (keeps the predicate free,
side-effect-free, and independently testable — per the project's "pure functions in
reusable modules" principle, and avoids bloating `editor.ts`/`browse.ts`, which own
unrelated concerns):

```ts
import type { RecordDto } from './ipc';

/**
 * True iff resurrecting this record would yield an empty shell — a tombstoned
 * record whose fields were dropped. The §11.3 merge-tombstone path empties a
 * record's fields; a local delete preserves them. We key on content-emptiness
 * (not tombstone provenance) because that is exactly the user-facing fact —
 * "there is nothing to restore" — and it needs no provenance flag on the
 * frozen on-disk format.
 */
export function isContentlessTombstone(record: RecordDto): boolean {
  return record.tombstoned === true && record.fieldCount === 0;
}
```

### 2. Row hint — `RecordRow.svelte`

When `isContentlessTombstone(record)`, render a muted badge after the meta line
(e.g. `· no recoverable contents`) and fold the same text into the row's `aria-label`
so assistive tech receives it. The Restore button itself is unchanged. This pre-empts
the surprise *before* the user clicks.

### 3. Confirm gate on resurrect — `RecordList.svelte`

`onRestore(record)` branches:

- **contentless tombstone** → set `pendingRestore = record`, mounting a second
  `ConfirmDialog` (the same component the delete flow already uses).
- **has content** → resurrect immediately (today's one-click behavior, unchanged).

A new `confirmRestore()` performs the actual `resurrectRecord` + `load()` (mirroring
`confirmDelete`). `pendingRestore` is nulled on confirm and on cancel.

Confirm copy (content-based, honest, not provenance-asserting):

> **Resurrect an empty record?**
> This record has no stored contents to recover — resurrecting brings it back with only
> its type and tags. (Contents are discarded when a record's deletion is merged from
> another device.)
>
> confirmLabel: **Resurrect**

### 4. Tests (vitest)

- `desktop/src/lib/records.test.ts` — predicate truth table:
  tombstoned + 0 fields → `true`; tombstoned + N fields → `false`;
  live + 0 fields → `false`; live + N fields → `false`;
  `tombstoned` undefined → `false`.
- `RecordRow` test — the badge renders **iff** contentless tombstone, and the
  `aria-label` includes the hint text; a has-content tombstone and a live row do not.
- `RecordList` test —
  - resurrecting a contentless tombstone opens the confirm and does **not** call
    `resurrectRecord` until confirmed;
  - confirm → calls `resurrectRecord` + reloads;
  - cancel → no IPC call, dialog closes;
  - resurrecting a has-content tombstone → immediate `resurrectRecord`, no confirm.

### 5. Manual GUI smoke (the one gate)

Reuse the #195 `stage_smoke_vault` helper on a `cp -R` temp copy of the golden vault to
produce a real merge-tombstone, then verify end-to-end:

1. `SMOKE_OUT=/tmp/veto_smoke cargo test --release -p secretary-cli --test sync_pass_integration -- --ignored stage_smoke_vault --nocapture`
2. `cd desktop && pnpm tauri dev`, open `/tmp/veto_smoke`, **Sync now** → resolution
   modal → **Accept delete** (merge-tombstones the record).
3. Enable **Show deleted** → the row shows the `no recoverable contents` badge.
4. Click **Restore** → the confirm appears with the empty-record copy.
5. Confirm → the empty record comes back (expected now, and explained); the badge is
   gone (it is live). Cancel on a fresh run → no change, dialog closes.

## Out of scope (YAGNI)

- No provenance flag, no `core` / bridge / on-disk-format change.
- No reveal of winner/loser field values (that is the separate "reveal-to-decide" slice).
- No change to has-content (local-delete) resurrect — it stays one-click.

## Verification

Desktop gauntlet only (Rust workspace untouched, so still green):

```
cd desktop
pnpm test         # records.test.ts + RecordRow + RecordList assertions
pnpm typecheck
pnpm svelte-check
pnpm lint
```

Cross-language conformance is **not** required (no FFI surface change).
