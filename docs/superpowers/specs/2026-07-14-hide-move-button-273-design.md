# Design — hide per-record Move button when no other blocks (#273, desktop)

**Date:** 2026-07-14
**Issue:** [#273](https://github.com/hherb/secretary/issues/273) — *Desktop: hide per-record Move button when the vault has no other blocks*
**Scope:** Desktop only (Tauri/Svelte). Android + iOS parity tracked as a separate follow-up.

## Problem

The per-record **Move** button (`RecordRow.svelte`) renders on every live record. In a
vault with only one block there is nowhere to move a record to: clicking Move opens
`MoveTargetPicker`, which enumerates `listBlocks()` minus the source block and, finding
none, shows the empty state *"No other blocks to move into."* plus Cancel.

The flow is already **functionally correct** — the picker's empty-state guard prevents a
broken flow, and `move_record_impl`'s same-block guard would reject a same-block move
anyway. But offering an affordance that can only dead-end is mild UX noise. The polish is
to hide the Move button when there are no candidate target blocks (live block count ≤ 1).

## Approaches considered

- **A — thread the block count from the parent (chosen).** `Vault.svelte` already holds
  the authoritative `manifest.blockCount` (rendered today as the "N blocks" label). Pass
  it into `RecordList`, which conditionally wires `onMove`. **No extra IPC**; reactive to
  `refreshManifest()`; reuses `RecordRow`'s existing `{#if onMove}` gate, so `RecordRow`
  needs no change.
- **B — extra `listBlocks()` call inside `RecordList`.** Self-contained but adds an IPC
  round-trip on every record-list load and duplicates the picker's own fetch. Rejected as
  heavier for no benefit — the manifest count is already in hand upstream.

## Design (Approach A)

### 1. Pure helper — `desktop/src/lib/blockCrud.ts`

A new pure, unit-testable predicate beside the existing `isSameBlock` / `isBlankName`
guards (the module's stated purpose is "pure pre-check guards for the block-CRUD UI"):

```ts
/** Minimum live-block count for a record move to have a destination: the
 *  record's own block plus at least one distinct target block. */
const MIN_BLOCKS_TO_MOVE = 2;

/** True when at least one block OTHER than the record's own exists, so a move
 *  has a real destination. `blockCount` is the manifest's live-block count —
 *  the same set `MoveTargetPicker` enumerates (minus the source block). Below
 *  the threshold the Move affordance can only dead-end, so it is hidden. */
export function hasMoveTargets(blockCount: number): boolean {
  return blockCount >= MIN_BLOCKS_TO_MOVE;
}
```

No magic number: the threshold is the named `MIN_BLOCKS_TO_MOVE` constant with a
documented rationale.

### 2. `desktop/src/components/RecordList.svelte`

- Add a required prop `blockCount: number` to the component's `Props`.
- Derive the affordance: `let canMove = $derived(hasMoveTargets(blockCount));`
- Change the row wiring in the `{#each}` from the `{onMove}` shorthand to
  `onMove={canMove ? onMove : undefined}`. When `canMove` is false the child receives
  `undefined` and its existing `{#if onMove}` gate hides the button.

`blockCount` is a **required** prop (not defaulted) so `svelte-check` enforces that every
call site supplies it — a forgotten count fails the type gate rather than silently
defaulting to a wrong affordance.

### 3. `desktop/src/routes/Vault.svelte`

At the `records`-level mount, pass the manifest count:

```svelte
<RecordList block={$browseNav.block} blockCount={manifest.blockCount} />
```

`manifest` is `unlocked.manifest`, already reactive; a block create/trash triggers
`refreshManifest()`, so `blockCount` — and therefore the Move affordance — updates on the
next render without extra wiring.

## Data flow

```
manifest.blockCount ──▶ Vault.svelte ──prop──▶ RecordList
                                                  │ hasMoveTargets(blockCount)
                                                  ▼
                              onMove = canMove ? onMove : undefined
                                                  │
                                                  ▼
                                   RecordRow  {#if onMove} → Move button
```

## Correctness / edge cases

- `blockCount` 0 or 1 → Move hidden; `blockCount ≥ 2` → Move shown.
- **Layered, not load-bearing.** This is a UX optimization on top of existing guards, not
  the sole safety. The picker's empty-state message and the Rust same-block rejection stay
  in place. If `listBlocks()` and `manifest.blockCount` ever diverge (e.g. one counting
  trashed blocks and the other not), the worst case is a momentarily-shown button that
  dead-ends into the existing empty-state — never an incorrect move.
- Trashed blocks are excluded from both `manifest.blockCount` and `listBlocks()` today, so
  the guard agrees with the picker's candidate set in the common case.

## Testing (TDD)

1. **Unit — `desktop/tests/blockCrud.test.ts`** (append): `hasMoveTargets` returns
   `false` for 0 and 1, `true` for 2 and 3 (threshold boundary pinned).
2. **Component — `desktop/tests/RecordListMove.test.ts`** (append): rendering `RecordList`
   with `blockCount: 1` shows **no** "Move record" button; with `blockCount: 2` the button
   renders. Follows the existing `@testing-library/svelte` render + `getByRole` pattern.
3. **Prop propagation:** the existing `RecordList` render sites in
   `RecordList.test.ts` / `RecordListDelete.test.ts` / `RecordListRestore.test.ts` /
   `RecordListMove.test.ts` gain a `blockCount` prop (required). Delete/restore/base
   assertions are unaffected by its value; a realistic `2` keeps their Move affordance
   as before.

Gate: `cd desktop && pnpm test` (vitest, host) and `pnpm exec svelte-check` (the desktop
type gate — required-prop enforcement is only caught here, per project convention).

## Out of scope

- Android / iOS parity (both currently always show Move). Filed as a follow-up so the
  parity gap is tracked; a note is added to #273.
- Any change to `MoveTargetPicker`, `move_record_impl`, or the manifest shape.
