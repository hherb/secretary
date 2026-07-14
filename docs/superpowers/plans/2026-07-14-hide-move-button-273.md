# Hide per-record Move button when no other blocks (#273) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hide the per-record Move button on the desktop client when the vault has no other block to move a record into (live block count ≤ 1).

**Architecture:** Thread the authoritative `manifest.blockCount` from `Vault.svelte` into `RecordList`, which uses a new pure `hasMoveTargets()` helper to conditionally wire `onMove`; `RecordRow`'s existing `{#if onMove}` gate then hides the button. No extra IPC, no `RecordRow` change.

**Tech Stack:** Svelte 5 (runes), TypeScript, Vitest + @testing-library/svelte (v5), Tauri 2 desktop.

## Global Constraints

- Desktop only. No Android/iOS change in this plan (parity filed as a follow-up).
- No new magic numbers — the move-threshold is a named constant with a doc comment.
- Pure helpers stay pure and unit-tested (`blockCrud.ts` convention).
- The desktop type gate is **svelte-check**, not `tsc` — required-prop enforcement is only caught by `pnpm run svelte-check` (there is no `typecheck` script; see #394).
- All commands run from `desktop/`: tests `pnpm test`, type gate `pnpm run svelte-check`, lint `pnpm run lint`.
- This guard is a UX layer on top of the existing `MoveTargetPicker` empty-state and `move_record_impl` same-block guard — it must not remove or weaken either.

## File Structure

- `desktop/src/lib/blockCrud.ts` — **modify**: add `MIN_BLOCKS_TO_MOVE` const + `hasMoveTargets()` pure predicate beside the existing `isBlankName` / `isSameBlock` guards.
- `desktop/tests/blockCrud.test.ts` — **modify**: unit tests for `hasMoveTargets`.
- `desktop/src/components/RecordList.svelte` — **modify**: add required `blockCount: number` prop; derive `canMove`; conditionally pass `onMove`.
- `desktop/src/routes/Vault.svelte` — **modify** (line 143): pass `blockCount={manifest.blockCount}`.
- `desktop/tests/RecordListMove.test.ts` — **modify**: 2 new render-gating tests; add `blockCount` to the 2 existing render sites.
- `desktop/tests/RecordList.test.ts`, `RecordListDelete.test.ts`, `RecordListRestore.test.ts` — **modify**: add `blockCount` to their existing `RecordList` render sites (required-prop propagation).

---

### Task 1: Pure `hasMoveTargets` helper

**Files:**
- Modify: `desktop/src/lib/blockCrud.ts`
- Test: `desktop/tests/blockCrud.test.ts`

**Interfaces:**
- Produces: `hasMoveTargets(blockCount: number): boolean` — `true` iff `blockCount >= 2`.

- [ ] **Step 1: Write the failing tests**

Edit `desktop/tests/blockCrud.test.ts`. Change the import on line 2 to add `hasMoveTargets`:

```ts
import { isBlankName, isSameBlock, hasMoveTargets } from '../src/lib/blockCrud';
```

Add these two `it` blocks inside the existing `describe('blockCrud pure guards', …)` (before its closing `});`):

```ts
  it('hasMoveTargets: fewer than two blocks has no move destination', () => {
    expect(hasMoveTargets(0)).toBe(false);
    expect(hasMoveTargets(1)).toBe(false);
  });
  it('hasMoveTargets: two or more blocks has a move destination', () => {
    expect(hasMoveTargets(2)).toBe(true);
    expect(hasMoveTargets(3)).toBe(true);
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd desktop && pnpm test blockCrud`
Expected: FAIL — `hasMoveTargets is not a function` (or an import error).

- [ ] **Step 3: Implement the helper**

Append to `desktop/src/lib/blockCrud.ts` (after `isSameBlock`):

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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd desktop && pnpm test blockCrud`
Expected: PASS (all `blockCrud pure guards` tests, including the two new ones).

- [ ] **Step 5: Commit**

```bash
cd desktop && git add src/lib/blockCrud.ts tests/blockCrud.test.ts
git commit -m "feat(desktop): hasMoveTargets pure guard for the Move affordance (#273)"
```

---

### Task 2: Wire the guard into RecordList + Vault

**Files:**
- Modify: `desktop/src/components/RecordList.svelte`
- Modify: `desktop/src/routes/Vault.svelte` (line 143)
- Test: `desktop/tests/RecordListMove.test.ts`
- Modify (prop propagation): `desktop/tests/RecordList.test.ts`, `desktop/tests/RecordListDelete.test.ts`, `desktop/tests/RecordListRestore.test.ts`

**Interfaces:**
- Consumes: `hasMoveTargets(blockCount)` from Task 1.
- Produces: `RecordList` now requires a `blockCount: number` prop; when `hasMoveTargets(blockCount)` is false the per-row Move button is not rendered.

- [ ] **Step 1: Write the failing render-gating tests**

Append these two `it` blocks to `desktop/tests/RecordListMove.test.ts`, inside `describe('RecordList move flow', …)` (before its closing `});`). They reuse the file's existing `block` and `rec` fixtures:

```ts
  it('hides the Move button when the vault has no other block (blockCount 1)', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === 'read_block'
        ? Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] })
        : Promise.resolve(null)
    );
    const { findByRole, queryByRole } = render(RecordList, { props: { block, blockCount: 1 } });
    // Delete is unconditional for a live record — wait on it so the row has rendered.
    await findByRole('button', { name: /delete record/i });
    expect(queryByRole('button', { name: /move record/i })).toBeNull();
  });

  it('shows the Move button when the vault has another block (blockCount 2)', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === 'read_block'
        ? Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] })
        : Promise.resolve(null)
    );
    const { findByRole } = render(RecordList, { props: { block, blockCount: 2 } });
    await findByRole('button', { name: /move record/i });
  });
```

- [ ] **Step 2: Run the new tests to verify the hide-case fails**

Run: `cd desktop && pnpm test RecordListMove`
Expected: the `blockCount 1` test FAILS — the Move button is still rendered (RecordList ignores `blockCount` today), so `queryByRole` returns a node, not `null`. The `blockCount 2` test passes (Move is currently always shown).

- [ ] **Step 3: Implement the RecordList change**

Edit `desktop/src/components/RecordList.svelte`:

Add `hasMoveTargets` to the `blockCrud` import — insert this import near the other `../lib/*` imports at the top of `<script>`:

```ts
  import { hasMoveTargets } from '../lib/blockCrud';
```

Change the `Props` type and destructure (currently `type Props = { block: BlockSummaryDto };` / `let { block }: Props = $props();`) to:

```ts
  type Props = { block: BlockSummaryDto; blockCount: number };
  let { block, blockCount }: Props = $props();

  // Hide the per-record Move button when there is nowhere to move to: a vault
  // with only this block has no candidate target (MoveTargetPicker would only
  // show its empty state). Reactive — a block create/trash refreshes the count.
  let canMove = $derived(hasMoveTargets(blockCount));
```

Change the `RecordRow` mount (currently `<RecordRow {record} onClick={openRecord} {onDelete} {onRestore} {onMove} />`) to pass `onMove` conditionally:

```svelte
      <RecordRow {record} onClick={openRecord} {onDelete} {onRestore} onMove={canMove ? onMove : undefined} />
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `cd desktop && pnpm test RecordListMove`
Expected: the `blockCount 1` and `blockCount 2` tests PASS. The two pre-existing move tests in this file will now FAIL — they render `{ props: { block } }` with no `blockCount`, so `hasMoveTargets(undefined)` is false and their Move button is gone. Fixed in Step 5.

- [ ] **Step 5: Add `blockCount` to the two pre-existing RecordListMove render sites**

In `desktop/tests/RecordListMove.test.ts`, both existing renders read `render(RecordList, { props: { block } })`. Change each to:

```ts
render(RecordList, { props: { block, blockCount: 2 } })
```

(`blockCount: 2` keeps the Move button shown, matching those tests' assumptions.)

- [ ] **Step 6: Update the production call site in Vault.svelte**

Edit `desktop/src/routes/Vault.svelte` line 143. Change:

```svelte
      <RecordList block={$browseNav.block} />
```

to:

```svelte
      <RecordList block={$browseNav.block} blockCount={manifest.blockCount} />
```

(`manifest` is already in scope at that point — see the `{@const manifest = unlocked.manifest}` on line 100 and its use on line 124.)

- [ ] **Step 7: Add `blockCount` to the remaining existing RecordList render sites**

`blockCount` is now required, so `svelte-check` fails on every render site that omits it. Update these:

- `desktop/tests/RecordListRestore.test.ts` — 4 sites, all `render(RecordList, { props: { block: BLOCK } })` → `render(RecordList, { props: { block: BLOCK, blockCount: 2 } })`.
- `desktop/tests/RecordListDelete.test.ts` — 5 sites, same replacement (`props: { block: BLOCK }` → `props: { block: BLOCK, blockCount: 2 }`).
- `desktop/tests/RecordList.test.ts` — 3 single-line sites (`props: { block: BLOCK }` → `props: { block: BLOCK, blockCount: 2 }`), plus the one **bare-props** site at lines 68-70:

```ts
    const { getByText } = render(RecordList, {
      block: { blockUuidHex: 'deadbeef', blockName: 'Logins', lastModifiedMs: 0, createdAtMs: 0 },
      blockCount: 2
    });
```

- [ ] **Step 8: Run the full desktop suite + type gate + lint**

Run: `cd desktop && pnpm test`
Expected: PASS — the whole vitest suite is green.

Run: `cd desktop && pnpm run svelte-check`
Expected: 0 errors (required `blockCount` satisfied at every render site + the Vault production site).

Run: `cd desktop && pnpm run lint`
Expected: clean.

- [ ] **Step 9: Commit**

```bash
cd desktop && git add src/components/RecordList.svelte src/routes/Vault.svelte \
  tests/RecordListMove.test.ts tests/RecordList.test.ts \
  tests/RecordListDelete.test.ts tests/RecordListRestore.test.ts
git commit -m "feat(desktop): hide per-record Move button when no other blocks (#273)"
```

---

## Post-implementation (session wrap, not a code task)

- File an Android + iOS parity follow-up issue (both platforms currently always show Move) and add a note on #273 pointing to it, so the parity gap is tracked, not lost.
- README/ROADMAP check: this is a small desktop UX polish with no new feature surface — confirm neither needs an edit (expected: no change, consistent with prior cosmetic slices).
- Push the branch, open the PR, author the handoff (symlink retarget), per the session workflow.

## Self-Review

- **Spec coverage:** helper (Task 1) ✓; RecordList prop + conditional onMove (Task 2 Steps 3) ✓; Vault threading (Task 2 Step 6) ✓; unit tests (Task 1) ✓; component render tests (Task 2 Step 1) ✓; existing-render-site propagation (Task 2 Steps 5, 7) ✓; layered-guard preservation (no change to picker/`move_record_impl`) ✓; scope note + parity follow-up (Post-implementation) ✓.
- **Placeholder scan:** none — every code and command step is concrete.
- **Type consistency:** `hasMoveTargets(blockCount: number): boolean` used identically in Task 1 (definition), the `blockCrud` import, and the `canMove` derivation; `blockCount: number` prop name consistent across RecordList, Vault, and all test render sites.
