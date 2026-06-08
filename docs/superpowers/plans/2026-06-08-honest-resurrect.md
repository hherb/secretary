# Honest Resurrect for No-Content Tombstones — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the silent "empty record" surprise when resurrecting a merge-tombstoned record — pre-empt it with a row hint and a confirm dialog, keyed on content-emptiness.

**Architecture:** Desktop-only. `RecordDto` already carries `tombstoned` and `fieldCount`, so a no-content tombstone (`tombstoned && fieldCount === 0`) is detectable in the UI with no `core`/FFI/on-disk-format change. A pure predicate drives both a `RecordRow` badge and a `RecordList` confirm gate; has-content resurrect stays one-click.

**Tech Stack:** Svelte 5 (runes), TypeScript, Vitest + `@testing-library/svelte`, jsdom. All work under `desktop/`.

**Spec:** [`docs/superpowers/specs/2026-06-08-honest-resurrect-design.md`](../specs/2026-06-08-honest-resurrect-design.md)

**Working directory:** `/Users/hherb/src/secretary/.worktrees/honest-resurrect` on branch `feature/honest-resurrect`. All `pnpm`/`git` commands below assume you have `cd`'d into `desktop/` for `pnpm` and the worktree root for `git` — chain `cd` in each Bash call (shell state does not persist between calls).

---

### Task 1: Pure predicate `isContentlessTombstone`

**Files:**
- Create: `desktop/src/lib/records.ts`
- Test: `desktop/tests/records.test.ts`

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/records.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { isContentlessTombstone } from '../src/lib/records';
import type { RecordDto } from '../src/lib/ipc';

const base: RecordDto = {
  recordUuidHex: 'cd',
  recordType: 'login',
  tags: [],
  createdAtMs: 1,
  lastModMs: 2,
  fieldCount: 0,
  fields: []
};

describe('isContentlessTombstone', () => {
  it('is true for a tombstoned record with zero fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: true, fieldCount: 0 })).toBe(true);
  });

  it('is false for a tombstoned record that still has fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: true, fieldCount: 3 })).toBe(false);
  });

  it('is false for a live record with zero fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: false, fieldCount: 0 })).toBe(false);
  });

  it('is false for a live record with fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: false, fieldCount: 3 })).toBe(false);
  });

  it('is false when tombstoned is undefined', () => {
    expect(isContentlessTombstone({ ...base, fieldCount: 0 })).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop && pnpm vitest run tests/records.test.ts`
Expected: FAIL — `Failed to resolve import "../src/lib/records"` (module does not exist yet).

- [ ] **Step 3: Write minimal implementation**

Create `desktop/src/lib/records.ts`:

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

- [ ] **Step 4: Run test to verify it passes**

Run: `cd desktop && pnpm vitest run tests/records.test.ts`
Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/honest-resurrect
git add desktop/src/lib/records.ts desktop/tests/records.test.ts
git commit -m "feat(desktop): isContentlessTombstone predicate (#196)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `RecordRow` — no-recoverable-contents badge + aria-label

**Files:**
- Modify: `desktop/src/components/RecordRow.svelte`
- Test: `desktop/tests/RecordRow.test.ts`

- [ ] **Step 1: Write the failing test**

Append these cases to `desktop/tests/RecordRow.test.ts` inside the existing `describe('RecordRow', ...)` block (after the existing `it(...)` calls). Also add `queryByText`/`getByRole` usage — they come from the same `render` return:

```ts
  it('shows a "no recoverable contents" hint for a contentless tombstone', () => {
    const rec: RecordDto = { ...REC, tombstoned: true, fieldCount: 0 };
    const { getByText, getByRole } = render(RecordRow, { props: { record: rec, onClick: () => {} } });
    expect(getByText(/no recoverable contents/i)).toBeTruthy();
    // The main row button folds the hint into its accessible name.
    expect(getByRole('button', { name: /no recoverable contents/i })).toBeTruthy();
  });

  it('shows no hint for a tombstone that still has fields', () => {
    const rec: RecordDto = { ...REC, tombstoned: true, fieldCount: 4 };
    const { queryByText } = render(RecordRow, { props: { record: rec, onClick: () => {} } });
    expect(queryByText(/no recoverable contents/i)).toBeNull();
  });

  it('shows no hint for a live record', () => {
    const { queryByText } = render(RecordRow, { props: { record: REC, onClick: () => {} } });
    expect(queryByText(/no recoverable contents/i)).toBeNull();
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop && pnpm vitest run tests/RecordRow.test.ts`
Expected: FAIL — the new `getByText(/no recoverable contents/i)` finds nothing.

- [ ] **Step 3: Write minimal implementation**

Edit `desktop/src/components/RecordRow.svelte`.

In the `<script>` block, add the import and two derived values. After the existing import lines (lines 2-3) add:

```ts
  import { isContentlessTombstone } from '../lib/records';
```

After the existing `let deleted = $derived(record.tombstoned === true);` line, add:

```ts
  let contentless = $derived(isContentlessTombstone(record));
  let ariaLabel = $derived(
    contentless
      ? `${record.recordType} record, ${countLabel}, no recoverable contents`
      : `${record.recordType} record, ${countLabel}`
  );
```

Change the main button's `aria-label` from:

```svelte
    aria-label={`${record.recordType} record, ${countLabel}`}
```

to:

```svelte
    aria-label={ariaLabel}
```

Then, inside the main button, immediately after the meta `<span>` (the `record-row__meta` line), add the visible hint:

```svelte
    {#if contentless}
      <span class="record-row__no-content">· no recoverable contents</span>
    {/if}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd desktop && pnpm vitest run tests/RecordRow.test.ts`
Expected: PASS — all original + 3 new tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/honest-resurrect
git add desktop/src/components/RecordRow.svelte desktop/tests/RecordRow.test.ts
git commit -m "feat(desktop): RecordRow no-recoverable-contents hint (#196)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `RecordList` — confirm gate on contentless resurrect

**Files:**
- Modify: `desktop/src/components/RecordList.svelte`
- Test: `desktop/tests/RecordListRestore.test.ts` (new)

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/RecordListRestore.test.ts` (mirrors the structure of `RecordListDelete.test.ts`):

```ts
// Tests for the RecordList resurrect gate: a contentless tombstone
// (fieldCount 0) routes through a ConfirmDialog before resurrect_record;
// a tombstone that still has fields resurrects one-click.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import RecordList from '../src/components/RecordList.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'Personal logins', createdAtMs: 1, lastModifiedMs: 2 };

const EMPTY_TOMBSTONE = {
  recordUuidHex: 'cd', recordType: 'login', tags: [] as string[],
  fieldCount: 0, lastModMs: 5, tombstoned: true, fields: []
};
const FILLED_TOMBSTONE = {
  recordUuidHex: 'ef', recordType: 'login', tags: [] as string[],
  fieldCount: 2, lastModMs: 5, tombstoned: true, fields: []
};

function mockReadReturning(record: unknown) {
  invokeMock.mockImplementation((cmd: string) => {
    if (cmd === 'read_block') {
      return Promise.resolve({ blockUuidHex: 'ab', blockName: 'Personal logins', records: [record] });
    }
    return Promise.resolve(null); // resurrect_record + any teardown invoke
  });
}

const calledResurrect = () => invokeMock.mock.calls.some(([c]) => c === 'resurrect_record');

describe('RecordList — contentless resurrect confirm gate', () => {
  beforeEach(() => invokeMock.mockReset());

  it('opens a confirm and does NOT resurrect until confirmed', async () => {
    mockReadReturning(EMPTY_TOMBSTONE);
    const { getByLabelText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    // ConfirmDialog mounts; resurrect must not have fired yet.
    await waitFor(() => {
      if (!container.querySelector('.confirm-dialog__button--danger')) {
        throw new Error('confirm dialog not yet mounted');
      }
    });
    expect(calledResurrect()).toBe(false);
  });

  it('confirming invokes resurrect_record and reloads', async () => {
    mockReadReturning(EMPTY_TOMBSTONE);
    const { getByLabelText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    const confirmBtn = await waitFor(() => {
      const el = container.querySelector('.confirm-dialog__button--danger');
      if (!el) throw new Error('confirm dialog not yet mounted');
      return el as HTMLButtonElement;
    });
    await fireEvent.click(confirmBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('resurrect_record', { blockUuidHex: 'ab', recordUuidHex: 'cd' })
    );
    await waitFor(() =>
      expect(invokeMock.mock.calls.filter(([c]) => c === 'read_block').length).toBeGreaterThanOrEqual(2)
    );
  });

  it('cancelling closes the dialog without resurrecting', async () => {
    mockReadReturning(EMPTY_TOMBSTONE);
    const { getByLabelText, getByText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    const cancelBtn = await waitFor(() => getByText('Cancel'));
    await fireEvent.click(cancelBtn);

    await waitFor(() => {
      if (container.querySelector('.confirm-dialog__button--danger')) {
        throw new Error('confirm dialog still mounted');
      }
    });
    expect(calledResurrect()).toBe(false);
  });

  it('resurrects a still-filled tombstone one-click (no confirm)', async () => {
    mockReadReturning(FILLED_TOMBSTONE);
    const { getByLabelText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('resurrect_record', { blockUuidHex: 'ab', recordUuidHex: 'ef' })
    );
    expect(container.querySelector('.confirm-dialog__button--danger')).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop && pnpm vitest run tests/RecordListRestore.test.ts`
Expected: FAIL — the first two tests fail because today `onRestore` resurrects immediately (no confirm dialog mounts; `resurrect_record` fires before any confirm).

- [ ] **Step 3: Write minimal implementation**

Edit `desktop/src/components/RecordList.svelte`.

Add the import to the existing `../lib/ipc` import group is not needed; instead add a new import after the `ConfirmDialog` import (line 14):

```ts
  import { isContentlessTombstone } from '../lib/records';
```

After the existing `let pendingDelete = $state<RecordDto | null>(null);` line, add:

```ts
  // Record awaiting resurrect confirmation (only set for a contentless
  // tombstone — a resurrect that would bring back an empty shell).
  let pendingRestore = $state<RecordDto | null>(null);
```

Replace the existing `onRestore` function:

```ts
  async function onRestore(record: RecordDto) {
    error = null;
    try {
      await resurrectRecord(block.blockUuidHex, record.recordUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
```

with this gate + shared worker + confirm handler:

```ts
  function onRestore(record: RecordDto) {
    // A contentless tombstone resurrects to an empty shell — confirm first so
    // the empty result is expected, not a surprise. A still-filled tombstone
    // resurrects one-click (lossless undelete, unchanged behaviour).
    if (isContentlessTombstone(record)) {
      pendingRestore = record;
      return;
    }
    void doRestore(record);
  }

  async function doRestore(record: RecordDto) {
    error = null;
    try {
      await resurrectRecord(block.blockUuidHex, record.recordUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  async function confirmRestore() {
    const target = pendingRestore;
    if (!target) return;
    pendingRestore = null;
    await doRestore(target);
  }
```

Finally, after the existing `{#if pendingDelete} ... {/if}` ConfirmDialog block (lines 111-119), add a second dialog:

```svelte
{#if pendingRestore}
  <ConfirmDialog
    title="Resurrect an empty record?"
    body="This record has no stored contents to recover — resurrecting brings it back with only its type and tags. Contents are discarded when a record's deletion is merged from another device."
    confirmLabel="Resurrect"
    onConfirm={confirmRestore}
    onCancel={() => (pendingRestore = null)}
  />
{/if}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd desktop && pnpm vitest run tests/RecordListRestore.test.ts`
Expected: PASS — 4 tests. Also re-run the sibling delete suite to confirm no regression: `cd desktop && pnpm vitest run tests/RecordListDelete.test.ts` → PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/honest-resurrect
git add desktop/src/components/RecordList.svelte desktop/tests/RecordListRestore.test.ts
git commit -m "feat(desktop): confirm gate on resurrecting an empty-shell tombstone (#196)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Style the hint + full desktop gauntlet + docs

**Files:**
- Modify: `desktop/src/components/RecordRow.svelte` (CSS only — the `.record-row__no-content` style)
- Modify: `ROADMAP.md` (note #196 fixed, if it tracks D.1.x desktop items)

- [ ] **Step 1: Add a muted style for the hint**

In `desktop/src/components/RecordRow.svelte`, inside the existing `<style>` block, add a rule consistent with the existing `record-row__meta` muting (match the surrounding palette — find the `.record-row__meta` rule and mirror its muted color):

```css
  .record-row__no-content {
    color: var(--color-text-muted, #888);
    font-style: italic;
    margin-left: 0.25rem;
  }
```

If the file uses a different muted-color token, use that token instead — grep the file's `<style>` for the color used by `.record-row__meta` and reuse it. This is cosmetic; no new test.

- [ ] **Step 2: Run the full desktop gauntlet**

```bash
cd desktop
pnpm test
pnpm typecheck
pnpm svelte-check
pnpm lint
```

Expected: all green. (`pnpm test` runs the whole suite including the three new/edited files; `svelte-check` must report 0 errors / 0 warnings.)

- [ ] **Step 3: Update ROADMAP / README if they track this**

Run: `cd /Users/hherb/src/secretary/.worktrees/honest-resurrect && grep -n "196\|resurrect\|D.1.15\|tombstone" ROADMAP.md README.md`

- If `ROADMAP.md` has a desktop/D.1.x bug-tracking line where a "#196 honest resurrect" entry belongs, add a one-line entry noting it shipped 2026-06-08.
- `README.md` status sections stay brief (per the project's README style) — only touch it if it enumerates desktop record-management features and would now be inaccurate. If neither needs a change, skip this step (do not invent content).

- [ ] **Step 4: Commit any doc/style changes**

```bash
cd /Users/hherb/src/secretary/.worktrees/honest-resurrect
git add desktop/src/components/RecordRow.svelte ROADMAP.md README.md
git commit -m "docs+style(desktop): muted resurrect hint + ROADMAP #196 (#196)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

(If only `RecordRow.svelte` changed, stage just that file.)

---

## Manual GUI smoke (pre-merge gate — not automatable here)

Per the spec §5. Run on a `cp -R` temp copy; reuses the #195 helper:

```bash
cd /Users/hherb/src/secretary/.worktrees/honest-resurrect
SMOKE_OUT=/tmp/veto_smoke cargo test --release -p secretary-cli --test sync_pass_integration -- --ignored stage_smoke_vault --nocapture
cd desktop && pnpm tauri dev
# open /tmp/veto_smoke → Sync now → Accept delete (merge-tombstones the record)
# → Show deleted → row shows "no recoverable contents" badge
# → Restore → confirm dialog with the empty-record copy
# → Confirm → empty record returns (expected, explained); badge gone
# → (fresh run) Cancel → no change, dialog closes
```

Record the result in the PR description.

---

## Self-Review

- **Spec coverage:** §1 predicate → Task 1; §2 row hint → Task 2 (+ Task 4 style); §3 confirm gate → Task 3; §4 tests → distributed across Tasks 1-3; §5 manual smoke → dedicated section. ✓
- **Type consistency:** `isContentlessTombstone(record: RecordDto): boolean` defined Task 1, imported identically in Tasks 2 & 3. `pendingRestore` / `doRestore` / `confirmRestore` introduced together in Task 3 and self-consistent. `RecordDto` fields used (`tombstoned`, `fieldCount`, `recordType`, `tags`, `recordUuidHex`, `lastModMs`, `fields`) all exist in `desktop/src/lib/ipc.ts`. ✓
- **No placeholders:** every code/edit step shows full content; the only conditional step (Task 4 docs) has an explicit "skip if not applicable, do not invent" instruction. ✓
- **Scope:** single subsystem (desktop), one plan. No FFI/core change → no cross-language conformance required. ✓
