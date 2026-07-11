# Purge-count post-op feedback (#411) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After each destructive trash op (empty-trash, delete-forever a block, retention purge), show an inline status banner derived from the report the op *already returns* — surfacing `filesFailed` as a warning — instead of discarding the report.

**Architecture:** A pure, host-testable `formatPurgeNotice(outcome) → {text, severity}` on each platform (desktop TS, iOS Swift, Android Kotlin), fed a small normalized `PurgeOutcome` the view-model builds from whichever report DTO the op returned. The view-model captures the previously-discarded report, publishes a `PurgeNotice`, and the view renders it beside the existing error banner. On iOS/Android the mobile write helpers (`reauthedWrite`/`guardedWrite`) become return-carrying so the report survives.

**Tech Stack:** Svelte 5 + TypeScript + vitest (desktop); SwiftUI + XCTest (iOS); Jetpack Compose + Kotlin + JUnit (Android).

## Global Constraints

- **UI-only.** No `core` / `ffi` / bridge / on-disk-format / `manifest_version` change; no new `FfiVaultError` / `VaultBrowseError` variant; no new Tauri command. `#![forbid(unsafe_code)]` intact.
- **The report DTOs are unchanged** — every field used (`purgedCount`, `filesFailed`) already exists on `EmptyTrashReportDto`/`RetentionReportDto` (desktop `RetentionReportDto`/`EmptyTrashReportDto`; iOS `EmptyTrashReportInfo`/`RetentionReportInfo`; Android same). `PurgeReportDto`/`PurgeResultInfo` (single-block) carries **no** `purgedCount`/`filesFailed` — single-block is always `Deleted forever`.
- **Reference wording** (formatter output, identical branch logic on all three platforms; a platform may adapt casing/punctuation but not the branch structure or counts):
  - single-block → `Deleted forever` (success)
  - `purgedCount = 0`, op = retention → `No items were past the retention window` (success)
  - `purgedCount = 0`, op = empty-trash → `Trash was already empty` (success)
  - `purgedCount = N > 0`, `filesFailed = 0` → `Purged N items` (success; `1 item` singular)
  - `purgedCount = N > 0`, `filesFailed = M > 0` → `Purged N items · M files could not be removed` (warning; `1 file` singular)
  - separator is the middle dot `·` (U+00B7).
- **Pure functions in reusable modules** — the formatter has no I/O, no ambient state; it lives beside the #413 `formatTrashedWhen` helpers (`desktop/src/lib/`, iOS `TrashFormatting.swift`, Android `TrashFormatting.kt`).
- **TDD** — failing formatter test first, every row of the table pinned, then the view-model wiring test, then the thin render binding.
- **Do NOT touch the pre-op confirmation dialogs** — the stale-snapshot pre-op count stays; #411 is the *post*-op reconciliation only.
- **Worktree:** all paths are under `/Users/hherb/src/secretary/.worktrees/purge-count-feedback/` on branch `feature/purge-count-feedback-411`. The `.claude/worktrees/strange-mayer-*` tree is a stale duplicate — never edit there ([[feedback_edit_tool_targets_main_not_worktree]]).

---

### Task 1: Desktop pure formatter (`formatPurgeNotice`)

**Files:**
- Create: `desktop/src/lib/purgeNotice.ts`
- Test: `desktop/tests/purgeNotice.test.ts`

**Interfaces:**
- Produces: `type PurgeSeverity = 'success' | 'warning'`; `interface PurgeNotice { text: string; severity: PurgeSeverity }`; `type PurgeOutcome = { op: 'emptyTrash'; purgedCount: number; filesFailed: number } | { op: 'retention'; purgedCount: number; filesFailed: number } | { op: 'singlePurge' }`; `function formatPurgeNotice(outcome: PurgeOutcome): PurgeNotice`.

- [ ] **Step 1: Write the failing test**

```typescript
// desktop/tests/purgeNotice.test.ts
// Unit tests for the pure post-op purge-notice formatter (#411). Pins every
// row of the design's message table incl. pluralization boundaries and the
// filesFailed warning branch. No I/O; no ambient state.
import { describe, it, expect } from 'vitest';
import { formatPurgeNotice } from '../src/lib/purgeNotice';

describe('formatPurgeNotice', () => {
  it('single-block purge is always "Deleted forever" (success)', () => {
    expect(formatPurgeNotice({ op: 'singlePurge' })).toEqual({
      text: 'Deleted forever',
      severity: 'success'
    });
  });

  it('empty-trash of one block is singular', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 1, filesFailed: 0 })).toEqual({
      text: 'Purged 1 item',
      severity: 'success'
    });
  });

  it('empty-trash of several blocks is plural, success', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 4, filesFailed: 0 })).toEqual({
      text: 'Purged 4 items',
      severity: 'success'
    });
  });

  it('one failed file is a singular warning', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 4, filesFailed: 1 })).toEqual({
      text: 'Purged 4 items · 1 file could not be removed',
      severity: 'warning'
    });
  });

  it('multiple failed files are a plural warning', () => {
    expect(formatPurgeNotice({ op: 'retention', purgedCount: 4, filesFailed: 2 })).toEqual({
      text: 'Purged 4 items · 2 files could not be removed',
      severity: 'warning'
    });
  });

  it('retention with nothing expired is a distinct success message', () => {
    expect(formatPurgeNotice({ op: 'retention', purgedCount: 0, filesFailed: 0 })).toEqual({
      text: 'No items were past the retention window',
      severity: 'success'
    });
  });

  it('empty-trash that purged nothing (concurrent empty) reports so', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 0, filesFailed: 0 })).toEqual({
      text: 'Trash was already empty',
      severity: 'success'
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop && pnpm exec vitest run tests/purgeNotice.test.ts`
Expected: FAIL — `Failed to resolve import "../src/lib/purgeNotice"`.

- [ ] **Step 3: Write minimal implementation**

```typescript
// desktop/src/lib/purgeNotice.ts
// Pure formatter for the post-op destructive-trash notice (#411). Maps the
// report an op already returns to a user-facing banner string + severity.
// Lives beside the #413 trash helpers; no I/O, no ambient state, so it is
// fully unit-testable and shared identically in logic with the iOS/Android
// mirrors (TrashFormatting.swift / .kt).

export type PurgeSeverity = 'success' | 'warning';

export interface PurgeNotice {
  text: string;
  severity: PurgeSeverity;
}

/** Normalized outcome the caller builds from whichever report DTO it holds.
 * `singlePurge` (delete-forever) carries no count — its DTO has none. */
export type PurgeOutcome =
  | { op: 'emptyTrash'; purgedCount: number; filesFailed: number }
  | { op: 'retention'; purgedCount: number; filesFailed: number }
  | { op: 'singlePurge' };

/** "1 item" / "4 items" — English count noun. */
function plural(n: number, singular: string): string {
  return n === 1 ? `1 ${singular}` : `${n} ${singular}s`;
}

export function formatPurgeNotice(outcome: PurgeOutcome): PurgeNotice {
  if (outcome.op === 'singlePurge') {
    return { text: 'Deleted forever', severity: 'success' };
  }
  const { purgedCount, filesFailed } = outcome;
  if (purgedCount === 0) {
    const text =
      outcome.op === 'retention'
        ? 'No items were past the retention window'
        : 'Trash was already empty';
    return { text, severity: 'success' };
  }
  const base = `Purged ${plural(purgedCount, 'item')}`;
  if (filesFailed > 0) {
    return {
      text: `${base} · ${plural(filesFailed, 'file')} could not be removed`,
      severity: 'warning'
    };
  }
  return { text: base, severity: 'success' };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd desktop && pnpm exec vitest run tests/purgeNotice.test.ts`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/purgeNotice.ts desktop/tests/purgeNotice.test.ts
git commit -m "feat(desktop): pure formatPurgeNotice helper (#411)"
```

---

### Task 2: Desktop wiring — capture reports + render banner

**Files:**
- Modify: `desktop/src/components/delete/TrashView.svelte`
- Modify: `desktop/src/components/delete/RetentionDialog.svelte`
- Test: `desktop/tests/TrashView.test.ts` (extend), `desktop/tests/RetentionDialog.test.ts` (extend)

**Interfaces:**
- Consumes: `formatPurgeNotice`, `PurgeNotice` from Task 1.
- Produces: `RetentionDialog`'s `onClose` prop becomes `(notice?: PurgeNotice) => void`.

- [ ] **Step 1: Write the failing tests (TrashView)**

Add to `desktop/tests/TrashView.test.ts` inside `describe('TrashView', …)`:

```typescript
  it('shows a "Purged N items" status banner after emptying trash', async () => {
    invokeMock.mockResolvedValueOnce([trashedEntry(), { ...trashedEntry(), blockUuidHex: 'cd', blockName: 'Card' }]);
    invokeMock.mockResolvedValueOnce([]); // reload after empty
    // empty_trash goes through the real ipc.emptyTrash -> mocked invoke:
    invokeMock.mockResolvedValueOnce({
      purgedCount: 2, sharedCount: 0, ownerOnlyCount: 2, unknownCount: 0, filesRemoved: 2, filesFailed: 0
    });

    const { findByRole, getByText } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());

    const emptyButton = await findByRole('button', { name: /empty trash/i });
    await fireEvent.click(emptyButton);
    const confirm = await findByRole('button', { name: /^empty trash$/i });
    await fireEvent.click(confirm);

    const status = await findByRole('status');
    expect(status.textContent).toMatch(/purged 2 items/i);
  });

  it('renders a warning banner when files could not be removed', async () => {
    invokeMock.mockResolvedValueOnce([trashedEntry()]);
    invokeMock.mockResolvedValueOnce([]); // reload after purge
    purgeBlockMock.mockResolvedValueOnce({
      blockUuidHex: 'ab', wasShared: false, recipientCount: 0, filesRemoved: 1
    });
    // (single-block purge is always "Deleted forever" — this asserts the
    // success banner text; the warning branch is covered by purgeNotice.test.ts)
    const { findByRole, getByText } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());
    const purgeButton = await findByRole('button', { name: /permanently delete block bank logins/i });
    await fireEvent.click(purgeButton);
    const confirm = await findByRole('button', { name: /^delete forever$/i });
    await fireEvent.click(confirm);
    const status = await findByRole('status');
    expect(status.textContent).toMatch(/deleted forever/i);
  });
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd desktop && pnpm exec vitest run tests/TrashView.test.ts`
Expected: FAIL — no element with `role="status"` (banner not implemented).

- [ ] **Step 3: Wire TrashView.svelte**

In the `<script>` imports, add:

```typescript
  import { formatPurgeNotice, type PurgeNotice } from '../../lib/purgeNotice';
```

Add state beside `let error`:

```typescript
  let notice = $state<PurgeNotice | null>(null);
```

In `restore`, at the top set `notice = null;` right after `error = null;`.

Replace the body of `confirmPurge`'s success try-block (currently `await purgeBlock…; await refreshManifest(); await load();`) so it captures and formats:

```typescript
    notice = null;
    try {
      await purgeBlock(target.blockUuidHex);
      await refreshManifest();
      notice = formatPurgeNotice({ op: 'singlePurge' });
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
```

Replace `confirmEmpty`'s success try-block (drop the "intentionally not surfaced" comment on lines ~84–87):

```typescript
    notice = null;
    try {
      const report = await emptyTrash();
      await refreshManifest();
      notice = formatPurgeNotice({ op: 'emptyTrash', purgedCount: report.purgedCount, filesFailed: report.filesFailed });
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
```

Update the `RetentionDialog` mount to receive the notice back:

```svelte
{#if showRetention}
  <RetentionDialog
    onClose={(n) => {
      showRetention = false;
      if (n) notice = n;
      void load();
    }}
  />
{/if}
```

Render the banner just after the `<button>`s and before the `{#if error}` block:

```svelte
  {#if notice}
    <p class="trash-view__notice" class:trash-view__notice--warning={notice.severity === 'warning'} role="status">
      {notice.text}
    </p>
  {/if}
```

Add a scoped style block at the end of the file (new — TrashView has none today):

```svelte
<style>
  .trash-view__notice {
    color: var(--color-success, #217a3c);
  }
  .trash-view__notice--warning {
    color: var(--color-warning, #a15c00);
  }
</style>
```

- [ ] **Step 4: Wire RetentionDialog.svelte**

Add import:

```typescript
  import { formatPurgeNotice, type PurgeNotice } from '../../lib/purgeNotice';
```

Change the `Props` type and destructure:

```typescript
  type Props = { onClose: (notice?: PurgeNotice) => void };
  let { onClose }: Props = $props();
```

In `confirm`, replace `await runRetention(); await refreshManifest(); onClose();` with:

```typescript
      const report = await runRetention();
      await refreshManifest();
      onClose(formatPurgeNotice({ op: 'retention', purgedCount: report.purgedCount, filesFailed: report.filesFailed }));
```

(The plain Cancel/Close buttons keep calling `onClose` with no argument — `onClose={onClose}` on line ~102 stays as-is; `onClose()` → `notice` undefined → TrashView shows nothing.)

- [ ] **Step 5: Write the failing RetentionDialog test**

Add to `desktop/tests/RetentionDialog.test.ts` (mirror its existing mock shape; the onClose spy now receives a notice):

```typescript
  it('passes a formatted purge notice to onClose after a successful run', async () => {
    previewRetentionMock.mockResolvedValue({ entries: [{ blockUuidHex: 'ab', tombstonedAtMs: 0, ageMs: 100 * 86_400_000 }], windowMs: 90 * 86_400_000 });
    runRetentionMock.mockResolvedValueOnce({
      purgedCount: 3, sharedCount: 0, ownerOnlyCount: 3, unknownCount: 0, filesRemoved: 3, filesFailed: 0, windowMs: 90 * 86_400_000
    });
    const onClose = vi.fn();
    const { findByRole } = render(RetentionDialog, { onClose });
    const purge = await findByRole('button', { name: /purge \d+ items/i });
    await fireEvent.click(purge);
    await waitFor(() => expect(onClose).toHaveBeenCalledWith({ text: 'Purged 3 items', severity: 'success' }));
  });
```

(If `RetentionDialog.test.ts` lacks the `runRetentionMock`/`vi`/`RetentionDialog` imports or a `previewRetentionMock` returning an expired entry, add them following the file's existing hoisted-mock pattern. Read the file first to match names exactly.)

- [ ] **Step 6: Run the full desktop suite + type check**

Run: `cd desktop && pnpm test && pnpm run svelte-check`
Expected: all green (the new banner tests pass; the pre-existing `testEmptyTrashGatesReloadsAndDiscardsReport`-equivalent desktop tests still pass — they don't assert absence of a status banner). svelte-check: 0 errors (the `onClose` prop-type change is now consistent between TrashView and RetentionDialog).

- [ ] **Step 7: Commit**

```bash
git add desktop/src/components/delete/TrashView.svelte desktop/src/components/delete/RetentionDialog.svelte desktop/tests/TrashView.test.ts desktop/tests/RetentionDialog.test.ts
git commit -m "feat(desktop): surface purge-count status banner after trash ops (#411)"
```

---

### Task 3: iOS pure formatter (`formatPurgeNotice`)

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/PurgeNoticeTests.swift` (create)

**Interfaces:**
- Produces: `enum PurgeSeverity { case success, warning }`; `struct PurgeNotice: Equatable { let text: String; let severity: PurgeSeverity }`; `enum PurgeOutcome: Equatable { case emptyTrash(purgedCount: UInt32, filesFailed: UInt32); case retention(purgedCount: UInt32, filesFailed: UInt32); case singlePurge }`; `func formatPurgeNotice(_ outcome: PurgeOutcome) -> PurgeNotice`.

- [ ] **Step 1: Write the failing test**

```swift
// ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/PurgeNoticeTests.swift
import XCTest
@testable import SecretaryVaultAccess

final class PurgeNoticeTests: XCTestCase {
    func testSinglePurge() {
        XCTAssertEqual(formatPurgeNotice(.singlePurge),
                       PurgeNotice(text: "Deleted forever", severity: .success))
    }
    func testEmptyTrashSingular() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 1, filesFailed: 0)),
                       PurgeNotice(text: "Purged 1 item", severity: .success))
    }
    func testEmptyTrashPlural() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 4, filesFailed: 0)),
                       PurgeNotice(text: "Purged 4 items", severity: .success))
    }
    func testOneFailedFileWarnsSingular() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 4, filesFailed: 1)),
                       PurgeNotice(text: "Purged 4 items · 1 file could not be removed", severity: .warning))
    }
    func testFailedFilesWarnPlural() {
        XCTAssertEqual(formatPurgeNotice(.retention(purgedCount: 4, filesFailed: 2)),
                       PurgeNotice(text: "Purged 4 items · 2 files could not be removed", severity: .warning))
    }
    func testRetentionNoop() {
        XCTAssertEqual(formatPurgeNotice(.retention(purgedCount: 0, filesFailed: 0)),
                       PurgeNotice(text: "No items were past the retention window", severity: .success))
    }
    func testEmptyTrashNoop() {
        XCTAssertEqual(formatPurgeNotice(.emptyTrash(purgedCount: 0, filesFailed: 0)),
                       PurgeNotice(text: "Trash was already empty", severity: .success))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter PurgeNoticeTests`
Expected: FAIL — `formatPurgeNotice`/`PurgeNotice`/`PurgeOutcome` not found (compile error).

- [ ] **Step 3: Append the implementation to `TrashFormatting.swift`**

```swift
/// Severity of a post-op purge notice (#411): a plain confirmation or a
/// warning that some on-disk files could not be removed.
public enum PurgeSeverity: Equatable {
    case success
    case warning
}

/// A formatted post-op notice for the Trash browser banner.
public struct PurgeNotice: Equatable {
    public let text: String
    public let severity: PurgeSeverity
    public init(text: String, severity: PurgeSeverity) {
        self.text = text
        self.severity = severity
    }
}

/// Normalized outcome the view-model builds from whichever report an op
/// returned. `singlePurge` (delete-forever) carries no count — its DTO
/// (`PurgeResultInfo`) has none. Logic mirrors desktop `formatPurgeNotice`
/// and Android's `formatPurgeNotice`.
public enum PurgeOutcome: Equatable {
    case emptyTrash(purgedCount: UInt32, filesFailed: UInt32)
    case retention(purgedCount: UInt32, filesFailed: UInt32)
    case singlePurge
}

private func pluralCount(_ n: UInt32, _ singular: String) -> String {
    n == 1 ? "1 \(singular)" : "\(n) \(singular)s"
}

/// Map a destructive-trash outcome to a banner string + severity (#411).
public func formatPurgeNotice(_ outcome: PurgeOutcome) -> PurgeNotice {
    switch outcome {
    case .singlePurge:
        return PurgeNotice(text: "Deleted forever", severity: .success)
    case let .emptyTrash(purgedCount, filesFailed):
        return countNotice(purgedCount, filesFailed, zeroText: "Trash was already empty")
    case let .retention(purgedCount, filesFailed):
        return countNotice(purgedCount, filesFailed, zeroText: "No items were past the retention window")
    }
}

private func countNotice(_ purgedCount: UInt32, _ filesFailed: UInt32, zeroText: String) -> PurgeNotice {
    if purgedCount == 0 {
        return PurgeNotice(text: zeroText, severity: .success)
    }
    let base = "Purged \(pluralCount(purgedCount, "item"))"
    if filesFailed > 0 {
        return PurgeNotice(text: "\(base) · \(pluralCount(filesFailed, "file")) could not be removed", severity: .warning)
    }
    return PurgeNotice(text: base, severity: .success)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter PurgeNoticeTests`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/PurgeNoticeTests.swift
git commit -m "feat(ios): pure formatPurgeNotice helper (#411)"
```

---

### Task 4: iOS view-model — return-carrying `reauthedWrite` + `purgeNotice`

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/TrashViewModel.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeTrashPort.swift` (add a `filesFailed` knob)
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/TrashViewModelTests.swift` (extend)

**Interfaces:**
- Consumes: `PurgeNotice`, `formatPurgeNotice`, `PurgeOutcome` (Task 3).
- Produces: `@Published public private(set) var purgeNotice: PurgeNotice?` on `TrashViewModel`; `FakeTrashPort.emptyTrashFilesFailed: UInt32`.

- [ ] **Step 1: Add the `filesFailed` knob to `FakeTrashPort`**

In `FakeTrashPort.swift`, add a stored property `public var emptyTrashFilesFailed: UInt32 = 0` (beside `defaultWindowMs`) and use it in `emptyTrash()`:

```swift
    public func emptyTrash() throws -> EmptyTrashReportInfo {
        try throwIfInjected()
        emptyTrashCount += 1
        let n = UInt32(trashedBlocks.count)
        trashedBlocks.removeAll()
        return EmptyTrashReportInfo(purgedCount: n, sharedCount: 0, ownerOnlyCount: n,
                                    unknownCount: 0, filesRemoved: n, filesFailed: emptyTrashFilesFailed)
    }
```

- [ ] **Step 2: Write the failing view-model tests**

Replace `testEmptyTrashGatesReloadsAndDiscardsReport` in `TrashViewModelTests.swift` with a notice-asserting version, and add a warning-path test + a single-purge test:

```swift
    func testEmptyTrashGatesReloadsAndSetsNotice() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.emptyTrash()
        XCTAssertEqual(gate.authorizeCount, 1)
        XCTAssertEqual(port.emptyTrashCount, 1)
        XCTAssertTrue(vm.entries.isEmpty)
        XCTAssertEqual(vm.purgeNotice, PurgeNotice(text: "Purged 2 items", severity: .success))
    }

    func testEmptyTrashWarnsWhenFilesFailed() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        port.emptyTrashFilesFailed = 1
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        vm.load()
        await vm.emptyTrash()
        XCTAssertEqual(vm.purgeNotice,
                       PurgeNotice(text: "Purged 2 items · 1 file could not be removed", severity: .warning))
    }

    func testPurgeSetsDeletedForeverNotice() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100)])
        let vm = TrashViewModel(port: port, gate: FakeWriteReauthGate())
        vm.load()
        await vm.purge(uuid: [1])
        XCTAssertEqual(vm.purgeNotice, PurgeNotice(text: "Deleted forever", severity: .success))
    }

    func testRefusedReauthClearsPriorNoticeAndSetsNone() async {
        let port = FakeTrashPort(trashedBlocks: [tb(1, at: 100), tb(2, at: 200)])
        let gate = FakeWriteReauthGate()
        let vm = TrashViewModel(port: port, gate: gate)
        vm.load()
        await vm.emptyTrash()                       // sets a notice
        XCTAssertNotNil(vm.purgeNotice)
        gate.failNext = .reauthFailed("cancelled")
        await vm.purge(uuid: [2])                    // refused: no new notice, prior cleared
        XCTAssertNil(vm.purgeNotice)
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd ios/SecretaryVaultAccess && swift test --filter TrashViewModelTests`
Expected: FAIL — `vm.purgeNotice` does not exist (compile error).

- [ ] **Step 4: Make `reauthedWrite` return-carrying + publish `purgeNotice`**

In `TrashViewModel.swift`, add the published property beside `preview`:

```swift
    /// The last destructive op's outcome, rendered as an inline banner (#411).
    /// Cleared at the start of any new write; set on a successful op.
    @Published public private(set) var purgeNotice: PurgeNotice?
```

Replace the four op methods and `reauthedWrite`:

```swift
    public func restore(uuid: [UInt8]) async {
        _ = await reauthedWrite(reason: "Confirm restoring this block") {
            try self.port.restoreBlock(uuid: uuid)
        }
    }

    public func purge(uuid: [UInt8]) async {
        let result = await reauthedWrite(reason: "Confirm permanently deleting this block") {
            try self.port.purgeBlock(uuid: uuid)
        }
        if result != nil { purgeNotice = formatPurgeNotice(.singlePurge) }
    }

    public func emptyTrash() async {
        let report = await reauthedWrite(reason: "Confirm permanently deleting all trashed blocks") {
            try self.port.emptyTrash()
        }
        if let report {
            purgeNotice = formatPurgeNotice(.emptyTrash(purgedCount: report.purgedCount, filesFailed: report.filesFailed))
        }
    }

    public func runRetention() async {
        let window = port.defaultRetentionWindowMs()
        let report = await reauthedWrite(reason: "Confirm permanently deleting expired trash") {
            try self.port.autoPurgeExpired(windowMs: window)
        }
        if let report {
            purgeNotice = formatPurgeNotice(.retention(purgedCount: report.purgedCount, filesFailed: report.filesFailed))
        }
    }

    /// Re-auth, run a guarded write, then reload; returns the op's result (or
    /// nil if the guard/op failed). `isWriting` set before the gate await so a
    /// second action during the biometric prompt is rejected; `purgeNotice`
    /// cleared here so any initiated write supersedes the prior banner.
    private func reauthedWrite<T>(reason: String, op: () throws -> T) async -> T? {
        guard !isWriting else { return nil }
        isWriting = true
        purgeNotice = nil
        defer { isWriting = false }
        do {
            try await gate.authorizeWrite(reason: reason)
        } catch let e as VaultAccessError {
            error = e
            return nil
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return nil
        }
        let result: T
        do {
            result = try op()
        } catch let e as VaultAccessError {
            error = e
            return nil
        } catch {
            self.error = .other(String(describing: error))
            return nil
        }
        load()
        return result
    }
```

Also update the class doc comment (lines 4–8): replace "Destructive-op reports are discarded — the reloaded (empty) list is the success signal, parity with desktop." with "Destructive-op reports are surfaced as `purgeNotice` (#411) after the reload."

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ios/SecretaryVaultAccess && swift test --filter TrashViewModelTests`
Expected: PASS (all, including the pre-existing restore/purge/reauth tests — their behavior is unchanged; `reauthedWrite` now returns a value they ignore).

Then run the whole host package once: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS (formatter + VM + formatting suites).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/TrashViewModel.swift ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeTrashPort.swift ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/TrashViewModelTests.swift
git commit -m "feat(ios): capture purge reports into purgeNotice (#411)"
```

---

### Task 5: iOS render — banner in `TrashScreen.swift`

**Files:**
- Modify: `ios/SecretaryApp/Sources/TrashScreen.swift`

**Interfaces:**
- Consumes: `viewModel.purgeNotice: PurgeNotice?` (Task 4).

Note: this is the XcodeGen app target — NOT part of host `swift test`. It's a thin binding; verification is a compile (a full `run-ios-tests.sh` builds the xcframework, multi-minute — [[project_secretary_ios_xcframework_build_watchdog]]). No new unit test here; the logic is host-tested in Tasks 3–4.

- [ ] **Step 1: Wrap the List and render the banner**

Change `var body: some View { List { … } … }` to wrap the `List` in a `VStack(spacing: 0)` with the banner on top:

```swift
    var body: some View {
        VStack(spacing: 0) {
            if let notice = viewModel.purgeNotice {
                Text(notice.text)
                    .font(.footnote)
                    .foregroundStyle(notice.severity == .warning ? Color.orange : Color.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal).padding(.vertical, 8)
                    .accessibilityIdentifier("purge-notice")
            }
            List {
                // … existing List contents unchanged …
            }
        }
        .navigationTitle("Trash")
        // … existing .toolbar / .onAppear / .confirmationDialog / .sheet modifiers
        //     stay attached to the VStack (move them from List to the VStack) …
    }
```

Move the `.navigationTitle`, `.toolbar`, `.onAppear`, both `.confirmationDialog`, and `.sheet` modifiers from the `List` to the enclosing `VStack` so they still apply. (SwiftUI: these attach to any View; the `List` keeps only its row `ForEach`/empty-state content.)

- [ ] **Step 2: Verify it compiles (best-effort, optional this task)**

If warming the xcframework build this session: `bash ios/scripts/run-ios-tests.sh` (build only needs to succeed; host tests already green). Otherwise note in the handoff that the app-target compile is deferred (as #413's call-site was). The change is a pure additive binding to an existing published property.

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryApp/Sources/TrashScreen.swift
git commit -m "feat(ios): render purge-notice banner in TrashScreen (#411)"
```

---

### Task 6: Android pure formatter (`formatPurgeNotice`)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/TrashFormatting.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/PurgeNoticeTest.kt` (create)

**Interfaces:**
- Produces: `enum class PurgeSeverity { SUCCESS, WARNING }`; `data class PurgeNotice(val text: String, val severity: PurgeSeverity)`; `sealed interface PurgeOutcome { data class EmptyTrash(purgedCount: Int, filesFailed: Int); data class Retention(purgedCount: Int, filesFailed: Int); data object SinglePurge }`; `fun formatPurgeNotice(outcome: PurgeOutcome): PurgeNotice`.

- [ ] **Step 1: Write the failing test**

```kotlin
// android/vault-access/src/test/kotlin/org/secretary/browse/PurgeNoticeTest.kt
package org.secretary.browse

import kotlin.test.Test
import kotlin.test.assertEquals

class PurgeNoticeTest {
    @Test fun singlePurge() =
        assertEquals(PurgeNotice("Deleted forever", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.SinglePurge))

    @Test fun emptyTrashSingular() =
        assertEquals(PurgeNotice("Purged 1 item", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 1, filesFailed = 0)))

    @Test fun emptyTrashPlural() =
        assertEquals(PurgeNotice("Purged 4 items", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 4, filesFailed = 0)))

    @Test fun oneFailedFileWarnsSingular() =
        assertEquals(PurgeNotice("Purged 4 items · 1 file could not be removed", PurgeSeverity.WARNING),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 4, filesFailed = 1)))

    @Test fun failedFilesWarnPlural() =
        assertEquals(PurgeNotice("Purged 4 items · 2 files could not be removed", PurgeSeverity.WARNING),
            formatPurgeNotice(PurgeOutcome.Retention(purgedCount = 4, filesFailed = 2)))

    @Test fun retentionNoop() =
        assertEquals(PurgeNotice("No items were past the retention window", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.Retention(purgedCount = 0, filesFailed = 0)))

    @Test fun emptyTrashNoop() =
        assertEquals(PurgeNotice("Trash was already empty", PurgeSeverity.SUCCESS),
            formatPurgeNotice(PurgeOutcome.EmptyTrash(purgedCount = 0, filesFailed = 0)))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.PurgeNoticeTest'`
Expected: FAIL — unresolved reference `formatPurgeNotice`/`PurgeNotice`/`PurgeOutcome` (compile error).

- [ ] **Step 3: Append the implementation to `TrashFormatting.kt`**

```kotlin
/** Severity of a post-op purge notice (#411): a plain confirmation or a warning that some
 * on-disk files could not be removed. Mirror of desktop/iOS `PurgeSeverity`. */
enum class PurgeSeverity { SUCCESS, WARNING }

/** A formatted post-op notice for the Trash browser banner. */
data class PurgeNotice(val text: String, val severity: PurgeSeverity)

/**
 * Normalized outcome the model builds from whichever report an op returned. [SinglePurge]
 * (delete-forever) carries no count — its DTO ([PurgeResultInfo]) has none. Logic mirrors desktop
 * and iOS `formatPurgeNotice`.
 */
sealed interface PurgeOutcome {
    data class EmptyTrash(val purgedCount: Int, val filesFailed: Int) : PurgeOutcome
    data class Retention(val purgedCount: Int, val filesFailed: Int) : PurgeOutcome
    data object SinglePurge : PurgeOutcome
}

/** "1 item" / "4 items" — English count noun. */
private fun pluralCount(n: Int, singular: String): String =
    if (n == 1) "1 $singular" else "$n ${singular}s"

/** Map a destructive-trash outcome to a banner string + severity (#411). */
fun formatPurgeNotice(outcome: PurgeOutcome): PurgeNotice = when (outcome) {
    is PurgeOutcome.SinglePurge -> PurgeNotice("Deleted forever", PurgeSeverity.SUCCESS)
    is PurgeOutcome.EmptyTrash -> countNotice(outcome.purgedCount, outcome.filesFailed, "Trash was already empty")
    is PurgeOutcome.Retention -> countNotice(outcome.purgedCount, outcome.filesFailed, "No items were past the retention window")
}

private fun countNotice(purgedCount: Int, filesFailed: Int, zeroText: String): PurgeNotice {
    if (purgedCount == 0) return PurgeNotice(zeroText, PurgeSeverity.SUCCESS)
    val base = "Purged ${pluralCount(purgedCount, "item")}"
    return if (filesFailed > 0) {
        PurgeNotice("$base · ${pluralCount(filesFailed, "file")} could not be removed", PurgeSeverity.WARNING)
    } else {
        PurgeNotice(base, PurgeSeverity.SUCCESS)
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.PurgeNoticeTest'`
Expected: PASS (7 tests). (First run may trigger a multi-minute cold JNI build — [[project_secretary_ios_xcframework_build_watchdog]] applies to Android `:kit` too; `:vault-access` is kotlin-jvm and host-only, so it's fast.)

- [ ] **Step 5: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/TrashFormatting.kt android/vault-access/src/test/kotlin/org/secretary/browse/PurgeNoticeTest.kt
git commit -m "feat(android): pure formatPurgeNotice helper (#411)"
```

---

### Task 7: Android model — return-carrying `guardedWrite` + notice StateFlow

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/TrashBrowseModel.kt`
- Modify: `android/vault-access/src/test/kotlin/org/secretary/browse/FakeTrashPort.kt` (add `filesFailed` knob)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/TrashBrowseModelTest.kt` (extend)

**Interfaces:**
- Consumes: `PurgeNotice`, `PurgeOutcome`, `formatPurgeNotice` (Task 6).
- Produces: `val notice: StateFlow<PurgeNotice?>` on `TrashBrowseModel`; `FakeTrashPort.emptyTrashFilesFailed: Int`.

- [ ] **Step 1: Add the `filesFailed` knob to `FakeTrashPort`**

In `FakeTrashPort.kt`, add a constructor param `var emptyTrashFilesFailed: Int = 0` (after `writeGate`) and use it in `emptyTrash()`:

```kotlin
    override suspend fun emptyTrash(): EmptyTrashReportInfo {
        writeGate?.await()
        emptied += 1
        return EmptyTrashReportInfo(list.size, 0, list.size, 0, list.size, emptyTrashFilesFailed)
    }
```

- [ ] **Step 2: Write the failing model tests**

Add to `TrashBrowseModelTest.kt` (read it first to reuse its `TestScope`/`runTest` + fake-gate helpers; follow existing names). If an existing test named like `emptyTrash…DiscardsReport` asserts the report is dropped, replace it with the notice assertion below.

```kotlin
    @Test fun emptyTrashSetsPurgedNotice() = runTest {
        val port = FakeTrashPort(list = listOf(tb(1, 100), tb(2, 200)))
        val model = TrashBrowseModel(port)
        model.load()
        model.emptyTrash()
        assertEquals(PurgeNotice("Purged 2 items", PurgeSeverity.SUCCESS), model.notice.value)
    }

    @Test fun emptyTrashWarnsWhenFilesFailed() = runTest {
        val port = FakeTrashPort(list = listOf(tb(1, 100), tb(2, 200)), emptyTrashFilesFailed = 1)
        val model = TrashBrowseModel(port)
        model.load()
        model.emptyTrash()
        assertEquals(
            PurgeNotice("Purged 2 items · 1 file could not be removed", PurgeSeverity.WARNING),
            model.notice.value,
        )
    }

    @Test fun purgeSetsDeletedForeverNotice() = runTest {
        val port = FakeTrashPort(list = listOf(tb(1, 100)))
        val model = TrashBrowseModel(port)
        model.load()
        model.purge(byteArrayOf(1))
        assertEquals(PurgeNotice("Deleted forever", PurgeSeverity.SUCCESS), model.notice.value)
    }

    @Test fun refusedReauthClearsPriorNotice() = runTest {
        val gate = FakeReauthGate()  // reuse the file's existing fake gate type/name
        val port = FakeTrashPort(list = listOf(tb(1, 100), tb(2, 200)))
        val model = TrashBrowseModel(port, gate)
        model.load()
        model.emptyTrash()
        assertNotNull(model.notice.value)
        gate.failNext = DeviceUnlockError.UserCancelled  // match the file's cancel-injection idiom
        model.purge(byteArrayOf(2))
        assertNull(model.notice.value)
    }
```

(`tb(...)` — reuse the test file's existing `TrashedBlockInfo` factory; if none, add `private fun tb(b: Byte, at: Long) = TrashedBlockInfo(byteArrayOf(b), "n$b", at, byteArrayOf(0))`.)

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.TrashBrowseModelTest'`
Expected: FAIL — unresolved reference `model.notice` (compile error).

- [ ] **Step 4: Make `guardedWrite` return-carrying + publish `notice`**

In `TrashBrowseModel.kt`, add imports are unnecessary (same package). Add the flow beside `_preview`:

```kotlin
    private val _notice = MutableStateFlow<PurgeNotice?>(null)
    /** The last destructive op's outcome for the inline banner (#411). Cleared at the start of any
     * new write; set on a successful op. */
    val notice: StateFlow<PurgeNotice?> = _notice.asStateFlow()
```

Replace the four op methods:

```kotlin
    suspend fun restore(uuid: ByteArray) {
        guardedWrite("Confirm restoring this block") { port.restoreBlock(uuid) }
    }

    suspend fun purge(uuid: ByteArray) {
        val result = guardedWrite("Confirm permanently deleting this block") { port.purgeBlock(uuid) }
        if (result != null) _notice.value = formatPurgeNotice(PurgeOutcome.SinglePurge)
    }

    suspend fun emptyTrash() {
        val report = guardedWrite("Confirm permanently deleting all trashed blocks") { port.emptyTrash() }
        if (report != null) {
            _notice.value = formatPurgeNotice(PurgeOutcome.EmptyTrash(report.purgedCount, report.filesFailed))
        }
    }

    suspend fun runRetention() {
        val window = port.defaultRetentionWindowMs()
        val report = guardedWrite("Confirm permanently deleting expired trash") { port.autoPurgeExpired(window) }
        if (report != null) {
            _notice.value = formatPurgeNotice(PurgeOutcome.Retention(report.purgedCount, report.filesFailed))
        }
    }
```

Replace `guardedWrite`'s signature + body to be generic and return the op result (clearing the notice up front):

```kotlin
    private suspend fun <T> guardedWrite(reason: String, op: suspend () -> T): T? {
        if (_writing.value) return null
        _writing.value = true
        _notice.value = null
        try {
            try {
                gate.authorizeWrite(reason)
            } catch (e: DeviceUnlockError.UserCancelled) {
                return null // silent: no write, no error
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(reauthFailedMessage(e))
                return null
            }
            val result = try {
                op()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return null
            }
            load()
            return result
        } finally {
            _writing.value = false
        }
    }
```

Update the class doc (lines 7–12): replace "Destructive-op reports are DISCARDED — the reloaded list is the success signal (parity with iOS/desktop; #411 surfaces counts later)." with "Destructive-op reports are surfaced via [notice] (#411) after the reload." Also update the `guardedWrite` doc line "The op's return value (report DTO) is discarded." to "Returns the op's result (report DTO) so the caller can build a [notice]."

Also update the `TrashPort` interface doc in `TrashModels.kt` (line ~99): change "Reports are returned (plumbed for #411) but the VM discards them." to "Reports are returned and surfaced by the model as a [notice] (#411)."

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd android && ./gradlew :vault-access:test`
Expected: PASS (formatter + model + formatting suites; pre-existing restore/purge/reauth/re-entrancy tests unchanged — `guardedWrite` now returns a value they ignore).

- [ ] **Step 6: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/TrashBrowseModel.kt android/vault-access/src/main/kotlin/org/secretary/browse/TrashModels.kt android/vault-access/src/test/kotlin/org/secretary/browse/FakeTrashPort.kt android/vault-access/src/test/kotlin/org/secretary/browse/TrashBrowseModelTest.kt
git commit -m "feat(android): capture purge reports into a notice StateFlow (#411)"
```

---

### Task 8: Android render — bridge + banner in `TrashScreen.kt`

**Files:**
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashBrowseViewModel.kt`
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashScreen.kt`

**Interfaces:**
- Consumes: `model.notice: StateFlow<PurgeNotice?>` (Task 7).

Note: the Compose render is a thin binding; there is no existing `TrashScreen` compose (JVM) test to extend, and Compose UI assertions need instrumentation (out of scope — mirrors the map's finding). Verification is the `:browse-ui` compile + `:app` assemble. The notice *logic* is host-tested in Tasks 6–7.

- [ ] **Step 1: Expose `notice` on the bridge VM**

In `TrashBrowseViewModel.kt`, add the import `import org.secretary.browse.PurgeNotice` and re-expose the flow beside `preview`:

```kotlin
    val notice: StateFlow<PurgeNotice?> = model.notice
```

- [ ] **Step 2: Render the banner in `TrashScreen.kt`**

Add imports:

```kotlin
import org.secretary.browse.PurgeNotice
import org.secretary.browse.PurgeSeverity
```

Collect the flow beside the others:

```kotlin
    val notice by viewModel.notice.collectAsStateWithLifecycle()
```

In the `Column` inside the `Scaffold` content, render the notice beside the error banner:

```kotlin
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            error?.let { TrashErrorBanner(it) }
            notice?.let { TrashNoticeBanner(it) }
            // … existing empty-state / LazyColumn unchanged …
        }
```

Add the composable beside `TrashErrorBanner`:

```kotlin
@Composable
private fun TrashNoticeBanner(notice: PurgeNotice) {
    Text(
        text = notice.text,
        color = if (notice.severity == PurgeSeverity.WARNING) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(16.dp).testTag("trash-notice"),
    )
}
```

- [ ] **Step 3: Verify compile + assemble**

Run: `cd android && ./gradlew :browse-ui:compileDebugKotlin :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Run the touched Android gates**

Run: `cd android && ./gradlew :kit:lintDebug :kit:testDebugUnitTest :vault-access:test :browse-ui:compileDebugKotlin :app:assembleDebug`
Expected: all green, `:kit:lintDebug` 0 errors (no new NewApi/lint surface — this is pure Compose + kotlin-jvm).

- [ ] **Step 5: Commit**

```bash
git add android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashBrowseViewModel.kt android/browse-ui/src/main/kotlin/org/secretary/browse/ui/TrashScreen.kt
git commit -m "feat(android): render purge-notice banner in TrashScreen (#411)"
```

---

### Task 9: Docs — README + ROADMAP + close-out

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README + ROADMAP**

Read both; move #411 (destructive-trash post-op feedback) from any "deferred/next" list to shipped, in the same brief dot-point style as the #413 entry the previous session added ([[feedback_readme_style]]). Keep it to one line each; no test-count walls.

- [ ] **Step 2: Verify the full touched gate matrix once more**

```bash
cd desktop && pnpm test && pnpm run svelte-check
cd android && ./gradlew :kit:lintDebug :kit:testDebugUnitTest :vault-access:test :browse-ui:compileDebugKotlin :app:assembleDebug
cd ios/SecretaryVaultAccess && swift test
```
Expected: all green.

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: #411 purge-count feedback shipped (README + ROADMAP)"
```

---

## Self-Review

**Spec coverage:**
- Message table (all 6 branches incl. plural boundaries) → formatter Tasks 1/3/6, one assertion per row. ✓
- Surface `filesFailed` as warning → warning branch in formatter + a VM/model warning test (Tasks 4/7 via the fake `filesFailed` knob). ✓
- Inline status banner beside error banner, per platform → Tasks 2/5/8. ✓
- Retention noop distinct message → formatter test `retentionNoop` + branch. ✓
- Single-block "Deleted forever" (no count) → formatter `singlePurge` + VM/model purge tests. ✓
- Report captured (not discarded) → return-carrying `reauthedWrite`/`guardedWrite` + notice assertions replacing the old "discards report" tests. ✓
- Pre-op confirmation untouched → no edits to `ConfirmDialog`/`AlertDialog`/`confirmationDialog` bodies. ✓
- No FFI/core/format/variant change; `#![forbid(unsafe_code)]` intact → Global Constraints; only UI-layer files touched. ✓
- All existing gates green → Task 9 Step 2 runs the full touched matrix. ✓

**Placeholder scan:** none — every step has concrete code or an exact command.

**Type consistency:** `PurgeNotice`/`PurgeOutcome`/`formatPurgeNotice`/`PurgeSeverity` names are identical across the three platforms (adjusted only for language casing: TS `'success'|'warning'`, Swift `.success/.warning`, Kotlin `SUCCESS/WARNING`). `reauthedWrite<T>`/`guardedWrite<T>` return `T?`; callers gate the notice on non-nil. `RetentionDialog.onClose` is `(notice?: PurgeNotice) => void` in both the dialog and the TrashView call site.

**Edge-case note (made explicit, not in the original spec table):** empty-trash with `purgedCount == 0` (a concurrent multi-device empty between snapshot and commit) → `Trash was already empty` rather than borrowing retention's window wording. Documented in the design's rationale and pinned by the `emptyTrashNoop` formatter test.
