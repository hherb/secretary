# Desktop empty-trash UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the already-projected `secretary-ffi-bridge::empty_trash` orchestrator into the Tauri desktop Trash view — an "Empty trash" button that permanently deletes every currently-trashed block in one batch, behind the existing password re-auth write gate.

**Architecture:** FFI-consuming UI slice. The desktop backend consumes `secretary-ffi-bridge` directly (in-process). A new DTO projects the bridge's `EmptyTrashReport` onto a camelCase wire shape; a new `empty_trash` Tauri command snapshots the session under one lock and calls the bridge; the frontend adds an IPC wrapper, a write-gate classification, a pure confirm-body helper, and a single `ConfirmDialog`-based button in `TrashView.svelte`. Single confirm (count shown) + silent reload — no two-step preview (empty-trash has no window filter).

**Tech Stack:** Rust (Tauri 2, `secretary-ffi-bridge`), Svelte 5 + TypeScript, vitest, svelte-check.

## Global Constraints

- **No `core` / crypto / on-disk-format change.** The bridge `empty_trash` surface is already shipped and unchanged. (`docs/crypto-design.md`, `docs/vault-format.md` untouched.)
- **No new `FfiVaultError` / `AppError` variant.** `empty_trash` surfaces only `CorruptVault` / `FolderInvalid` / `SaveCryptoFailure`, all already mapped by `map_ffi_error`.
- **`#![forbid(unsafe_code)]` intact.** No `manifest_version` bump; no KEM / signature-site / equal-clock change.
- **No secret widening.** New DTO projects counts only — no plaintext, no UUID.
- **Clippy clean with `-D warnings`; `cargo fmt` clean; rustdoc `-D warnings` clean.**
- **Irreversible write is `authorizeWrite`-gated** and classified in `writeCommands.ts` (the #280 scanner).
- Work in the isolated worktree `.worktrees/desktop-empty-trash` (branch `feature/desktop-empty-trash`). All commands below run from that worktree root unless a `cd desktop` is shown.

## File structure

- `desktop/src-tauri/src/dtos/retention.rs` — **modify**: add `EmptyTrashReportDto` + `From<&EmptyTrashReport>` + serde test.
- `desktop/src-tauri/src/dtos/mod.rs` — **modify**: re-export `EmptyTrashReportDto`.
- `desktop/src-tauri/src/commands/retention.rs` — **modify**: add `empty_trash` command + `empty_trash_impl`; extend the bridge + dtos `use` lines.
- `desktop/src-tauri/src/main.rs` — **modify**: register `retention::empty_trash` in `generate_handler!`.
- `desktop/src/lib/trash.ts` — **modify**: add pure `emptyTrashConfirmBody(count)`.
- `desktop/tests/trash.test.ts` — **modify**: test the helper.
- `desktop/src/lib/ipc.ts` — **modify**: add `EmptyTrashReportDto` interface + `emptyTrash()` wrapper.
- `desktop/src/lib/writeCommands.ts` — **modify**: classify `empty_trash` as a gated write.
- `desktop/tests/writeCommands.test.ts` — **modify**: bump command count 43→44 and gated-wrapper count 16→17.
- `desktop/src/components/delete/TrashView.svelte` — **modify**: add the "Empty trash" button + confirm flow.
- `README.md`, `ROADMAP.md` — **modify**: note the shipped desktop empty-trash UX.

## Task ordering note (cross-suite green window)

`writeGateCoverage.test.ts` parses `generate_handler!` from `main.rs` and requires a **two-way** match with the TS classification (`writeCommands.ts`). Registering `empty_trash` in `generate_handler!` (Task 3, Rust) therefore makes the TS `writeGateCoverage` test transiently red until Task 4 (frontend wiring) classifies it. This is expected and mirrors the #409 retention slice: each Rust task is verified with `cargo`, each TS task with `pnpm test`; the branch is fully green again after Task 4. Do **not** try to "fix" the transient red inside Task 3.

---

### Task 1: Pure frontend confirm-body helper

Independent of the backend. Ships the pluralized confirm text as a pure, unit-tested function.

**Files:**
- Modify: `desktop/src/lib/trash.ts`
- Test: `desktop/tests/trash.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `emptyTrashConfirmBody(count: number): string` — the `ConfirmDialog` body used by Task 5.

- [ ] **Step 1: Write the failing test.** Append to `desktop/tests/trash.test.ts` (the file already imports `describe, it, expect` from `vitest` and helpers from `../src/lib/trash`). Add `emptyTrashConfirmBody` to the existing import and append this block:

```typescript
import { sortTrashed, formatTrashedWhen, emptyTrashConfirmBody } from '../src/lib/trash';

// ... (existing describe blocks unchanged) ...

describe('emptyTrashConfirmBody', () => {
  it('uses the singular form for one item', () => {
    expect(emptyTrashConfirmBody(1)).toBe(
      'The 1 item in trash will be permanently deleted. This cannot be undone.',
    );
  });

  it('uses the plural form for multiple items', () => {
    expect(emptyTrashConfirmBody(4)).toBe(
      'All 4 items in trash will be permanently deleted. This cannot be undone.',
    );
  });
});
```

> Note: only add `emptyTrashConfirmBody` to the existing `import { sortTrashed, formatTrashedWhen } ...` line — do not duplicate the import statement. The snippet above shows the merged line for clarity.

- [ ] **Step 2: Run test to verify it fails.**

Run: `cd desktop && pnpm exec vitest run tests/trash.test.ts`
Expected: FAIL — `emptyTrashConfirmBody is not a function` (or an import/type error).

- [ ] **Step 3: Write minimal implementation.** Append to `desktop/src/lib/trash.ts`:

```typescript
/**
 * Body text for the "Empty trash?" confirmation dialog. Pure — no IPC / DOM.
 * `count` is the number of trashed blocks about to be permanently deleted
 * (always ≥ 1 in practice: the button that triggers this only renders when
 * the trash list is non-empty). Pluralized for a clean singular case.
 */
export function emptyTrashConfirmBody(count: number): string {
  const subject = count === 1 ? 'The 1 item' : `All ${count} items`;
  return `${subject} in trash will be permanently deleted. This cannot be undone.`;
}
```

- [ ] **Step 4: Run test to verify it passes.**

Run: `cd desktop && pnpm exec vitest run tests/trash.test.ts`
Expected: PASS (all trash tests green).

- [ ] **Step 5: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-empty-trash
git add desktop/src/lib/trash.ts desktop/tests/trash.test.ts
git commit -m "feat(desktop): pure emptyTrashConfirmBody helper (empty-trash UX T1)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Backend DTO — `EmptyTrashReportDto`

Projects the bridge `EmptyTrashReport` onto a camelCase wire shape. Counts only — no secret widening.

**Files:**
- Modify: `desktop/src-tauri/src/dtos/retention.rs`
- Modify: `desktop/src-tauri/src/dtos/mod.rs`

**Interfaces:**
- Consumes: `secretary_ffi_bridge::EmptyTrashReport` (fields: `purged_count, shared_count, owner_only_count, unknown_count, files_removed, files_failed`, all `u32`).
- Produces: `crate::dtos::EmptyTrashReportDto` with `From<&EmptyTrashReport>` — consumed by Task 3.

- [ ] **Step 1: Write the failing test.** In `desktop/src-tauri/src/dtos/retention.rs`, inside the existing `#[cfg(test)] mod tests { ... }`, add (after `retention_report_dto_camel_case`):

```rust
    #[test]
    fn empty_trash_report_dto_camel_case() {
        let dto = EmptyTrashReportDto::from(&secretary_ffi_bridge::EmptyTrashReport {
            purged_count: 4,
            shared_count: 1,
            owner_only_count: 3,
            unknown_count: 0,
            files_removed: 4,
            files_failed: 0,
        });
        let v = to_json(&dto);
        assert_eq!(v["purgedCount"], 4);
        assert_eq!(v["sharedCount"], 1);
        assert_eq!(v["ownerOnlyCount"], 3);
        assert_eq!(v["unknownCount"], 0);
        assert_eq!(v["filesRemoved"], 4);
        assert_eq!(v["filesFailed"], 0);
        // No snake_case / UUID / window leakage.
        assert!(v.get("purged_count").is_none());
        assert!(v.get("blockUuidHex").is_none());
        assert!(v.get("windowMs").is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails.**

Run: `cargo test --release -p secretary-desktop empty_trash_report_dto_camel_case`
Expected: FAIL — `cannot find type EmptyTrashReportDto` (compile error).

- [ ] **Step 3: Write minimal implementation.** In `desktop/src-tauri/src/dtos/retention.rs`:

Extend the top `use` line to import the bridge type:

```rust
use secretary_ffi_bridge::{EmptyTrashReport, ExpiredEntry, PurgeReport, RetentionPurgeReport};
```

Then add the DTO (place it after `RetentionReportDto`, before `PurgeReportDto`, or at the end of the non-test region — anywhere in the module body):

```rust
/// Report from an `empty_trash` batch purge. Aggregate counts only —
/// no per-block UUID, no window, no plaintext (parity with the security
/// contract of `RetentionReportDto`; nothing secret is projected).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyTrashReportDto {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
}

impl From<&EmptyTrashReport> for EmptyTrashReportDto {
    fn from(r: &EmptyTrashReport) -> Self {
        Self {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
        }
    }
}
```

In `desktop/src-tauri/src/dtos/mod.rs`, extend the retention re-export (keep alphabetical order):

```rust
pub use retention::{
    EmptyTrashReportDto, ExpiredEntryDto, PurgeReportDto, RetentionPreviewDto, RetentionReportDto,
};
```

- [ ] **Step 4: Run test to verify it passes.**

Run: `cargo test --release -p secretary-desktop empty_trash_report_dto_camel_case`
Expected: PASS.

- [ ] **Step 5: Verify lint + format.**

Run: `cargo fmt --all -- --check && cargo clippy --release -p secretary-desktop --tests -- -D warnings`
Expected: clean (no warnings). If `fmt --check` flags the file, run `cargo fmt --all` and re-check.

- [ ] **Step 6: Commit.**

```bash
git add desktop/src-tauri/src/dtos/retention.rs desktop/src-tauri/src/dtos/mod.rs
git commit -m "feat(desktop): EmptyTrashReportDto — counts-only camelCase projection (empty-trash UX T2)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Backend command + `generate_handler!` registration

Adds the `empty_trash` Tauri command and registers it. Follows the `purge_block` shape exactly (snapshot under one lock, one bridge call, typed error via `map_ffi_error`).

**Files:**
- Modify: `desktop/src-tauri/src/commands/retention.rs`
- Modify: `desktop/src-tauri/src/main.rs`

**Interfaces:**
- Consumes: `secretary_ffi_bridge::empty_trash(identity, manifest, device_uuid, now_ms) -> Result<EmptyTrashReport, FfiVaultError>`; `crate::dtos::EmptyTrashReportDto` (Task 2); existing `lock_session`, `now_ms`, `map_ffi_error`.
- Produces: Tauri command `empty_trash` (no args) → `Result<EmptyTrashReportDto, AppError>`; consumed by the frontend `emptyTrash()` wrapper (Task 4) and the write-gate coverage test.

- [ ] **Step 1: Extend the imports in `commands/retention.rs`.**

Change the bridge `use` block to add `empty_trash as bridge_empty_trash` (keep the others):

```rust
use secretary_ffi_bridge::{
    auto_purge_expired as bridge_auto_purge, empty_trash as bridge_empty_trash,
    expired_trash_entries as bridge_expired_entries, purge_block as bridge_purge_block,
};
```

Change the dtos `use` line to add `EmptyTrashReportDto`:

```rust
use crate::dtos::{EmptyTrashReportDto, PurgeReportDto, RetentionPreviewDto, RetentionReportDto};
```

- [ ] **Step 2: Add the command + impl.** In `commands/retention.rs`, add the `#[tauri::command]` wrapper next to the other command wrappers (after `purge_block`):

```rust
#[tauri::command]
pub async fn empty_trash(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<EmptyTrashReportDto, AppError> {
    empty_trash_impl(state.inner())
}
```

And add the impl next to `purge_block_impl` (after it):

```rust
/// Permanently delete every currently-trashed, not-already-purged block in
/// one batch ("empty trash"). Unlike `purge_block`, takes no `block_uuid` —
/// the bridge targets the entire trash in a single manifest commit.
pub fn empty_trash_impl(state: &Mutex<VaultSession>) -> Result<EmptyTrashReportDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        // NOTE arg order: `bridge_empty_trash(identity, manifest, device_uuid,
        // now_ms)` — `device_uuid` is `[u8; 16]` and `now_ms` is `u64`, so the
        // trailing two are distinct types and cannot swap silently (unlike the
        // same-`u64` window/now hazard in `run_retention` or the same-`[u8;16]`
        // hazard in `purge_block`). Guard comment kept for parity.
        let report = bridge_empty_trash(&u.identity, &u.manifest, u.device_uuid, now_ms())
            .map_err(map_ffi_error)?;
        Ok(EmptyTrashReportDto::from(&report))
    })
}
```

- [ ] **Step 3: Register the command.** In `desktop/src-tauri/src/main.rs`, add to the `generate_handler!` list immediately after `retention::purge_block,`:

```rust
            retention::purge_block,
            retention::empty_trash,
```

- [ ] **Step 4: Verify it builds + lints (Rust suite is the gate for this task).**

Run:
```bash
cargo build --release -p secretary-desktop \
  && cargo test --release -p secretary-desktop \
  && cargo fmt --all -- --check \
  && cargo clippy --release -p secretary-desktop --tests -- -D warnings
```
Expected: builds, tests pass, fmt clean, clippy clean.

> Do NOT run `pnpm test` here — the TS `writeGateCoverage` test is expected to be transiently red until Task 4 classifies `empty_trash`. That is by design (see "Task ordering note" above).

- [ ] **Step 5: Commit.**

```bash
git add desktop/src-tauri/src/commands/retention.rs desktop/src-tauri/src/main.rs
git commit -m "feat(desktop): empty_trash Tauri command + generate_handler wiring (empty-trash UX T3)

Follows the purge_block shape: snapshot under one lock, one bridge call
(empty_trash(identity, manifest, device_uuid, now_ms)), typed error via
map_ffi_error. No new FfiVaultError/AppError variant.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Frontend IPC wrapper + write-gate classification

Adds the TS DTO + `emptyTrash()` wrapper and classifies the command as a gated write. Closes the transient TS-red window from Task 3.

**Files:**
- Modify: `desktop/src/lib/ipc.ts`
- Modify: `desktop/src/lib/writeCommands.ts`
- Modify: `desktop/tests/writeCommands.test.ts`

**Interfaces:**
- Consumes: the `empty_trash` Tauri command (Task 3); `call<T>(...)` (existing in `ipc.ts`).
- Produces: `emptyTrash(): Promise<EmptyTrashReportDto>` (consumed by Task 5); the `empty_trash → emptyTrash` gated-write classification.

- [ ] **Step 1: Update the count assertions (failing test first).** In `desktop/tests/writeCommands.test.ts`, bump the two hardcoded counts:

```typescript
  it('classifies exactly the 44 registered commands', () => {
    expect(classifiedCommandNames().size).toBe(44);
  });

  it('lists the gated write wrappers (17)', () => {
    const w = gatedWrappers();
    expect(w).toContain('saveRecord');
    expect(w).toContain('importContact');
    expect(w).toContain('runRetention');
    expect(w).toContain('purgeBlock');
    expect(w).toContain('emptyTrash');
    expect(w).not.toContain('createVault'); // exempt
    expect(w).not.toContain('listBlocks'); // read
    expect(w).toHaveLength(17);
  });
```

- [ ] **Step 2: Run the frontend suite to verify the relevant tests fail.**

Run: `cd desktop && pnpm exec vitest run tests/writeCommands.test.ts tests/writeGateCoverage.test.ts`
Expected: FAIL — count mismatch in `writeCommands.test.ts` (expects 44/17, actual 43/16 + missing `emptyTrash`), and `writeGateCoverage` layer-1 reports `empty_trash` unclassified (from Task 3's registration).

- [ ] **Step 3: Add the IPC DTO + wrapper.** In `desktop/src/lib/ipc.ts`, add the interface next to `RetentionReportDto` / `PurgeReportDto`:

```typescript
export interface EmptyTrashReportDto {
  purgedCount: number;
  sharedCount: number;
  ownerOnlyCount: number;
  unknownCount: number;
  filesRemoved: number;
  filesFailed: number;
}
```

And add the wrapper next to `purgeBlock`:

```typescript
export async function emptyTrash(): Promise<EmptyTrashReportDto> {
  return call<EmptyTrashReportDto>('empty_trash', {});
}
```

- [ ] **Step 4: Classify the command.** In `desktop/src/lib/writeCommands.ts`, add next to `purge_block`:

```typescript
  purge_block: { kind: 'write', gate: 'gated', wrapper: 'purgeBlock' },
  empty_trash: { kind: 'write', gate: 'gated', wrapper: 'emptyTrash' },
```

- [ ] **Step 5: Run the frontend suite to verify it passes (full suite — closes the red window).**

Run: `cd desktop && pnpm test`
Expected: PASS — `writeCommands` counts match (44/17), `writeGateCoverage` layer-1 (two-way match) and layer-2 (`emptyTrash` wrapper exists in `ipc.ts`) both green. Full suite green.

- [ ] **Step 6: Commit.**

```bash
git add desktop/src/lib/ipc.ts desktop/src/lib/writeCommands.ts desktop/tests/writeCommands.test.ts
git commit -m "feat(desktop): emptyTrash IPC wrapper + gated-write classification (empty-trash UX T4)

Closes the transient writeGateCoverage red window from T3: empty_trash is now
classified two-way and bound to the emptyTrash ipc.ts wrapper. Counts bumped
44 commands / 17 gated wrappers.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: TrashView "Empty trash" button + confirm flow

Adds the button (rendered only when the trash list is non-empty) and the `ConfirmDialog`-based, re-auth-gated purge flow. Mirrors the existing `confirmPurge` handler.

**Files:**
- Modify: `desktop/src/components/delete/TrashView.svelte`

**Interfaces:**
- Consumes: `emptyTrash()` (Task 4); `emptyTrashConfirmBody(count)` (Task 1); existing `authorizeWrite`, `ReauthCancelled`, `refreshManifest`, `ConfirmDialog`, `isAppError`.
- Produces: user-facing empty-trash action (terminal — nothing consumes it).

- [ ] **Step 1: Extend the imports.** In the `<script>` block of `TrashView.svelte`:

Add `emptyTrash` to the ipc import:

```typescript
  import { listTrashedBlocks, restoreBlock, purgeBlock, emptyTrash, isAppError, type TrashedBlockDto } from '../../lib/ipc';
```

Add `emptyTrashConfirmBody` to the trash import:

```typescript
  import { sortTrashed, emptyTrashConfirmBody } from '../../lib/trash';
```

- [ ] **Step 2: Add the state + handler.** After the `pendingPurge` state declaration, add:

```typescript
  let pendingEmpty = $state(false);
```

After the `confirmPurge` function, add (this mirrors `confirmPurge` — authorize, run the irreversible batch purge, refresh, reload). **Do not write `emptyTrash(` anywhere above the `authorizeWrite` call in this body, including in comments — the #280 write-gate scanner is comment-naive (see #408) and attributes a bare `emptyTrash(` mention to this body:**

```typescript
  // Mirrors `confirmPurge` for the whole-trash batch: authorize, run the
  // irreversible empty, then refresh the manifest and reload the (now empty)
  // list. The returned report is intentionally not surfaced — the empty list
  // is the success signal (parity with per-block purge).
  async function confirmEmpty() {
    pendingEmpty = false;
    error = null;
    try {
      await authorizeWrite('Confirm permanently deleting all trashed blocks');
    } catch (err) {
      if (err === ReauthCancelled) return;
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    try {
      await emptyTrash();
      await refreshManifest();
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
```

- [ ] **Step 3: Add the button.** In the markup, add an "Empty trash" button that renders only when there are entries. Place it next to the "Run retention now" button — but because `entries` may be `null` (loading) or `[]` (empty), guard the button on a non-empty list. Update the header region:

```svelte
<section class="trash-view">
  <button type="button" class="trash-view__back" onclick={() => back()}>← Trash</button>
  <button type="button" class="trash-view__retention" onclick={() => (showRetention = true)}>
    Run retention now
  </button>
  {#if entries && entries.length > 0}
    <button type="button" class="trash-view__empty-all" onclick={() => (pendingEmpty = true)}>
      Empty trash
    </button>
  {/if}
```

(Leave the rest of the `<section>` body — the error / loading / empty / `{#each}` block — unchanged.)

- [ ] **Step 4: Add the confirm dialog.** After the existing `{#if pendingPurge} … {/if}` block, add:

```svelte
{#if pendingEmpty}
  <ConfirmDialog
    title="Empty trash?"
    body={emptyTrashConfirmBody(entries?.length ?? 0)}
    confirmLabel="Empty trash"
    onConfirm={confirmEmpty}
    onCancel={() => (pendingEmpty = false)}
  />
{/if}
```

- [ ] **Step 5: Type-check + run the full frontend suite.**

Run: `cd desktop && pnpm exec svelte-check && pnpm test`
Expected: svelte-check → 0 errors / 0 warnings; `pnpm test` full suite green (including `writeGateCoverage`, which now scans `TrashView.svelte` and must find `emptyTrash()` gated behind `authorizeWrite` in `confirmEmpty`).

- [ ] **Step 6: Commit.**

```bash
git add desktop/src/components/delete/TrashView.svelte
git commit -m "feat(desktop): TrashView 'Empty trash' button + re-auth-gated batch purge (empty-trash UX T5)

Button renders only when the trash list is non-empty. Single ConfirmDialog
(count via emptyTrashConfirmBody) → authorizeWrite → emptyTrash → refresh +
reload. Report ignored — empty list is the success signal.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Docs — README + ROADMAP

Reflect the shipped desktop empty-trash UX.

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Locate the relevant sections.**

Run:
```bash
grep -n "retention\|Delete forever\|empty[- ]trash\|purge" README.md ROADMAP.md
```
Expected: finds the desktop trash / retention lines added by the #409 slice.

- [ ] **Step 2: Update `README.md`.** In the desktop status area where the #409 retention/purge UX is described, extend the trash-ops description to include "Empty trash" alongside "Run retention now" and per-block "Delete forever" (one dot point / clause; keep it brief per the README style — no test-count walls).

- [ ] **Step 3: Update `ROADMAP.md`.** Where the #409 slice noted empty-trash as deferred, mark the desktop empty-trash UX shipped (and keep iOS/Android empty-trash + retention as the remaining deferred platform surface).

- [ ] **Step 4: Verify no broken references.**

Run: `grep -n "empty" README.md ROADMAP.md`
Expected: the new lines read correctly; no stray "deferred" wording that now contradicts the shipped desktop state.

- [ ] **Step 5: Commit.**

```bash
git add README.md ROADMAP.md
git commit -m "docs: desktop empty-trash UX shipped (empty-trash UX T6)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final full-workspace acceptance (after all tasks)

Run from the worktree root:

```bash
cargo fmt --all -- --check
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
cd desktop && pnpm test && pnpm exec svelte-check
```

All must be green: clippy `-D warnings`, `fmt --check`, rustdoc `-D warnings` clean; lean-binding pass; `pnpm test` full suite; `svelte-check` 0/0.

## Self-review checklist (done during planning)

- **Spec coverage:** DTO (T2) ✓, command+handler (T3) ✓, IPC wrapper (T4) ✓, write-gate classification (T4) ✓, pure helper (T1) ✓, UI button+confirm+re-auth (T5) ✓, docs (T6) ✓, security properties (write-gated in T5, no new variant in T3, counts-only DTO in T2) ✓.
- **Placeholder scan:** none — every code step shows full code; doc steps (T6) name the exact sections and edit intent.
- **Type consistency:** `EmptyTrashReportDto` (Rust `dtos::retention`) ↔ `EmptyTrashReportDto` (TS `ipc.ts`) same six camelCase fields; `emptyTrash` wrapper name matches the `writeCommands` classification (`wrapper: 'emptyTrash'`) and the `TrashView` call; `empty_trash` command name matches `generate_handler!` and the classification key; `emptyTrashConfirmBody(count)` signature matches its call in `TrashView`.
