# Purge-count post-op feedback (#411) — design

**Date:** 2026-07-11
**Issue:** [#411](https://github.com/hherb/secretary/issues/411) — *destructive-trash ops assert a client-snapshot count / discard the actual purge report*
**Scope:** UI-only, cross-platform (desktop + iOS + Android). **No `core` / `ffi` / bridge / on-disk-format / `manifest_version` change; no new `FfiVaultError`/`VaultBrowseError` variant. `#![forbid(unsafe_code)]` intact.**

## Problem

The three destructive trash operations — **empty-trash**, **purge-block** (delete-forever a single block), and **retention auto-purge** — confirm against a *client-side snapshot* and then discard the *actual on-disk result*. Each op's port already returns a count-bearing report DTO (`purgedCount`, `filesFailed`, …), but every UI layer throws it away; the "reloaded / empty list is the success signal" was the design contract to date. The confirmation text makes a specific promise the app never reconciles against the real outcome. On iOS and Android the report is already plumbed to the port layer *specifically for #411* — only the view-model discards it.

## Fix (one sentence)

Capture the report the op already returns, run it through a **pure, host-testable formatter** that maps a report → `(text, severity)`, and render the result in an **inline status banner** beside each platform's existing error banner.

## Non-goals

- No change to the pre-op **confirmation dialogs**. The stale-snapshot *pre*-op count stays as-is; #411's fix is the *post*-op reconciliation, not preventing the (single-user-benign) snapshot drift.
- No toast/snackbar infrastructure (rejected in brainstorm: a failure warning that auto-dismisses can be missed; more new infra on desktop + Android).
- No FFI / bridge / core / on-disk-format change. The DTOs already carry every field used.

## Message content (the pure formatter)

One formatter per platform, identical logic, host-tested. Input: the op's report DTO. Output: `(text: String, severity: {success | warning})`.

| Op | Report condition | Severity | Text |
|----|----|----|----|
| **empty-trash** | `purgedCount = N > 0`, `filesFailed = 0` | success | `Purged N items` |
| **empty-trash** | `purgedCount = N`, `filesFailed = M > 0` | warning | `Purged N items · M files could not be removed` |
| **retention** | `purgedCount = N > 0` | success / warning | same rows as empty-trash |
| **retention** | `purgedCount = 0` | success | `No items were past the retention window` |
| **purge-block** (single) | — (DTO carries no count/`filesFailed`) | success | `Deleted forever` |

**Pluralization** is handled inside the formatter: `1 item` vs `N items`; `1 file` vs `M files`. The exact user-facing strings are the reference wording; a platform may adapt casing/punctuation to its idiom but the branch logic (which severity, which count) is identical and pinned by tests.

**Rationale for surfacing `filesFailed`:** the issue is explicitly about the *honesty gap* — a silent partial failure (blocks whose on-disk files could not all be removed) is exactly the discrepancy #411 names. Count-only would move the same gap rather than close it.

**Rationale for single-block "Deleted forever":** `PurgeReportDto` / `PurgeResultInfo` carry `filesRemoved` but **no** `purgedCount` and **no** `filesFailed` — the "1 item" is implicit and there is no failure signal to surface. Showing a count there would be inventing data the DTO does not carry.

## Per-platform mechanism

All three: capture the currently-discarded return, format it, publish it to a notice state, render an inline banner. The banner is dismissed/replaced on the next op (same lifecycle as the existing error banner).

### Desktop (`desktop/`)
- **Capture:** `TrashView.svelte` (`purgeBlock` @76, `emptyTrash` @99) and `RetentionDialog.svelte` (`runRetention` @73) — keep the returned `PurgeReportDto` / `EmptyTrashReportDto` / `RetentionReportDto` instead of ignoring it.
- **Formatter:** new pure module `desktop/src/lib/purgeNotice.ts` — `formatPurgeNotice(report) → { text, severity }`, no I/O, no store access.
- **Render:** a `<p role="status">` (with a warning variant class) beside the existing `role="alert"` error paragraph in `TrashView.svelte`. Remove the obsolete "The returned report is intentionally not surfaced" comment (lines ~84–87).

### iOS (`ios/`)
- **Structural:** `TrashViewModel.reauthedWrite(reason:op:)`'s `op` closure is `() throws -> Void`, which structurally drops the report. Make it return-carrying (generic over the op's report type, or a small enum), so each op can stash its count.
- **Publish:** add `@Published var purgeNotice: PurgeNotice?` (where `PurgeNotice = (text, severity)`), set after the write, cleared at the start of the next write.
- **Formatter:** pure `formatPurgeNotice(...)` in `SecretaryVaultAccess` (host-testable, FFI-free — mirrors `formatTrashedWhen` from #413).
- **Render:** an inline banner in `ios/SecretaryApp/Sources/TrashScreen.swift` bound to `purgeNotice`.

### Android (`android/`)
- **Structural:** `TrashBrowseModel.guardedWrite(reason, op)`'s `op` is `suspend () -> Unit`, dropping the report. Make it return-carrying so each op can read its count. (Interface doc at `TrashPort` line ~99 already says "Reports are returned (plumbed for #411) but the VM discards them.")
- **Publish:** add a success/warning `StateFlow<PurgeNotice?>` to `TrashBrowseModel`, mirroring the existing `error` StateFlow lifecycle.
- **Formatter:** pure `formatPurgeNotice(...)` in `:vault-access` (host unit-testable — same module as `TrashFormattingTest`).
- **Render:** a `TrashSuccessBanner` composable beside `TrashErrorBanner` in `android/browse-ui/.../ui/TrashScreen.kt`, with a distinct `testTag` (e.g. `"trash-notice"`).

## Testing (TDD — test first, per row)

- **Formatter unit tests** (all three platforms), one assertion per table row plus pluralization boundaries:
  - `purgedCount = 1` → `Purged 1 item` (singular).
  - `purgedCount = 4, filesFailed = 0` → `Purged 4 items`, success.
  - `purgedCount = 4, filesFailed = 1` → `Purged 4 items · 1 file could not be removed`, warning (singular "file").
  - `purgedCount = 4, filesFailed = 2` → `… 2 files …`, warning (plural).
  - retention `purgedCount = 0` → `No items were past the retention window`, success.
  - single-block → `Deleted forever`, success.
- **View-model / component tests** asserting the report is **captured** and the notice state is set:
  - Desktop: extend `desktop/tests/TrashView.test.ts` + `RetentionDialog.test.ts` — the ipc mock returns a report with a known `purgedCount`/`filesFailed`; assert the `role="status"` banner text.
  - iOS: extend `TrashViewModelTests` (via `FakeTrashPort` returning configurable counts) — assert `purgeNotice` after each op; assert cleared at the next op's start.
  - Android: extend `TrashBrowseModelTest` (via `FakeTrashPort`) — assert the notice `StateFlow` after each op.
- **Banner render assertion** via role / testTag on each platform.

## Acceptance criteria

1. After empty-trash / retention / delete-forever, an inline status banner shows the count-derived text from the **returned** DTO (not the pre-op snapshot).
2. When `filesFailed > 0`, the banner is a **warning** and names the failed-file count; a fully-successful op is a **success** banner.
3. Retention with nothing expired shows a distinct "nothing past the window" message.
4. Formatter logic is a pure function with unit tests pinning every row above; view-model/component tests prove the report is captured (not discarded).
5. All existing gates stay green: desktop `pnpm test` + `svelte-check`; iOS `swift test` (`SecretaryVaultAccess`); Android `:vault-access:test` + `:browse-ui`/`:app` compile + `:kit:lintDebug`. Desktop write-gate coverage (#280) and lean-binding guard unaffected (no new Tauri command, no FFI change).
6. No `core` / `ffi` / bridge / on-disk-format / `manifest_version` change; no new error variant; `#![forbid(unsafe_code)]` intact.

## Risks / open items

- **iOS `SecretaryApp` banner is in the XcodeGen target**, not host `swift test`. The pure formatter + VM logic in `SecretaryVaultAccess` **are** host-tested; the `TrashScreen.swift` render binding is a thin call site. A full `run-ios-tests.sh` confirms the app compiles (multi-minute xcframework build — [[project_secretary_ios_xcframework_build_watchdog]]).
- **Return-carrying `guardedWrite`/`reauthedWrite`** is a small structural change to a shared write helper — must preserve the re-auth gate and error handling exactly; only the return type changes. Covered by existing write-reauth tests plus the new notice assertions.
- The `.claude/worktrees/strange-mayer-*` tree is a stale duplicate of these paths — all edits target the live (`.worktrees/purge-count-feedback`) paths.
