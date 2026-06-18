# Write-action in-flight guard (#254) — design

**Date:** 2026-06-18
**Issue:** [#254](https://github.com/hherb/secretary/issues/254) — *Android: Save/delete/restore not debounced — concurrent commit can double-write (Add)*
**Scope:** Android (`:vault-access`, `:browse-ui`) + iOS (`SecretaryVaultAccess`) parity. **No `core` / `ffi` / on-disk-format / UDL change.**

## Problem

The Compose and SwiftUI write actions are not guarded against an in-flight write:

- **Android** `RecordEditModel.commit()`, `VaultBrowseModel.delete()` / `restore()` are `suspend`, launched on `viewModelScope`. Two fast Save (or Delete/Restore) taps spawn **two concurrent coroutines**; both pass validation and both call the FFI writer → in **Add** mode, **two records appended**. `commit()` sets `committed`/the write succeeds only *after* the suspend `appendRecord` returns, so the second coroutine is already past the early guards. Edit mode is idempotent-ish (same record UUID); Add is not.
- **iOS** `RecordEditViewModel.commit()`, `VaultBrowseViewModel.delete()` / `restore()` are **synchronous** on `@MainActor`. Events serialize, so the window is narrower: a second tap can only land in the **render gap** after the first `commit()` set `committed = true` but before SwiftUI re-renders to dismiss the form. In that gap a second synchronous `commit()` runs and (Add mode) appends again, because `commit()` does not check `committed`.

The session lock already serializes the *I/O*, but that does not help: two Adds simply queue behind the lock and **both still append**. The dedup must happen at the **intent layer** (the model), not the I/O layer.

## Goal

No write action (record Add/Edit `commit`, or list `delete`/`restore`) executes twice from concurrent or rapid-repeat invocations. The fix lives in the **host-tested model layer** (a re-entrancy guard, unit-testable); the UI reads the guard flag to disable buttons. Android and iOS reach parity.

## Non-goals

- Read-path actions (`setShowDeleted`, `selectBlock`, `reveal`) — reads, not writes; unguarded, out of scope.
- Per-row granularity. A single **global** `writing` flag disables all Delete/Restore buttons while any one write is in flight (decision below).
- Any `core` / `ffi` / UDL / KAT / on-disk-format change. The FFI write surface is unchanged.

## Design

### Decision: model-level re-entrancy guard + UI disable

Rejected alternatives:
- **UI-only disable** — not host-testable, and a UI that forgets to disable still double-writes; the bug survives in the model.
- **Mutex / single-flight in the `:kit` session adapter** — the session lock already serializes I/O, so two Adds still both append; dedup must be at the intent layer, and a `:kit`-level guard is not exercisable in the pure host-tested model.

The guard is the **correctness** fix (host-testable: fire two concurrent `commit()`s, assert exactly one `appendRecord`). The disabled button is the **UX** layer reading the same flag. Each flag is **local to the model that owns the responsibility** — single-responsibility, both files stay well under 500 lines.

### Decision: global `writing` flag for the record list

A single `writing` flag on `VaultBrowseModel` disables **every** Delete/Restore button while any write is in flight. Writes already serialize under the session lock, so blocking a second different-row write (which would otherwise queue and could still double-act) is the correct "no concurrent writes" posture. One `StateFlow`, one host test.

### Android

**`RecordEditModel` (`:vault-access`)**
- Add `private val _inFlight = MutableStateFlow(false)` + `val inFlight: StateFlow<Boolean>`.
- `commit()` becomes:
  ```
  suspend fun commit() {
      if (_inFlight.value || _committed.value || _loadFailed.value) return
      _inFlight.value = true
      try {
          // existing: buildContent → validate → appendRecord/editRecord → committed
      } finally {
          _inFlight.value = false
      }
  }
  ```
  The guard checks **three** flags: `inFlight` blocks a *concurrent* coroutine (two Saves launched before the first returns); `committed` blocks a *post-success re-tap* (a second Save landing in the render gap after the first succeeded but before `LaunchedEffect(committed)` → `onEditCommitted` clears `editing` — Android's analog of iOS's sync render-gap, and the symmetric reason iOS guards on `committed`); `loadFailed` is the existing "never clobber a half-read record" guard. The `CancellationException` rethrow stays — `finally` resets `inFlight` first, then the throw propagates.

**`VaultBrowseModel` (`:vault-access`)**
- Add `private val _writing = MutableStateFlow(false)` + `val writing: StateFlow<Boolean>`.
- `commitThenReload` wraps its body:
  ```
  private suspend fun commitThenReload(op: suspend (BlockSummaryView) -> Unit) {
      val block = _selectedBlock.value ?: return
      if (_writing.value) return
      _writing.value = true
      try {
          try { op(block) } catch (e: VaultBrowseError) { _error.value = e; return }
          selectBlock(block)
      } finally {
          _writing.value = false
      }
  }
  ```
  Both `delete` and `restore` route through this, so both are covered. `lock()` resets `_writing.value = false` alongside the other flow resets (defense-in-depth; a wipe during a write).

**`VaultBrowseViewModel` (`:browse-ui`)**
- Re-expose `val writing: StateFlow<Boolean> = model.writing`. The edit form's `inFlight` is read off `editing.value?.inFlight` in the composable (the form already collects the active `RecordEditModel`).
- The `commitEdit` / `delete` / `restore` launchers are **unchanged** — the model guard makes even a double-launch safe.

**Compose UI (`:browse-ui`)**
- `RecordEditForm`: collect `inFlight` from the model; **Save** `enabled = !loadFailed && !inFlight`.
- `BrowseScreen`: collect `writing`; per-row **Delete** / **Restore** `enabled = !writing`; **Add** button `enabled = !writing` (consistency — opening a form mid-write is harmless but the disable keeps the surface uniform).

### iOS (`SecretaryVaultAccess`)

Synchronous, so the mechanism differs but the concept matches.

**`RecordEditViewModel`**
- Add `@Published public private(set) var isWriting = false`.
- `commit()` gains a top guard `guard !committed, !isWriting else { return }`. The `committed` guard is iOS's actual Add-double-write fix (closes the render-gap re-entry). `isWriting` is set `true` around the synchronous op and reset in a `defer`, driving the button-disable.
- SwiftUI Save `.disabled(viewModel.loadFailed || viewModel.committed || viewModel.isWriting)`.

**`VaultBrowseViewModel`**
- Add `@Published public private(set) var isWriting = false`.
- `commitThenReload` gains `guard !isWriting else { return }`, sets `isWriting` around the op (`defer` reset).
- SwiftUI per-row Delete/Restore (and Add) `.disabled(viewModel.isWriting)`.

## Error handling

The `finally` (Android) / `defer` (iOS) guarantees the flag clears on **success, typed error, and unexpected throwable** — a failed write re-enables the button so the user can retry. Android's `CancellationException` rethrow happens after the `finally` resets the flag. A rejected write still leaves the visible list intact (the existing `commitThenReload` re-reads on success only — unchanged).

## Testing (TDD — test first per task)

**Android host (JUnit5):**
- `RecordEditModel`:
  - two concurrent `commit()` (Add) on a gated `FakeVaultSession` → exactly **one** `appendRecord` (assert the fake's append audit list size == 1). The fake's write awaits an injected gate so both coroutines reach the guard while the first is in flight (a faithful race, not a sleep).
  - a second `commit()` *after* the first succeeded (Add) → still exactly **one** `appendRecord` (the `committed` guard — the post-success re-tap case).
  - `inFlight` is observed `true` while the gated write is parked and `false` after the gate releases.
  - a failing write (`FakeVaultSession` throws) resets `inFlight` to `false`.
  - `loadFailed == true` → `commit()` no-ops and never sets `inFlight`.
- `VaultBrowseModel`:
  - two concurrent `delete` → one `tombstoneRecord`; same for `restore`.
  - `writing` toggles true→false across a write; error path resets it.

**Android instrumented (Compose):**
- Save button disabled while `inFlight` (drive a slow fake) and while `loadFailed`.
- Delete/Restore disabled during `writing`.

**iOS (`swift test`):**
- a second `commit()` after the first succeeded (Add) does **not** append again (assert fake append count == 1) — the `committed` guard.
- `isWriting` reflects state across a `commit` / `delete`.

## Guardrails

```bash
# core/ffi/format must NOT change (ios/ IS touched this slice, so it is allowed):
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'   # must be empty
# everything is under android/, ios/, docs/:
git diff main...HEAD --name-only | grep -vE '^(android/|ios/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'  # must be empty
```

Note: unlike prior Android-only slices, **`ios/` is intentionally in the diff** this slice — the standard "no `ios/` change" guardrail does **not** apply and the handoff will say so explicitly.

## Acceptance

- `cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test` → green.
- `cd android && ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest` → green on `Medium_Phone_API_36.1`.
- `cd ios/SecretaryVaultAccess && swift test` → green.
- The two guardrail greps above are empty.
- #254 fully closed (both Android and iOS halves).
