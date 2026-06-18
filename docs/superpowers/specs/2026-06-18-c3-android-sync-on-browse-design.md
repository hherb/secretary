# Design — C.3 Android: sync badge + sync-at-unlock on the browse screen

**Date:** 2026-06-18
**Slice:** C.3 Android (sync/browse unification)
**Status:** approved (brainstorming) → ready for plan

## Problem

The Android `:app` walking skeleton routes `Unlock → Browse`. The sync stack
(badge, sync-at-unlock, interactive sync, conflict resolution) shipped as a
*separate* `SyncScreen` in slice 6, then slice 7 replaced the `:app` main screen
with `BrowseScreen` and dropped the sync flow from the running app. Today an
unlocked Android user can browse/edit a vault but sees no sync status and cannot
sync.

iOS already unified these: its `VaultBrowseScreen` (in the **app target**, not
the reusable library) shows the sync badge in the toolbar, hosts the password +
conflict sheets, and fires sync-at-unlock as a background task — composing both
`VaultBrowseViewModel` and `VaultSyncViewModel` at the app layer.

**Goal:** bring the Android app to parity — one screen showing both browse and a
live sync badge, with sync-at-unlock and the interactive sync/conflict flow,
mirroring the iOS layering.

## Non-goals

- No change to `core/`, `ffi/`, the on-disk vault format, or the UDL/FFI surface.
- No change to `:vault-access`, `:browse-ui`, or `:sync-ui` library code. Both
  UI libraries stay decoupled siblings over `:vault-access`; the composition is
  an `:app` concern (mirroring iOS, whose unified screen lives in the app target).
- No restructuring of `:kit`'s `makeVaultSync` to share the browse session (see
  "Known accepted cost" — that would touch the FFI surface and is out of scope).
- No `WorkManager` background sync (still deferred per ADR-0003 foreground-only).

## Approach

A new app-level composable in `:app` — `BrowseWithSyncScreen` — stacks the two
existing, independently-tested library surfaces, reusing `SyncScreen` **as-is**:

```kotlin
Column {
    SyncScreen(viewModel = syncViewModel)      // :sync-ui — badge + password + conflict sheets
    HorizontalDivider()
    BrowseScreen(viewModel = browseViewModel)  // :browse-ui — block/record browse + CRUD
}
```

`SyncScreen` already renders the badge, owns the password/conflict sheets, and
holds the `heldPassword` zeroize discipline for the interactive path. Reusing it
unchanged means the interactive sync flow (badge tap → re-prompt → conflict
resolve) comes for free with zero new test surface in `:sync-ui`/`:browse-ui`
and zero regression risk to their suites (15 + 8 instrumented tests stay green).

Rejected alternative: embedding the badge + sheets *into* `BrowseScreen` inside
`:browse-ui`. That would require a new `:browse-ui → :sync-ui` dependency,
coupling two currently-independent sibling libraries — worse layering than iOS
actually uses, for no functional gain.

## Components

### `BrowseWithSyncScreen` (new, `:app`)

A thin composable: `Column { SyncScreen(sync); HorizontalDivider(); BrowseScreen(browse) }`.
The badge sits above the browse content, so it is visible on both the
block-list and record-list views (BrowseScreen swaps its inner content but the
badge row is outside it). No state of its own.

### `AppRoot.kt` (modified, `:app`)

The `Browse` route grows to carry all three handles, mirroring iOS's
`.browse(browseVM, syncVM, monitor)`:

```kotlin
private sealed interface Route {
    data object Unlock : Route
    data class Browse(
        val browse: VaultBrowseViewModel,
        val sync: VaultSyncViewModel,
        val monitor: ChangeDetectionMonitor,
    ) : Route
}
```

`unlockAndOpen` (runs on the main `rememberCoroutineScope`; `openWithPassword`
hops to IO internally and is awaited, so control returns to main afterward)
becomes, after a successful open and still on the main thread:

1. `open_vault_with_password` → browse session; `VaultBrowseModel(session)` →
   `loadBlocks()` (unchanged).
2. `makeVaultSync(folder, syncStateDir(context.filesDir), goldenVaultUuid)` →
   `(syncModel, monitor)`; wrap the model in `VaultSyncViewModel`. (The factory
   asserts it is called on the main looper — satisfied here.)
3. Return `Route.Browse(browseVM, syncVM, monitor)`.

### Sync-at-unlock (background, non-blocking — mirrors iOS)

Browse renders immediately; the sync pass runs off the render path so the second
Argon2id never blocks the UI:

- Before the existing `password.fill(0)` in `unlockAndOpen`'s `finally`, **clone**
  the password into a fresh `ByteArray`.
- After routing to `Browse`, launch on the app scope:
  `scope.launch { syncViewModel.syncAtUnlock(pwClone); pwClone.fill(0) }`.
  `syncAtUnlock` suspends until the pass settles, so the clone is zeroized only
  after the async Argon2id re-open has consumed it (no use-after-zero race —
  exactly the contract `VaultSyncViewModel.syncAtUnlock` documents).
- A conflict on this silent path only raises the review badge (no sheet — the
  clone is dropped). The interactive path (badge tap) re-prompts for the password
  fresh via the password sheet, so **the unlock password is not retained for
  conflict resolution** — no new long-lived secret buffer is introduced.

### Monitor lifecycle (`AppRoot.kt`)

A `DisposableEffect` keyed on the route's `monitor` calls `monitor.start()` on
entry and `monitor.stop()` on dispose (mirrors slice 6). A failed `start()` is
logged and non-fatal — detection just stays advisory-blind and the badge falls
back to the manual "Sync now" tap (mirrors iOS). The existing
`browseViewModel.lock()` onDispose stays (session wipe on background/teardown).

## Secret hygiene

- The unlock password buffer is still zeroized in `unlockAndOpen`'s `finally` on
  every exit (success, open failure, early throw) — unchanged.
- The sync clone is a second buffer, zeroized in the background coroutine after
  `syncAtUnlock` returns. Both buffers are short-lived; neither is stored on a VM.
- `SyncScreen`'s `heldPassword` lifetime (zeroize on clean pass / cancel / dismiss
  / lifecycle disposal) is reused unchanged — the sole owner of the interactive
  password's lifetime.

## Known accepted cost

Both platforms' `SyncCoordinator` opens the vault with the password per sync call,
so the sync pass runs its own Argon2id derivation (m=256 MiB, t=3) on both iOS
and Android. The Android-specific delta is that Android cannot reuse the open browse
session even to read the vault UUID: iOS's `makeVaultSync(session:)` extracts the
UUID from the already-opened session handle, whereas Android provisions it separately
via `goldenVaultUuid`. Both platforms mitigate the sync-pass Argon2id by running it
in the background, off the browse-render critical path — browse is interactive
immediately while the badge shows "syncing…". Restructuring `:kit` to share the
session is out of scope (it would touch the FFI surface); recorded here so a future
reader does not "fix" the behaviour without realising it is a deliberate scope
boundary.

## Testing (TDD)

### Host-testable (`:app` unit, no emulator)

The unlock orchestration is currently inline in `AppRoot`. Extract the
password-handling + route-assembly into a small host-testable helper so the
clone/zeroize discipline and "both VMs produced" property are unit-tested without
an emulator. The helper takes injected seams (an open port, a `makeVaultSync`
factory function) so it can run over fakes. Properties to assert:

- A successful unlock produces a `Browse` route carrying a browse VM, a sync VM,
  and a monitor.
- The original password buffer is zeroized after the helper returns (every exit).
- The sync clone passed to `syncAtUnlock` is a distinct buffer (not the original),
  and is zeroized after the sync pass settles.
- A failed open returns `Unlock` and still zeroizes the password.

### Instrumented (`:app` connected, emulator)

- The combined screen shows the sync badge **and** the block list together.
- The badge is present on both the block-list and the record-list views (i.e. it
  survives BrowseScreen's inner content swap).
- Reuse the existing `:app` instrumented fakes; add a fake sync VM/model seam if
  the existing fakes do not already cover the sync surface.

### Regression

`:sync-ui` (15) and `:browse-ui` (8) instrumented suites and all host suites stay
green untouched — the reuse approach adds no edits to those libraries.

## Acceptance criteria

1. After unlock, the browse screen shows a live sync badge and runs sync-at-unlock
   (background) without a separate screen.
2. Tapping the badge opens the password sheet → interactive sync → conflict sheet,
   all on the browse screen (reused `SyncScreen` behaviour).
3. The monitor starts on browse entry and stops on dispose; a failed start is
   non-fatal.
4. `:app`, `:browse-ui`, `:sync-ui` host + connected suites green; iOS unaffected.
5. Guardrails empty:
   - `git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'` → empty.
   - `git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'` → empty
     (this is an **Android-only** slice — unlike #254, `ios/` is **not** touched).

## Files (anticipated)

| File | Change |
|---|---|
| `android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt` | new — `Column { SyncScreen; Divider; BrowseScreen }` |
| `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` | `Browse` route carries 3 handles; `unlockAndOpen` builds sync VM + monitor; background sync-at-unlock; monitor lifecycle |
| `android/app/src/main/kotlin/org/secretary/app/UnlockOrchestration.kt` (or similar) | new — extracted host-testable unlock helper (open + makeVaultSync + route assembly + password clone/zeroize) |
| `android/app/src/test/...` | new — host tests for the unlock helper |
| `android/app/src/androidTest/...` | new — instrumented combined-screen test |
| `README.md`, `ROADMAP.md` | sync-on-browse row |
