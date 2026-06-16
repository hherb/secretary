# C.3 Android slice 5 — Compose sync render (design)

**Date:** 2026-06-16
**Sub-project:** C.3 (Android sync), slice 5 (the Compose UI over the slice-4 model)
**Status:** approved design → implementation plan
**Predecessors:** slice 1 (#228-equiv sync orchestration core), slice 2/3 (#239/#241 folder-change detection), **slice 4 (#243, `190d455`) — the host-tested `VaultSyncModel` + seams + `:kit` wiring**
**iOS mirror:** `docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md` (slice 3 of the iOS track)

## 1. Purpose

Slice 4 shipped the **testable heart** of Android sync UI — `VaultSyncModel`
(a plain class exposing `StateFlow`s and `suspend` methods), the
`WallClock`/`SyncMonitorHook` seams, badge-state derivation, and the real
`:kit` `makeVaultSync` composition — but **nothing renders it**. This slice
makes it **user-visible**: a Compose sync badge, a password sheet, and a
metadata-only conflict-resolution sheet, plus the thin `ViewModel` that bridges
the model to Compose.

It is the **Android mirror of iOS slice 3's rendering layer** (`SyncBadgeView`,
`SyncPasswordSheet`, `ConflictResolutionSheet`, `VaultSyncViewModel`), adapted
to the fact that Android's testable heart already lives in `:vault-access`
(iOS put it in the ViewModel). It is also the **first Compose UI-test harness
on Android**.

**Additive only.** `git diff main...HEAD --name-only` must touch only
`android/**`, `docs/**`, `README.md`, `ROADMAP.md`. No Rust, FFI, on-disk
format, crypto, or CRDT change. Both guardrail greps stay empty:
`grep -E 'core/|ffi/|ios/|crypto-design|vault-format'` and
`grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'`.

## 2. The structural gap that shapes scope

Unlike iOS — where slice 3 plugged into an existing `SecretaryApp` walking
skeleton that already had unlock → browse screens — **Android has no app
module and no unlock/browse UI**. The two existing modules are `:vault-access`
(pure Kotlin/JVM, host-tested) and `:kit` (Android library: the uniffi/JNI
adapter + `makeVaultSync`).

Therefore this slice delivers the **sync UI surface and its ViewModel**, not a
runnable app. The real unlock/lock lifecycle wiring (`monitor.start()` on
unlock, `syncAtUnlock(password)`, `monitor.stop()` on lock/background) is a
**documented integration seam** consumed by a future `:app` module — see §7.
This matches the project's small-slice, host-tested-first discipline.

## 3. Architecture

A new Gradle module **`:sync-ui`** (`com.android.library`, Compose enabled),
package `org.secretary.sync.ui`.

```
┌─ :vault-access (pure Kotlin/JVM — slice 4, UNCHANGED) ──────────────────────┐
│  VaultSyncModel       StateFlows + suspend methods (the testable heart)      │
│  SyncBadgeState       sealed interface + pure syncBadgeState(...)            │
│  PendingConflict / SyncVeto / SyncCollision / SyncVetoDecision               │
│  collectDecisions / decisionsComplete                                        │
│  FakeVaultSyncPort / FakeWallClock / FakeSyncMonitorHook (test doubles)      │
├─ :sync-ui (NEW — Android library, Compose, FFI-free) ───────────────────────┤
│  VaultSyncViewModel   androidx.lifecycle.ViewModel; thin bridge over the     │
│                       injected VaultSyncModel; owns sheet-presentation state │
│  SyncBadge            @Composable — 5 states, tap → onTap                    │
│  SyncPasswordSheet    @Composable — ModalBottomSheet, password local-only   │
│  ConflictResolutionSheet @Composable — per-record Keep mine / Accept delete │
│  SyncScreen           @Composable — wires the VM's collected state into the  │
│                       three surfaces (instrumented-test entry point)         │
│  relativeSyncedLabel / badgeLabel / badgeIcon   pure render helpers          │
├─ :kit (Android library — slice 4, UNCHANGED) ───────────────────────────────┤
│  makeVaultSync(folder, stateDir, vaultUuid) -> (VaultSyncModel, monitor)     │
│     ← the production composition root; injected into the VM by a future :app │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Key dependency rule:** `:sync-ui` depends on **`:vault-access` only, not
`:kit`**. The ViewModel takes an *injected* `VaultSyncModel` (production: from
`:kit`'s `makeVaultSync`; tests: built over the existing `FakeVaultSyncPort`).
Consequences:

- `:sync-ui` pulls in **no JNA, no uniffi, no NDK, no `.so`** on either the
  build or the test path. It mirrors iOS, where the ViewModel lives in the pure
  `SecretaryVaultAccessUI` and the factory lives in `SecretaryKit`.
- The **instrumented Compose UI tests render against a fake-backed model** and
  need no native library — the emulator run is pure-UI and fast.

`settings.gradle.kts` gains `include(":sync-ui")`. `android.useAndroidX=true`
is set in `gradle.properties` (required for the AndroidX Compose test deps,
per the project's instrumented-test notes). `:sync-ui` adds the Compose BOM,
`androidx.lifecycle:lifecycle-viewmodel-compose`, `androidx.activity:activity-compose`
(instrumented-test host), and `androidx.compose.ui:ui-test-junit4` /
`ui-test-manifest`.

## 4. Components

### 4.1 `VaultSyncViewModel` (androidx.lifecycle.ViewModel)

A thin adapter over `VaultSyncModel` — it owns **no** badge/conflict logic.

- **Construction:** `class VaultSyncViewModel(private val model: VaultSyncModel) : ViewModel()`.
  A `ViewModelProvider.Factory` (or `viewModel { }` initializer) supplies the
  model. No FFI reference.
- **Re-exposes** the model's five `StateFlow`s (`badge`, `isSyncing`,
  `reviewNeeded`, `pendingConflict`, `lastError`) for Compose to collect via
  `collectAsStateWithLifecycle()`.
- **Owns the sheet-presentation state** the model deliberately omits (slice 4
  dropped `beginInteractiveSync()` as a UI concern):
  `passwordSheetVisible: StateFlow<Boolean>`.
- **Methods** launch the model's `suspend` functions in `viewModelScope`:
  - `beginInteractiveSync()` — show the password sheet (trigger-2 entry).
  - `submitPassword(password: ByteArray)` — `model.runInteractivePass(password)`,
    then hide the sheet (the conflict sheet, if any, is driven by
    `pendingConflict` going non-null).
  - `resolve(decisions, password)` — `model.resolve(...)`.
  - `cancelConflict()` / `dismissPasswordSheet()`.
  - `refreshStatus()` — best-effort label refresh (read before/after a pass).
  - `syncAtUnlock(password)` — exposed for the **future** app's unlock hook
    (not driven by any UI in this slice).
- **Concurrency / host-testability:** `viewModelScope` runs on
  `Dispatchers.Main`. Host tests use `Dispatchers.setMain(StandardTestDispatcher())`
  (kotlinx-coroutines-test, already a dep) so the forwarding + sheet-state
  logic is plain JUnit5 host tests — no emulator. Rendering is what goes
  instrumented.

### 4.2 Compose surfaces (stateless / hoisted)

All three take state + lambdas and hold no ViewModel reference, so `@Preview`
and the UI tests drive them directly.

- **`SyncBadge(state: SyncBadgeState, nowMs: Long, onTap: () -> Unit)`** —
  renders all 5 states: icon + short label (`Synced 3m ago` / `Changes detected`
  / `Review needed` / a spinner for `Syncing` / `Never synced`). Tap → `onTap`,
  disabled while `Syncing`. Label/icon come from the pure helpers (§4.3).
- **`SyncPasswordSheet(error: VaultSyncError?, onSubmit: (ByteArray) -> Unit, onDismiss: () -> Unit)`**
  — a `ModalBottomSheet`. Password lives only in a transient
  `remember { mutableStateOf("") }` (**not** `rememberSaveable` — never
  persisted/restored). On submit it is encoded to a `ByteArray`, handed to
  `onSubmit`, and the field state is cleared; cleared on every terminal path
  (submit, cancel, conflict-handoff). Inline error, stays open on failure.
- **`ConflictResolutionSheet(conflict: PendingConflict, error: VaultSyncError?, onResolve: (List<SyncVetoDecision>) -> Unit, onCancel: () -> Unit)`**
  — a `ModalBottomSheet` mirroring desktop D.1.15 / iOS 1:1. One card per
  `SyncVeto`: record type · tags · `fieldNames` · "deleted on device
  `<peerDeviceHex prefix>`"; a per-record **Keep mine / Accept delete** toggle,
  default `keepLocal = true`. A read-only collapsible disclosure lists
  `SyncCollision` auto-merged fields ("N field(s) auto-merged — no action
  needed"). "Apply" assembles decisions via the existing `collectDecisions`
  (slice 4) and calls `onResolve`. Inline error, stays open on
  `EvidenceStale`/`DecisionsIncomplete`. **Metadata only — no secret field
  value is ever shown.**
- **`SyncScreen(viewModel)`** — collects the VM's flows and wires them into the
  three surfaces (badge always visible; password sheet gated on
  `passwordSheetVisible`; conflict sheet gated on `pendingConflict != null`).
  This is the instrumented-test entry point.

### 4.3 Pure render helpers (host-tested, no magic numbers)

In `:sync-ui` (rendering-only, so not in `:vault-access`):

- **`relativeSyncedLabel(sinceMs: ULong, nowMs: ULong): String`** — "just now"
  / "Nm ago" / "Nh ago" / "Nd ago". Bucket thresholds are named constants
  (`JUST_NOW_CUTOFF_MS`, `MINUTE_MS`, `HOUR_MS`, `DAY_MS`) — no inline numbers.
  `now` is a parameter (no real-clock call, mirroring the `WallClock`
  discipline); the composable passes `System.currentTimeMillis()` at render.
- **`badgeLabel(state, nowMs): String` / `badgeIcon(state): ImageVector`** —
  pure state → display mapping (icons from `androidx.compose.material.icons`);
  the `Synced` arm delegates to `relativeSyncedLabel`.
  Keeps the composable declarative and the label/icon choice host-tested.

Conflict-decision assembly **reuses** slice 4's `collectDecisions` /
`decisionsComplete` (`:vault-access`). The sheet only toggles per-record
`keepLocal`; no new decision logic.

## 5. Testing matrix

| Layer | Kind | Location | Emulator |
|---|---|---|---|
| `relativeSyncedLabel`, `badgeLabel`, `badgeIcon` | JUnit5 host | `:sync-ui` `src/test` | no |
| `VaultSyncViewModel` forwarding + sheet state | JUnit5 host (`Dispatchers.setMain`, `FakeVaultSyncPort`-backed model) | `:sync-ui` `src/test` | no |
| `SyncBadge` (5 states), `SyncPasswordSheet`, `ConflictResolutionSheet`, `SyncScreen` end-to-end (badge-tap → password → conflict → resolve → cleared) | Compose UI test (`createAndroidComposeRule`) over a `FakeVaultSyncPort`-backed model | `:sync-ui` `src/androidTest` | **yes** (no `.so` — fake-backed) |

The instrumented suite drives a real `VaultSyncModel` built over the existing
`FakeVaultSyncPort`, with the fake configured to return `ConflictsPending` so
the conflict sheet is exercised on-device (the single-device golden vault never
produces a conflict — carried `[[project_secretary_sync_veto_needs_seeded_state]]`).
Per the project's instrumented-test notes, `connectedAndroidTest` rejects
`--tests`; select a single test with
`-Pandroid.testInstrumentationRunnerArguments.class=...`.

### Acceptance (the gauntlet)

```bash
cd android
./gradlew :sync-ui:test                          # host JUnit5 — green, 0 warnings
PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest    # Compose UI tests on emulator — green
./gradlew :vault-access:test :kit:testDebugUnitTest  # unchanged suites still green
# guardrails (both empty):
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

## 6. Secret hygiene

The password is never stored on the model or ViewModel (slice 4 invariant). In
`SyncPasswordSheet` it lives only in transient Compose state (not
`rememberSaveable`), is encoded to a `ByteArray` at submit, handed straight to
the ViewModel method, and the Compose field state is cleared on every terminal
path. Kotlin `String` is immutable and cannot be truly zeroized — so the policy
is minimal lifetime + clear-ASAP (same posture as iOS, which nulls the Swift
`Array`). No secret field *value* is ever rendered anywhere — the conflict
sheet shows `fieldNames` only (anti-oracle / metadata-only discipline).

## 7. Out of scope (the deferred integration seam)

- **No app lifecycle wiring.** `:sync-ui` exposes `VaultSyncViewModel(model)` +
  `SyncScreen(...)`. The real `makeVaultSync(...) → (model, monitor)`
  composition and `monitor.start()`-on-unlock / `syncAtUnlock(password)` /
  `monitor.stop()`-on-lock handoff land when a `:app` module exists (later
  slice). The integration contract: the app builds the pair via `:kit`,
  constructs the ViewModel with the model, observes the monitor's `onChange`
  (already wired into `model.pendingChangesRaised()` by `makeVaultSync`), and
  drives `refreshStatus()` before/after a pass for the "synced N ago" label.
- **No on-device veto round-trip against a real vault.** The conflict path is
  exercised via the fake; a real concurrent-state round-trip needs a seeded
  divergent vault (carried).
- **No production change** to `:vault-access` / `:kit` / `core` / `ffi` /
  `ios` / on-disk format — additive `:sync-ui` only.

## 8. Deliberate decisions (so a future reader does not "fix" them)

- **`:sync-ui` depends on `:vault-access`, not `:kit`** — keeps the UI module
  FFI-free and the instrumented tests `.so`-free. Mirrors the iOS
  pure-UI / thin-conformer split.
- **ViewModel owns sheet-presentation state, the model does not** — continues
  the slice-4 decision to treat sheet presentation as a UI concern (the model
  surfaces `pendingConflict`; the *password* sheet's visibility is VM state).
- **Compose surfaces are stateless/hoisted** — so `@Preview` and UI tests drive
  them without a ViewModel, and the VM stays the single state owner.
- **Instrumented (emulator) Compose tests, not Robolectric** — chosen to avoid
  Robolectric-on-Compose caveats and exercise the real Android runtime;
  fake-backed so no native lib is needed. The host JUnit5 tests still cover the
  pure helpers and VM forwarding off the emulator.
