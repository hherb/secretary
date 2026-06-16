# C.3 Android slice 4 — host-tested sync-UI model (design)

**Date:** 2026-06-16
**Status:** Approved (brainstorm) — ready for implementation plan
**Sub-project:** C.3 (Android sync), slice 4
**Mirrors:** iOS slice 3 (#233, `docs/superpowers/specs/2026-06-15-c3-ios-sync-ui-design.md`) and desktop D.1.15
interactive conflict resolution (`docs/handoffs/2026-06-08-interactive-conflict-resolution-shipped.md`)
**Scope:** the pure, host-tested *testable heart* of the Android sync UI — badge-state derivation, the
`VaultSyncModel` state machine, the `WallClock` / `SyncMonitorHook` seams, decision-collection helpers,
and the real `:kit` wiring (`SystemWallClock`, `MonitorSyncHook`, factory). **No Compose rendering, no app
module, no `androidx.lifecycle` this slice.** Additive only — no `core/` / `ffi/` / `ios/` / on-disk-format
change.

## 1. Context & motivation

C.3 Android slice 3 (#241) shipped a detect-only, debounced "remote changes detected" signal
(`ChangeDetectionMonitor`) for an open vault's folder. Nothing consumes it yet. This slice builds the
**consumer**: the presentation-state machine that turns `pendingChanges` + a `SyncStatus` snapshot + the
result of a sync pass into a badge state, drives the two sync triggers (silent sync-at-unlock and
interactive re-prompt), and surfaces the metadata-only conflict-resolution flow.

This is the Android mirror of iOS slice 3's *testable heart* — the `VaultSyncViewModel` logic — **minus the
rendering layer**. iOS shipped its SwiftUI views into an app that already existed (SecretaryApp from B.3).
Android has **no Compose app module yet**, so standing up the actual `@Composable` badge/password/conflict
screens plus a Compose UI-test harness is a separate, orthogonal slice (slice 5). This slice delivers
everything that can be proven with JUnit 5 host tests against fakes, so the state-machine logic is locked
down before any rendering exists.

The design driver is fidelity: the desktop decision semantics (D.1.15) and the iOS state machine are the
contract. Android must reproduce them exactly — same badge precedence, same two-trigger/one-resolution-path
shape, same `keepLocal` default ("Keep mine", no data loss), same metadata-only conflict surface, same
typed errors that keep the conflict context intact and never auto-dismiss.

## 2. Architecture & module placement

```
[:vault-access]  (pure JVM Kotlin, JUnit 5, Android-free, coroutines only)
   SyncBadgeState.kt      — sealed interface (5 states) + syncBadgeState(...) pure fn
   WallClock.kt           — interface WallClock { fun nowMs(): ULong }
   SyncMonitorHook.kt     — interface SyncMonitorHook { fun muteSelfWrite(); fun acknowledge() }
   VaultSyncModel.kt      — the state-machine class; StateFlow surface + suspend methods
   SyncDecisions.kt       — pure collectDecisions(...) / decisionsComplete(...)
   src/test/:             FakeWallClock, FakeSyncMonitorHook  (reuse existing FakeVaultSyncPort)
        ▲ api dependency
[:kit]  (Android adapters, no Compose)
   SystemWallClock.kt     — nowMs() = System.currentTimeMillis().toULong()
   MonitorSyncHook.kt     — wraps ChangeDetectionMonitor (muteUntil / acknowledge)
   VaultSyncFactory.kt    — makeVaultSync(...) composition + monitor.onChange → model.pendingChangesRaised()
        ▲ (planned)
[slice 5: Compose UI]     — new app module: androidx.lifecycle.ViewModel wrapper + @Composables + UI tests
```

The pure model lives in `:vault-access` (package `org.secretary.sync`) — the project's designated pure-JVM,
JUnit-5, Android-free home, with `kotlinx-coroutines` already wired. It exposes `StateFlow` (coroutines, not
Android), so it is fully host-testable. No new Gradle module; one-concept-per-file discipline keeps it tidy
and it can be extracted to a dedicated module later if it grows.

The real `WallClock` / `SyncMonitorHook` impls and the composition factory live in `:kit`, because
`MonitorSyncHook` needs `monotonicNow()` (`SystemClock.elapsedRealtimeNanos`) and the factory composes the
`:kit`-only `UniffiVaultSyncPort`. This is the same core/adapter cut iOS used (SecretaryVaultAccess vs
SecretaryKit).

## 3. Badge state (pure derivation)

```kotlin
sealed interface SyncBadgeState {
    data object NeverSynced : SyncBadgeState
    data class  Synced(val sinceMs: ULong) : SyncBadgeState   // from SyncStatus.lastStateWriteMs
    data object ChangesDetected : SyncBadgeState              // monitor raised pendingChanges
    data object ReviewNeeded : SyncBadgeState                 // conflictsPending from a prior pass
    data object Syncing : SyncBadgeState
}

fun syncBadgeState(
    inProgress: Boolean,
    pendingChanges: Boolean,
    reviewNeeded: Boolean,
    status: SyncStatus?,
): SyncBadgeState
```

Precedence (mirrors iOS exactly):

1. `inProgress` → `Syncing`
2. else `reviewNeeded` → `ReviewNeeded`
3. else `pendingChanges` → `ChangesDetected`
4. else `status?.lastStateWriteMs != null` → `Synced(lastStateWriteMs)`
5. else → `NeverSynced`

The single `reviewNeeded` input collapses the two ways a review can be pending: the model supplies
`reviewNeeded = reviewNeededFlag || (pendingConflict != null)`. This is required because the sync-at-unlock
path sets the `reviewNeeded` flag **without** a `pendingConflict` object (the password was dropped, so no
interactive conflict is stashed yet), while the interactive path stashes a `pendingConflict`. Both must light
the same badge.

Rendering "synced N min ago" from `sinceMs` is slice 5's concern (it has the wall clock at render time). The
model only carries the epoch-millis value.

## 4. `VaultSyncModel` — surface & state machine

**Constructor dependencies (injected):** `SyncCoordinator`, `WallClock`, `SyncMonitorHook`,
`vaultUuid: ByteArray?`.

**Exposed state — each a `StateFlow`:**

- `badge: StateFlow<SyncBadgeState>`
- `isSyncing: StateFlow<Boolean>`
- `reviewNeeded: StateFlow<Boolean>`
- `pendingConflict: StateFlow<PendingConflict?>`
- `lastError: StateFlow<VaultSyncError?>`

No sheet-presentation booleans — slice 5 derives "show password sheet" / "show conflict sheet" from
`pendingConflict` / `reviewNeeded` / an interactive-begin signal. (`beginInteractiveSync()` exposes the
intent; the model carries no UI-toggle state.)

**Two triggers, one resolution path (faithful to iOS):**

- `suspend fun syncAtUnlock(password: ByteArray)` — one silent pass with the in-hand unlock password.
  `muteSelfWrite()` first. Auto-applying arms (`NothingToDo` / `AppliedAutomatically` / `SilentMerge` /
  `MergedClean`) → `acknowledge()`, recompute badge silently. `ConflictsPending` → set `reviewNeeded = true`,
  **drop password, surface nothing** (the badge shows `ReviewNeeded`; the user resolves later via the
  interactive path — the password is never held across a modal at unlock).
- `fun beginInteractiveSync()` — entry from a badge tap; exposes the intent for slice 5 to prompt for a
  password. No work yet (no-op if already syncing).
- `suspend fun runInteractivePass(password: ByteArray)` — `muteSelfWrite()`, `coordinator.runPass(...)`.
  `ConflictsPending` → stash `pendingConflict` (the coordinator already stashes the TOCTOU freshness token
  internally). Clean arm → clear `pendingConflict` / `reviewNeeded`, `acknowledge()`.
- `suspend fun resolve(decisions: List<SyncVetoDecision>, password: ByteArray)` — `muteSelfWrite()`,
  `coordinator.resolve(...)`. Clean arm → clear conflict, `acknowledge()`.
  `EvidenceStale` / `DecisionsIncomplete` / wrong-password → keep `pendingConflict` set, surface
  `lastError` (slice 5 keeps the sheet open for retry; never auto-dismiss).
- `fun cancelConflict()` — clear `pendingConflict` without writing.
- `fun pendingChangesRaised()` — the monitor `onChange` seam; flips the internal `pendingChanges` flag and
  recomputes the badge.
- `suspend fun refreshStatus()` — best-effort `coordinator.status(vaultUuid)` when `vaultUuid != null`;
  updates the `Synced` label. Failure keeps prior state (no error surfaced for a best-effort read).

`nowMs` for every coordinator call comes from `WallClock.nowMs()` (deterministic in host tests via
`FakeWallClock`). The password is a `ByteArray` argument per call and is **never stored on the model**.

**Concurrency:** main-thread-confined like iOS `@MainActor` — `pendingChangesRaised()` and flag/`StateFlow`
updates run on the UI dispatcher; the underlying `SyncCoordinator` is already `Mutex`-serialized across its
suspending port calls, so the model never drives concurrent passes. Carries the slice-1 caveat: a
`status()`/`refreshStatus()` read parks behind an in-flight pass — slice 5 must not drive a badge refresh off
the same coordinator while a pass is running; read status before/after a pass.

## 5. Decision collection (pure, host-tested)

```kotlin
fun collectDecisions(vetoes: List<SyncVeto>, overrides: Map<String, Boolean>): List<SyncVetoDecision>
fun decisionsComplete(vetoes: List<SyncVeto>, overrides: Map<String, Boolean>): Boolean
```

- Default per record is **`keepLocal = true` ("Keep mine", no data loss)** — `overrides[uuid] ?? true` —
  matching desktop D.1.15.
- Decisions are emitted **one per veto, in veto order**.
- `decisionsComplete` is for slice 5's "Apply enabled" gate; with the keep-mine default it is effectively
  always satisfiable, but the helper is provided to mirror desktop and guard against future non-defaulting
  UI.

The slice-5 conflict sheet owns the transient per-record toggle map and calls
`model.resolve(collectDecisions(vetoes, overrides), password)`. The model never holds toggle state.

**Metadata only:** `SyncVeto` already exposes `recordType` / `tags` / `fieldNames` (names, never values) /
timestamps / `peerDeviceHex`; `SyncCollision` exposes `fieldNames` only. No secret values cross this layer.

## 6. Error handling

Every error path keeps the conflict context intact and surfaces a typed `VaultSyncError` via `lastError` —
no silent swallow, no auto-dismiss. Specifically:

- `WrongPasswordOrCorrupt` on any pass → surface; keep any existing `pendingConflict`.
- `EvidenceStale` / `DecisionsIncomplete` on `resolve` → keep `pendingConflict` set so the user can retry.
- `InProgress` should not occur (model serializes via the coordinator), but if surfaced it is reported, not
  swallowed.
- Best-effort `refreshStatus()` failures are intentionally not surfaced (read-only label refresh) and keep
  prior state.

The typed-error surface is preserved end to end and asserted in tests — no enforcement-by-assumption on the
error paths.

## 7. `:kit` real wiring

- `SystemWallClock` — `nowMs() = System.currentTimeMillis().toULong()`.
- `MonitorSyncHook(monitor: ChangeDetectionMonitor, muteWindow: Duration = defaultSelfWriteMuteWindow)` —
  `muteSelfWrite()` → `monitor.muteUntil(monotonicNow().advancedBy(muteWindow))`; `acknowledge()` →
  `monitor.acknowledge()`. `defaultSelfWriteMuteWindow` is the existing `ChangeDetectionTuning` 10 s constant
  (no new magic number).
- `makeVaultSync(...)` — composition factory: builds `SyncCoordinator` over `UniffiVaultSyncPort`, builds
  the `ChangeDetectionMonitor` (via the existing `makeChangeMonitor`), wraps it in `MonitorSyncHook`,
  constructs `VaultSyncModel`, and wires `monitor.onChange → model.pendingChangesRaised()`. Returns
  `(model, monitor)` for the caller to `start()`/`stop()` (mirrors iOS `makeVaultSync`). Must be called on
  the main thread (the underlying `makeChangeMonitor` already fast-fails off-main).

## 8. Testing (TDD, JUnit 5 host)

Mirror the iOS coverage in `:vault-access/src/test`:

- `syncBadgeState` precedence table — all 5 states + each tie-break.
- sync-at-unlock: auto-arms call `acknowledge()` + silent badge; `ConflictsPending` → `reviewNeeded`,
  password dropped, no conflict surfaced.
- interactive pass: clean → clears conflict + `acknowledge()`; conflict → `pendingConflict` set.
- resolve: success clears + `acknowledge()`; `EvidenceStale` / `DecisionsIncomplete` keep conflict + set
  `lastError`.
- `muteSelfWrite()` called before each writing pass; `acknowledge()` on each clean arm — asserted via
  `FakeSyncMonitorHook` counters.
- `collectDecisions` / `decisionsComplete` — defaults, ordering, completeness.

`:kit` reals get focused tests where meaningful: `MonitorSyncHook` forwarding (real `ChangeDetectionMonitor`
composed from the existing `FakeFolderWatch` + `ManualFlushScheduler`, asserting mute/acknowledge reach the
detector); `SystemWallClock` sanity (monotone, non-zero). `makeVaultSync` is pure composition (covered
indirectly; an instrumented smoke is deferred to slice 5 when an app/emulator surface exists).

## 9. Guardrails & invariants

- Purely additive `:vault-access` / `:kit` Kotlin — **no `core/` / `ffi/` / `ios/` / on-disk-format change**.
  The slice-3 guardrail greps stay empty:
  - `git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'` → empty
  - `git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'` → empty
- Host path stays NDK-free (`:vault-access:test` + `:kit:testDebugUnitTest` need no emulator/native build).
- No new magic numbers: the only timing constant (`defaultSelfWriteMuteWindow`) is the existing
  `ChangeDetectionTuning` value.
- Files stay well under the 500-line guideline (one concept per file).

## 10. Slicing (for the implementation plan)

Roughly six TDD tasks, each red→green→review:

1. `SyncBadgeState` + `syncBadgeState(...)` pure fn + precedence tests.
2. `WallClock` / `SyncMonitorHook` seams + `FakeWallClock` / `FakeSyncMonitorHook` doubles.
3. `SyncDecisions` (`collectDecisions` / `decisionsComplete`) + tests.
4. `VaultSyncModel` state machine + the full state-machine test suite (against `FakeVaultSyncPort` +
   fakes).
5. `:kit` reals — `SystemWallClock`, `MonitorSyncHook` (+ forwarding test).
6. `VaultSyncFactory.makeVaultSync` composition + docs (README/ROADMAP slice-4 ✅).

## 11. What this slice does NOT do (deferred to slice 5)

- The Compose app module, `androidx.lifecycle.ViewModel` wrapper, `@Composable` badge / password sheet /
  conflict-resolution sheet, and the Compose UI-test harness.
- The "synced N min ago" relative-time rendering.
- Any instrumented/on-device coverage of the model wiring (no emulator surface exists until the app module
  lands).
- On-device veto round-trip (the golden vault is single-device → never `ConflictsPending`; exercising
  `resolve` on-device needs a seeded concurrent state — carried).
