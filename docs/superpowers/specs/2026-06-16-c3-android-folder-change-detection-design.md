# C.3 Android slice 3 — folder-change detection (detect-only) — design

**Date:** 2026-06-16
**Sub-project:** C.3 (mobile sync adapters), Android, slice 3 of 4
**Builds on:** slice 1 (sync orchestration core, #237 — `SyncCoordinator` / `VaultSyncPort` / `SyncModels`), slice 2a (real `UniffiVaultSyncPort`, #238), slice 2b (emulator round-trip, #239)
**Mirrors:** iOS slice 2 (#230, `docs/superpowers/specs/2026-06-15-c3-ios-folder-change-detection-design.md`)
**Status:** approved (brainstorm) — pending implementation plan

## Purpose

Give the Android app a **debounced, foreground-gated "remote changes detected" signal** for an open vault's
folder, so a later UI slice (slice 4 — Compose sync UI) can show a sync badge / "Sync now" affordance. Per
ADR-0003 mobile sync is realistically **foreground-only** (no reliable background file watchers). This slice
ships the host-tested detection core plus the real platform watcher; it does **not** run a sync pass or build
UI. It is a faithful Kotlin mirror of the iOS slice-2 architecture.

## The central constraint (why "detect-only")

`sync_vault` / `sync_commit_decisions` re-open the identity from the **password** (full Argon2id cost). The
app deliberately **drops the password after unlock** (secret hygiene — see slice 1 + lock-on-background).
Therefore a file-change event **cannot silently run a sync pass** — there is no password in hand once the user
is browsing.

So a detected change does not call `SyncCoordinator.runPass`. It sets an **advisory, metadata-only signal**
(`pendingChanges`). Acting on that signal — re-prompting for the password or running sync-at-unlock — is
slice 4's concern, alongside the conflict-resolution UI. The password-availability policy is therefore
**deferred to slice 4** where there is a UI to handle it.

## Scope

**In:** a pure host-tested change-detection core (`:vault-access`, package `org.secretary.sync`) + the real
`FileObserver`-based watcher (`:kit`, same package) + one instrumented smoke test on the emulator.
**Out:** any `runPass` call; the Android `ViewModel` / `StateFlow` / sync badge / conflict-resolution sheet
(slice 4); a `SyncMonitorHook` self-write-mute adapter (slice 4, when a writer exists); WorkManager background
polling (explicitly deferred — see "Background-execution decision"); the `state_dir` container path decision
(already exercised by slice 2b's staging, not revisited here).

## Architecture (mirrors slice 1's pure-core / real-adapter split)

The whole monitor is host-testable by injecting two small ports; only thin real-IO conformers + one emulator
smoke test land in `:kit`.

```
:vault-access (pure Kotlin/JVM, Android-free, host-tested)   package org.secretary.sync
  MonotonicInstant.kt          instant value type (no wall-clock in the core)
  ChangeDetectionTuning.kt     named Duration constants (debounce window, self-write mute window)
  FolderChangeDetector.kt      pure reducer: pulses → debounced, gated, muted → pendingChanges
  FolderWatchPort.kt           interface: start(onPulse) / stop()
  FlushScheduler.kt            interface: schedule(after: Duration, (MonotonicInstant)->Unit) / cancel()
  ChangeDetectionMonitor.kt    coordinates port + detector + scheduler; exposes pendingChanges + onChange

:vault-access/src/test (JUnit 5)
  FakeFolderWatch.kt           test drives raw pulses (emit(at:)), tracks start/stop, injectable startError
  ManualFlushScheduler.kt      test controls flush fire time + instant (fire(at:)), tracks scheduledDelay

:kit (real adapters — thin, Android)                         package org.secretary.sync
  MonotonicClock.kt            monotonicNow() = MonotonicInstant(SystemClock.elapsedRealtimeNanos())
  FileObserverFolderWatch.kt   android.os.FileObserver → FolderWatchPort (root-only, non-recursive)
  HandlerFlushScheduler.kt     main-Looper Handler.postDelayed → FlushScheduler
  ChangeMonitorFactory.kt      makeChangeMonitor(folder:File, ...) tiny composition factory

:kit/src/androidTest (JUnit 4, emulator)
  FolderWatchInstrumentedTest.kt   real FileObserver on a temp dir → debounced pendingChanges
```

### `MonotonicInstant` + `ChangeDetectionTuning`

- `MonotonicInstant`: a `@JvmInline value class MonotonicInstant(val nanos: Long) : Comparable<MonotonicInstant>`
  with `advancedBy(Duration): MonotonicInstant` and `durationTo(later: MonotonicInstant): Duration`. The pure
  core never touches wall-clock; the real conformer sources it from `SystemClock.elapsedRealtimeNanos()`
  (Android-specific, lives in `:kit`). Host tests supply instants directly → deterministic. Only ordering and
  differences are meaningful — never interpreted as wall-clock.
- `ChangeDetectionTuning`: named `kotlin.time.Duration` constants (no magic numbers), `defaultDebounceWindow`
  = **2000 ms**, `defaultSelfWriteMuteWindow` = **10000 ms**, injectable into the detector for tests.

### `FolderChangeDetector` (pure reducer — the heart)

Idiomatic Kotlin class with mutable private state (in place of Swift's `mutating struct`). Deterministic
transitions, no real timers/clock. Trailing-debounce semantics ("emit once the folder has been quiet for
`debounceWindow` after the last pulse"):

- **`recordPulse(at: MonotonicInstant)`** — the watcher saw a change. If active and not muted, sets
  `lastPulseAt` and (implicitly via `nextFlushDeadline`) requests a flush at `lastPulseAt + window`. A burst
  within the window coalesces to one signal. **Does not guard on `!pendingChanges`** — a pulse arriving while
  the signal is still pending preserves the latest instant so `acknowledge()` can re-arm it.
- **`flush(now: MonotonicInstant): Boolean`** — if `now ≥ lastPulseAt + window`, active, and not muted →
  `pendingChanges = true`, clear the deadline, return `true` (the false→true transition). Otherwise no-op,
  return `false` (the monitor re-arms to the current deadline).
- **`setActive(active: Boolean)`** — foreground/unlocked gate (ADR-0003 foreground-only). Pulses while inactive
  are dropped; transitioning to inactive **resets** detection state (clears `pendingChanges`, deadline, and any
  pending pulse) for a clean slate on next foreground.
- **`muteUntil(instant: MonotonicInstant)`** — optional self-write suppression. Pulses stamped strictly before
  the mute instant are ignored (mitigates our own record writes tripping the observer).
- **`acknowledge()`** — caller consumed the signal → `pendingChanges = false`; if a pulse was preserved during
  the pending window, it re-arms so the monitor flushes again.
- Exposes `val isActive: Boolean`, `val pendingChanges: Boolean`, and the computed
  `val nextFlushDeadline: MonotonicInstant?` (what the monitor arms to: non-null only when active, a pulse has
  been seen, and not already pending).

### `ChangeDetectionMonitor` (pure glue, host-tested with the two fakes)

Owns the detector + an injected `FolderWatchPort` + `FlushScheduler` + an `onChange: () -> Unit` callback.
Main-thread-confined (mirrors iOS `@MainActor`): the real conformers marshal their callbacks onto the main
thread before touching the monitor, so the monitor itself needs **no locks** (matches the pure-core,
single-threaded model). Flow:

1. OS pulse (on the main thread) → `detector.recordPulse(at:)` → if a deadline is now pending, (re)schedule
   the flush to that deadline (cancel + schedule — trailing debounce).
2. Scheduler fires with the fire instant → `detector.flush(now:)` → if it flips false→true, invoke `onChange`
   and update the published `pendingChanges`; otherwise re-arm (a later pulse moved the deadline).
3. `start()` sets active + starts the watch port; if `watch.start` throws, it **rolls back the active gate**
   so a retry starts clean. Double-start is idempotent (guarded on `detector.isActive`). `stop()` cancels the
   scheduler, stops the port, sets inactive (which resets the signal). `acknowledge()` forwards to the detector
   and, if a pulse was preserved, re-arms the scheduler with a **`Duration.ZERO`** delay so the scheduler
   issues its own fire instant (the monitor stays clock-free). `muteUntil(instant)` forwards to the detector.

Because both ports are injected, the burst/coalesce/cancel/ack behavior is host-tested deterministically.

### Real conformers (`:kit`, thin)

- **`MonotonicClock.kt`** — `fun monotonicNow(): MonotonicInstant = MonotonicInstant(SystemClock.elapsedRealtimeNanos())`.
  The only Android-specific time source; keeps `MonotonicInstant` itself pure in `:vault-access`.
- **`FileObserverFolderWatch`** — registers a single `android.os.FileObserver` on the vault **root**,
  **non-recursively**. `FileObserver` is non-recursive on *all* API levels (even API 29's `FileObserver(File,
  mask)` watches only the directory's immediate contents, not subdirectories — the standard recursive
  workaround is one observer per subdir, which we deliberately avoid). Root-only watching is **correct and
  sufficient** because the top-level `manifest.cbor.enc` is re-signed and rewritten via atomic rename on every
  committed state advance (vault-format §4.4), surfacing as a `MOVED_TO` / `CREATE` event on the root
  directory. A remote device's change always lands a new top-level manifest, so it always pulses. A deep-only
  change with no manifest touch is not a committed (sync-relevant) state.
  - **API 29+:** `FileObserver(folder: File, mask)` — the non-deprecated constructor (still non-recursive).
  - **API 26–28:** `FileObserver(path: String, mask)` — the legacy constructor (deprecated on 29+; identical
    non-recursive behavior). The API split is **deprecation hygiene only**, not a coverage difference.
  - Mask: creation / modification / move-in/out / delete events (`CREATE | MODIFY | MOVED_TO | MOVED_FROM | DELETE | CLOSE_WRITE`).
  - `FileObserver.onEvent` fires on the observer's own thread; the conformer stamps `monotonicNow()` and
    **posts to a main-`Looper` `Handler`** before invoking `onPulse`, so the monitor is only ever touched on
    the main thread (matches iOS delivering on `@MainActor`).
  - `start` can throw (folder unreadable) → surfaced to the caller; no silent swallow.
- **`HandlerFlushScheduler`** — a `Handler` on the main `Looper`; `schedule` does `postDelayed` with a single
  outstanding token (a new schedule cancels the prior — trailing debounce); `cancel` removes it. Fires the work
  with `monotonicNow()` (the fire instant). Mirrors iOS `DispatchFlushScheduler`.
- **`makeChangeMonitor(folder: File, debounceWindow: Duration = ..., onChange: () -> Unit)`** — composes the
  above with a fresh `FolderChangeDetector` into a ready-to-start monitor.

## Data flow

```
FileObserver.onEvent (observer thread) ──► post to main Handler ──► FileObserverFolderWatch.onPulse(now)
   ──► ChangeDetectionMonitor ──► FolderChangeDetector.recordPulse(at: now)
        └─ deadline? ──► HandlerFlushScheduler.schedule(after: deadline-now) ──┐
                                                                                ▼
   (quiet for window) ──► scheduler fires(now') ──► detector.flush(now: now')
        └─ pendingChanges false→true ──► monitor.onChange() + published pendingChanges = true
```

## Error handling

- `FileObserverFolderWatch.start` can fail (folder unreadable) → throws; the monitor surfaces it to the caller
  (slice 4 decides UX). No silent swallow.
- The signal is **advisory**: a missed or spurious pulse never corrupts anything — sync (slice 4) reconciles
  the actual truth. Documented known limitations:
  - **Self-write false positives**: our record writes (Rust atomic rename, not file-coordinated) can trip the
    observer. The `muteUntil` hook lets the app suppress a window around a local write (slice 4 wiring);
    residual false positives are benign (badge → user syncs → `NothingToDo`).
  - **Backgrounded full-sync**: a change that fully downloads while backgrounded won't pulse on next
    foreground. Slice 4's sync-at-unlock / "Sync now" covers the cold-start case.
  - **Deep-only changes (all APIs)**: because watching is root-only/non-recursive, a change confined to a
    subdirectory with no top-level manifest rewrite would not pulse. Such a change is, by definition, not a
    committed (sync-relevant) state (vault-format §4.4), so root-only misses nothing that matters.

## Background-execution decision (documented, not built)

Detection is **foreground-only**: the `FileObserver` lives only while the monitor is active (app
foregrounded / unlocked). This mirrors iOS slice 2 and honors **ADR-0003** (mobile sync is realistically
foreground-only). **WorkManager background polling is explicitly deferred, not built**, because:

- Doze / App Standby batch and defer `WorkManager` jobs — a background poll cannot give timely detection and
  burns battery for little benefit.
- Cloud `DocumentsProvider`s rarely emit reliable change notifications, and SAF `content://` tree URIs are not
  readable by the path-based Rust FFI (which consumes filesystem path strings — see slice 2b). The realistic
  model is a local filesystem folder that a cloud client syncs, observed while foreground.

When a future product need justifies background detection, the natural seam is a second `FolderWatchPort`
conformer (a WorkManager-driven periodic poll comparing directory listings/mtimes), wired behind the same
interface with no change to the pure core. Noted, not in this slice.

## Testing (TDD)

**Detector (host, pure, JUnit 5):** single pulse → pending after window; burst within window → exactly one
pending after quiet; quiet < window → not yet pending; out-of-order pulses; muted pulse ignored; inactive
drops pulses; going inactive resets pending + deadline + preserved pulse; acknowledge clears then a later
pulse re-arms; acknowledge re-arms a pulse preserved during the pending window.
**Monitor (host, fakes, JUnit 5):** pulse → scheduler fires → `onChange` once + `pendingChanges` true; burst →
single `onChange`; `stop()` cancels scheduler + stops watch; `acknowledge()` resets; `start` error → active
gate rolled back, clean retry; double-start idempotent; acknowledge re-arms a preserved pulse.
**MonotonicInstant (host):** ordering, `advancedBy`, `durationTo`.
**`:kit` (emulator, JUnit 4):** one real-`FileObserver` smoke test — observer + scheduler wired through a
monitor on a temp dir, a file write fires a pulse, `pendingChanges` becomes true after the window
(`CountDownLatch` + timeout, pumping the main `Looper`). No golden vault / FFI / native `.so` needed — pure
filesystem, so **no new native build wiring** this slice.

## Security / hygiene

No secrets touched. The detector sees only timestamps and a folder path; the signal is **pure metadata**
(never record contents). Foreground-only gating honors ADR-0003. Pure additive slice — no Rust / FFI / on-disk
format / crypto / CRDT change; `:vault-access`/`:kit` existing main sources, `core/`, `ffi/`, and `ios/` are
untouched.

## Out of scope / deferred

- `runPass` invocation and the password-availability policy → slice 4.
- Android `ViewModel` / `StateFlow` / sync badge / conflict-resolution sheet → slice 4.
- `SyncMonitorHook` self-write-mute adapter → slice 4 (when a writer exists; slice 4 can call the monitor's
  public `muteUntil` / `acknowledge` directly, so no separate hook is needed this slice).
- WorkManager background polling → deferred (see "Background-execution decision").
- `armv7` / `x86_64` cross-builds → unchanged from slice 2b (arm64-v8a only); irrelevant here (no native code).
