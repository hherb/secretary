# C.3 iOS slice 2 — folder-change detection (detect-only) — design

**Date:** 2026-06-15
**Sub-project:** C.3 (mobile sync adapters), iOS, slice 2 of 3
**Builds on:** slice 1 (sync orchestration core, #228 — `SyncCoordinator` / `VaultSyncPort` / `SyncModels`)
**Status:** approved (brainstorm) — pending implementation plan

## Purpose

Give the iOS app a **debounced, foreground-gated "remote changes detected" signal** for an open vault's
folder, so a later UI slice can show a sync badge / "Sync now" affordance. Per ADR-0003 mobile sync is
realistically **foreground-only** (no background file watchers). This slice ships the host-tested detection
core plus the real platform watcher; it does **not** run a sync pass or build UI.

## The central constraint (why "detect-only")

`sync_vault` / `sync_commit_decisions` re-open the identity from the **password** (full Argon2id cost). The
app deliberately **drops the password after unlock** (secret hygiene — see slice 1 + `SecretaryApp`'s
lock-on-background). Therefore a file-change event **cannot silently run a sync pass** — there is no password
in hand once the user is browsing.

So a detected change does not call `SyncCoordinator.runPass`. It sets an **advisory, metadata-only signal**
(`pendingChanges`). Acting on that signal — re-prompting for the password or running sync-at-unlock — is
slice 3's concern, alongside the conflict-resolution UI. The password-availability policy is therefore
**deferred to slice 3** where there is a UI to handle it.

## Scope

**In:** a pure host-tested change-detection core (`SecretaryVaultAccess`) + the real `NSFilePresenter`-based
watcher (`SecretaryKit`). **Out:** any `runPass` call; app/UI wiring or a visible badge (slice 3); the
`state_dir` / app-group container path decision (not exercised until sync actually runs — still deferred).

## Architecture (mirrors slice 1's pure-core / real-adapter split)

The whole monitor is host-testable by injecting two small ports; only thin real-IO conformers + one sim
smoke test land in `SecretaryKit`.

```
SecretaryVaultAccess (pure, FFI-free)
  MonotonicInstant.swift        instant value type (no wall-clock in the core) + DebounceWindow constant
  FolderChangeDetector.swift    pure reducer: pulses → debounced, gated, muted → pendingChanges
  FolderWatchPort.swift         protocol: start(onPulse:) / stop()
  FlushScheduler.swift          protocol: schedule(after:Duration, (MonotonicInstant)->Void) / cancel()
  ChangeDetectionMonitor.swift  coordinates port + detector + scheduler; exposes pendingChanges + onChange

SecretaryVaultAccessTesting
  FakeFolderWatch.swift          test drives raw pulses
  ManualFlushScheduler.swift     test controls flush fire time + instant

SecretaryKit (real adapters — thin)
  PresenterFolderWatch.swift     NSFilePresenter → FolderWatchPort (stamps instants from DispatchTime)
  DispatchFlushScheduler.swift   DispatchSourceTimer → FlushScheduler
  makeChangeMonitor(folder:)     tiny composition factory
```

### `MonotonicInstant` + `DebounceWindow`

- `MonotonicInstant`: a `Comparable`, `Sendable` value wrapping a monotonic time (e.g. nanoseconds), with
  `+ Duration` / difference. The pure core never touches wall-clock (`Date()`); the real conformers source
  it from `DispatchTime.now()`. Host tests supply instants directly → deterministic.
- `DebounceWindow`: a named constant (no magic numbers), default **2000 ms**, injectable into the detector
  for tests.

### `FolderChangeDetector` (pure reducer — the heart)

Deterministic transitions, no real timers/clock. Trailing-debounce semantics ("emit once the folder has been
quiet for `DebounceWindow` after the last pulse"):

- **`recordPulse(at:)`** — the watcher saw a change. If active and not muted, sets `lastPulseAt` and requests
  a flush at `lastPulseAt + window`. A burst within the window coalesces to one signal.
- **`flush(now:)`** — if `now ≥ lastPulseAt + window`, active, and not muted → `pendingChanges = true`,
  clear the deadline. Otherwise no-op (the monitor re-arms to the current deadline).
- **`setActive(_:)`** — foreground/unlocked gate (ADR-0003 foreground-only). Pulses while inactive are
  dropped; transitioning to inactive **resets** detection state (clears `pendingChanges` + deadline) for a
  clean slate on next foreground.
- **`muteUntil(_:)`** — optional self-write suppression. Pulses stamped strictly before the mute instant are
  ignored (mitigates our own record writes tripping the presenter).
- **`acknowledge()`** — caller consumed the signal → `pendingChanges = false`; a later pulse re-arms.
- Exposes `pendingChanges: Bool` and `nextFlushDeadline: MonotonicInstant?` (what the monitor arms to).

### `ChangeDetectionMonitor` (pure glue, host-tested with the two fakes)

Owns the detector + an injected `FolderWatchPort` + `FlushScheduler`. Flow:

1. OS pulse → `detector.recordPulse(at:)` → if a deadline is now pending, (re)schedule the flush to that
   deadline (cancel + schedule — trailing debounce).
2. Scheduler fires with the fire instant → `detector.flush(now:)` → if `pendingChanges` flips false→true,
   invoke `onChange` and update the published state.
3. `start()` starts the watch port + sets active; `stop()` cancels the scheduler, stops the port, sets
   inactive. `acknowledge()` forwards to the detector.

Because both ports are injected, the burst/coalesce/cancel/ack behavior is host-tested deterministically.

### Real conformers (`SecretaryKit`, thin)

- **`PresenterFolderWatch`** — registers an `NSFilePresenter` on the vault folder; `presentedSubitemDidChange`
  / `presentedItemDidChange` → `onPulse(instant)` (instant derived from `DispatchTime.now()`). NSFilePresenter
  is the most general fit for the security-scoped, possibly-iCloud folders the app already opens via bookmarks.
  *(Future: `NSMetadataQuery` for iCloud-download-specific detection — noted, not in this slice.)*
- **`DispatchFlushScheduler`** — a `DispatchSourceTimer` for the debounce delay, passing the fire instant.
- **`makeChangeMonitor(folder:)`** — composes the above with a `FolderChangeDetector` into a ready monitor.

## Data flow

```
NSFilePresenter callback ──► PresenterFolderWatch.onPulse(now)
   ──► ChangeDetectionMonitor ──► FolderChangeDetector.recordPulse(at: now)
        └─ deadline? ──► DispatchFlushScheduler.schedule(after: deadline-now) ──┐
                                                                                 ▼
   (quiet for window) ──► scheduler fires(now') ──► detector.flush(now: now')
        └─ pendingChanges false→true ──► monitor.onChange() + published pendingChanges = true
```

## Error handling

- `PresenterFolderWatch.start` can fail (folder unreadable / scope lost) → throws; the monitor surfaces it to
  the caller (slice 3 decides UX). No silent swallow.
- The signal is **advisory**: a missed or spurious pulse never corrupts anything — sync (slice 3) reconciles
  the actual truth. Documented known limitations:
  - **Self-write false positives**: our record writes (Rust atomic rename, not Swift file-coordinated) can
    trip the presenter. The `muteUntil` hook lets the app suppress a window around a local write; residual
    false positives are benign (badge → user syncs → `nothingToDo`).
  - **Backgrounded full-sync**: a change that fully downloads while backgrounded won't pulse on next
    foreground. Slice 3's sync-at-unlock / "Sync now" covers the cold-start case.

## Testing (TDD)

**Detector (host, pure):** single pulse → pending after window; burst within window → exactly one pending
after quiet; quiet < window → not yet pending; muted pulse ignored; inactive drops pulses; going inactive
resets pending + deadline; acknowledge clears then a later pulse re-arms.
**Monitor (host, fakes):** pulse → scheduler fires → `onChange` once + `pendingChanges` true; burst → single
`onChange`; `stop()` cancels scheduler + stops watch; `acknowledge()` resets.
**SecretaryKit (sim):** one real-`NSFilePresenter` smoke test — presenter on a tempdir, a coordinated write
fires a pulse, `pendingChanges` becomes true after the window (`XCTestExpectation` + timeout).

## Security / hygiene

No secrets touched. The detector sees only timestamps and a folder path; the signal is **pure metadata**
(never record contents). Foreground-only gating honors ADR-0003. Pure Swift slice — no Rust / FFI / on-disk
format / crypto / CRDT change.

## Out of scope / deferred

- `runPass` invocation and the password-availability policy → slice 3.
- App/UI wiring, sync badge, conflict-resolution modal → slice 3.
- `state_dir` / app-group container path decision → slice 3 (first slice that actually runs sync).
- `NSMetadataQuery` iCloud-download-specific detection → future enhancement.
