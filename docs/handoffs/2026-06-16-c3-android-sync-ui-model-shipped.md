# NEXT_SESSION.md — C.3 Android slice 4: host-tested sync-UI model ✅

**Session date:** 2026-06-16. Flow: `/nextsession` → confirmed C.3 Android slice 3 (#241, `08a1acf`) was squash-merged to `main` after the prior session's network outage cleared → removed the stale `feature/c3-android-folder-watch` worktree/branch → chose **Android slice 4** (sync-UI model) → brainstormed (3 decisions: host-tested-model-only scope, `SyncMonitorHook` seam, model lives in `:vault-access`) → spec → 7-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; all review items fixed in-task) → final whole-slice opus review (Ready to merge) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-android-sync-ui-model` (worktree `.worktrees/c3-android-sync-ui-model`). PR: see §4 (push/PR is the first resume step). This slice delivers the **Android mirror of iOS slice 3's testable heart** — badge-state derivation, the `VaultSyncModel` state machine, the `WallClock`/`SyncMonitorHook` seams, decision helpers, and the real `:kit` wiring — **minus Compose rendering** (deferred to slice 5). `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** the consumer of slice 3's folder-watch signal. A pure, host-tested presentation-state machine turns `pendingChanges` + a `SyncStatus` snapshot + the result of a sync pass into a 5-state badge, and drives two triggers (silent sync-at-unlock + interactive re-prompt) that converge on one resolution path. No Compose, no app module, no `androidx.lifecycle` — `VaultSyncModel` is a plain class exposing `StateFlow` (coroutines only), fully JUnit-5 host-testable. Slice 5 wraps it in a `ViewModel` and renders it.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | design doc, 7-task TDD plan | `c54b7f4` `e042579` |
| **Task 1 — badge** | `SyncBadgeState` (5-state sealed interface) + pure `syncBadgeState(...)` precedence fn + 6 tests | `5b52533` |
| **Task 2 — seams** | `WallClock` / `SyncMonitorHook` interfaces + `FakeWallClock` / `FakeSyncMonitorHook` + 2 tests | `db9dd29` |
| **Task 3 — decisions** | `collectDecisions` / `decisionsComplete` (per-record default "Keep mine") + 4 tests | `993e66a` |
| **Task 4 — model** | `VaultSyncModel` two-trigger/one-resolution state machine + 12 tests | `d3f3f22` |
| **Task 4 — review fix** | assert mute on interactive/resolve passes + resolve acknowledge | `280db43` |
| **Task 5 — :kit reals** | `SystemWallClock`, `MonitorSyncHook` (wraps `ChangeDetectionMonitor`) + 3 tests | `261bd68` |
| **Task 6 — factory** | `makeVaultSync` composition (lateinit cycle-break, main-thread fast-fail) | `c7bd630` |
| **Task 6 — review fix** | document `makeVaultSync` `vaultUuid` nullability | `9bed668` |
| **Task 7 — docs** | README + ROADMAP slice-4 ✅ (+ corrected the stale "slice 4 = Compose UI" forward-ref to "slice 5 = render over the slice-4 model") | `1a233a0` |
| **Final-review polish** | KDoc note: badge label refresh is slice-5-driven | `05558f8` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `08a1acf`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live — all package `org.secretary.sync`)
- **`:vault-access` (pure Kotlin/JVM, Android-free, host-tested JUnit 5):**
  - `SyncBadgeState.kt` — sealed interface (`NeverSynced` / `Synced(sinceMs)` / `ChangesDetected` / `ReviewNeeded` / `Syncing`) + pure `syncBadgeState(inProgress, pendingChanges, reviewNeeded, status?)`. Precedence: syncing → review → changes → synced → never. The single `reviewNeeded` input collapses both review paths (model supplies `reviewNeededFlag || pendingConflict != null`).
  - `WallClock.kt` / `SyncMonitorHook.kt` — the two injected seams (clock for `nowMs`; outbound `muteSelfWrite`/`acknowledge`).
  - `SyncDecisions.kt` — `collectDecisions` (default `keepLocal = true`, one-per-veto in order) / `decisionsComplete`.
  - `VaultSyncModel.kt` — the heart. StateFlows: `badge`, `isSyncing`, `reviewNeeded`, `pendingConflict`, `lastError` (all read-only via `asStateFlow`). Methods: `syncAtUnlock` (silent; conflict → reviewNeeded only, password dropped), `runInteractivePass` (conflict → surface `pendingConflict`), `resolve` (clean → clear+acknowledge; EvidenceStale/DecisionsIncomplete → keep conflict + set lastError), `cancelConflict` (close sheet, keep review badge), `pendingChangesRaised` (monitor onChange seam), `refreshStatus` (best-effort, null-uuid no-op). `guardedPass` wrapper mutes before every pass, catches only `VaultSyncError` into `lastError`, acknowledges only on clean arms. Password never stored.
  - test doubles `FakeWallClock` / `FakeSyncMonitorHook` in `src/test`.
- **`:kit` (real Android adapters):**
  - `SystemWallClock.kt` — `nowMs()` = `System.currentTimeMillis().toULong()`.
  - `MonitorSyncHook.kt` — wraps `ChangeDetectionMonitor`: `muteSelfWrite()` → `muteUntil(now().advancedBy(defaultSelfWriteMuteWindow))`; `acknowledge()` → `acknowledge()`. `now` injected (defaults to `monotonicNow`) so it's host-testable.
  - `VaultSyncFactory.kt` — `makeVaultSync(folder, stateDir, vaultUuid, wallClock=SystemWallClock())`: builds `SyncCoordinator` over `UniffiVaultSyncPort`, wires `monitor.onChange → model.pendingChangesRaised()` via a `lateinit var` (JVM GC reclaims the cycle — no weak-ref needed, unlike iOS ARC), main-thread fast-fail. Returns `(model, monitor)`.

### Acceptance (green — full gauntlet this session)
```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks   → BUILD SUCCESSFUL, 90 tests, 0 failures, 0 warnings (host path NDK-free)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **`beginInteractiveSync()` omitted.** The spec sketched it as "expose intent, no work yet" — but a no-op method is a placeholder and the model holds no sheet-presentation state. The badge-tap → password-prompt trigger is slice-5 UI state; slice 5 collects the password and calls `runInteractivePass(password)` directly.
- **No auto-`refreshStatus()` after a clean pass** (the one place Android deliberately differs from iOS, which refreshes inside the pass). On Android the "synced N ago" label refresh is a slice-5 UI concern — driven via `refreshStatus()` read before/after a pass, never during — to avoid re-parking behind the just-released coordinator mutex. Documented in `VaultSyncModel` KDoc.
- **Model lives in `:vault-access`** (not a new `:sync-ui` module) — the designated pure-JVM host-tested home; extract later only if it grows.

## (2) What's next — slice 5

- **Android slice 5 — Compose sync render** (the actual UI over the slice-4 model). **Acceptance:** a new Compose app module (or Compose-enabled surface) + `androidx.lifecycle.ViewModel` wrapper exposing the `VaultSyncModel` StateFlows; `@Composable` sync badge (rendering all 5 `SyncBadgeState`s incl. the "synced N min ago" relative-time label computed at render from `Synced.sinceMs` + a wall clock), a password sheet (badge-tap → `runInteractivePass`), and a **metadata-only conflict-resolution sheet** mirroring desktop D.1.15 (per-record Keep mine / Accept delete, default Keep mine, read-only auto-merged-collision disclosure, stays-open-on-error). Wire `makeVaultSync` into the app's unlock/lock lifecycle (`monitor.start()` on unlock + `syncAtUnlock(password)`; `monitor.stop()` on lock/background). A Compose UI-test harness is the first on Android. This is also where the slice-4 model's `refreshStatus()` gets driven (before/after a pass) for the "synced" label.
  - **Integration seam:** `makeVaultSync(folder, stateDir, vaultUuid)` returns `(VaultSyncModel, ChangeDetectionMonitor)`; the ViewModel observes the model's StateFlows and calls its suspend methods from the UI dispatcher.
  - **UI-slice caveat (carried from slice 1):** `SyncCoordinator` holds one `Mutex` across all four methods (held across the suspending port call = real Argon2id re-open), so a `status()`/`pendingConflict()` read parks behind an in-flight `runPass()`. The UI must not drive a status/badge refresh off the same coordinator while a pass is running; read status before/after a pass, or surface "syncing…" from the in-flight pass.
- **On-device veto round-trip (later, carried):** the golden vault is single-device → only `AppliedAutomatically`/`NothingToDo`, never `ConflictsPending`. Exercising `resolve`/`commitDecisions` on-device needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).
- **Optional WorkManager background detection (deferred since slice 3):** foreground-only per ADR-0003; a background poll would be a second `FolderWatchPort` conformer behind the same seam, no change to the pure core.

**Other open directions (carried):** C.4 KeepLocal-veto clean-room rung; N-device convergence topologies; durability/partition/clock-skew scenarios; iOS biometric re-auth before write; Rust-core backlog #193/#192/#190/#189.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session.)

## (3) Open decisions and risks
- **No on-device/instrumented coverage of the model wiring this slice** (no Compose app/emulator surface exists until slice 5). Expected + matches the project model — the model + adapters are fully host-tested; the real `makeVaultSync` composition is pure wiring over already-tested units. Flagged so it isn't mistaken for on-device-proven.
- **`makeVaultSync` has no host test** (needs Android `Looper` + the native `.so`). Deliberate — it composes already-tested units; the final review confirmed there is no cheap testable seam being missed. An instrumented smoke is a slice-5 option.
- **No production-code change to anything pre-existing.** Purely additive `:vault-access`/`:kit` sources; `core/`, `ffi/`, `ios/`, and the on-disk format are untouched (both guardrail greps empty).
- **`armv7`/`x86_64` still not cross-built** (arm64-v8a only) — irrelevant here (no native code in this slice; the model is pure filesystem-free logic).

## (4) Exact commands to resume

```bash
# 0) FIRST — push the branch + open the PR:
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-ui-model
git push -u origin feature/c3-android-sync-ui-model
gh pr create --base main --head feature/c3-android-sync-ui-model \
  --title "C.3 Android slice 4: host-tested sync-UI model — VaultSyncModel + seams + :kit wiring" \
  --body "Android mirror of iOS slice 3's testable heart (#233), minus Compose rendering (slice 5). Pure host-tested :vault-access model (SyncBadgeState + syncBadgeState, VaultSyncModel two-trigger/one-resolution state machine, WallClock/SyncMonitorHook seams, collectDecisions/decisionsComplete) + real :kit wiring (SystemWallClock, MonitorSyncHook, makeVaultSync). 90 host tests green; additive only — no core/ffi/ios/format change."

# 1) After review, squash-merge, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-sync-ui-model && git branch -D feature/c3-android-sync-ui-model
git worktree prune && git worktree list

# 2) Next direction (Android slice 5 = Compose sync render): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch (host-only, no emulator needed):
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-ui-model/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks    # 90 tests green, 0 warnings
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-ui-model && \
  git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `08a1acf` == current `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory
- **Branch on close:** `main` @ `08a1acf`; `feature/c3-android-sync-ui-model` carries spec + plan + 6 source files (`:vault-access`) + 3 source files (`:kit`) + 7 test files + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — `:vault-access` + `:kit` host suites, 90 tests, 0 warnings; host path NDK-free; both guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + two-stage spec/quality review per task; all per-task review items fixed in-task; plus a final whole-slice opus review = Ready to merge). Reviews caught + fixed real items: muteCount/acknowledge coverage gaps on the interactive/resolve paths (T4), `vaultUuid` nullability KDoc (T6), badge-refresh-is-slice-5-driven KDoc (final review).
- **README.md / ROADMAP.md:** updated — Android C.3 sync-UI model ✅ (slice 5 Compose render pending); corrected the stale "slice 4 = Compose UI" forward-reference.
- **NEXT_SESSION.md:** symlink retargeted to this file.
