# NEXT_SESSION.md — C.3 Android slice 3: folder-change detection ✅

**Session date:** 2026-06-16. Flow: `/nextsession` → confirmed C.3 Android slice 2b (#239, `2c7b9aa`) squash-merged to `main` + removed its stale worktree/branch → chose **Android slice 3** (folder-change detection) → brainstormed (3 decisions: FileObserver push, host+instrumented tests, root-only watch) → **caught + corrected a factual error mid-brainstorm** (FileObserver is non-recursive on ALL API levels — the "API 29 is recursive" premise was wrong; re-asked the user, landed on root-only) → spec → 7-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; all review items fixed in-task) → final whole-slice review → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-android-folder-watch`. PR: see §4 (⚠️ **push/PR were blocked by a GitHub connectivity outage at session end — the branch is ready locally and needs `git push` + `gh pr create` when the network returns**; commands in §4). This slice delivers the **Android mirror of iOS slice 2** — an advisory, detect-only, debounced, foreground-gated "remote changes detected" signal for an open vault's folder. `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** a faithful Kotlin mirror of the iOS folder-change-detection feature. The signal never runs a sync pass (`sync_vault` needs the password = full Argon2id, which the app drops after unlock) — it just raises `pendingChanges`; acting on it is slice 4 (Compose UI). Pure host-tested debounce core in `:vault-access`; real `FileObserver`/`Handler` adapters in `:kit`; one emulator smoke.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + recursion correction + plan** | design doc, the non-recursive correction, 7-task TDD plan | `cece48b` `f0678bf` `ea7e70a` |
| **Task 1 — value types** | `MonotonicInstant` (`@JvmInline value class`) + `ChangeDetectionTuning` | `90871f4` `ed2dc19` |
| **Task 2 — reducer** | `FolderChangeDetector` (pure trailing-debounce) + 10 tests | `4a23ea1` `1c19930` |
| **Task 3 — ports + doubles** | `FolderWatchPort`/`FlushScheduler` + `FakeFolderWatch`/`ManualFlushScheduler` + 6 tests | `1d82cc8` `4dda65a` |
| **Task 4 — monitor** | `ChangeDetectionMonitor` (composes detector + ports) + 7 tests | `aa55429` `75a2a70` |
| **Task 5 — real adapters** | `MonotonicClock`, `HandlerFlushScheduler`, `FileObserverFolderWatch` (root-only), `ChangeMonitorFactory` | `3571294` `c997b57` |
| **Task 6 — emulator smoke** | `FolderWatchInstrumentedTest` — real FileObserver→Handler→onChange on `Medium_Phone_API_36.1` | `9975607` `6540a5c` |
| **Task 7 — docs** | README + ROADMAP slice-3 ✅ (+ corrected the stale "SAF + WorkManager" framing) | `2127868` |
| **Final-review polish** | sub-ms-truncation comment | `a047e4f` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `2c7b9aa`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### 🔑 Headline finding — `android.os.FileObserver` is NON-recursive on ALL API levels

The brainstorm originally framed a recursion question around the premise that API 29's `FileObserver(File, mask)` constructor watches subdirectories recursively. **It does not** — `FileObserver` is non-recursive at every API level (the standard workaround is a hand-rolled per-subdir `RecursiveFileObserver`). This was verified against the Android docs mid-brainstorm and the user was re-asked. The resolution: **watch only the vault root, non-recursively.** That is *correct and sufficient* because the top-level `manifest.cbor.enc` is re-signed and rewritten via atomic rename on every committed state advance (vault-format §4.4), so a remote change always surfaces as a root-level `MOVED_TO`/`CREATE`/`CLOSE_WRITE` event (all in the watched MASK). A deep-only change with no manifest rewrite is not a committed (sync-relevant) state. The API 29 vs 26-28 constructor split is **deprecation hygiene only**, not a coverage difference. (Lesson: the `f0678bf` commit captures the correction; don't "restore" recursive watching.)

### Architecture (where the pieces live — all package `org.secretary.sync`)
- **`:vault-access` (pure Kotlin/JVM, Android-free, host-tested JUnit 5):**
  - `MonotonicInstant.kt` — `@JvmInline value class` wrapping `Long` nanos (`advancedBy`/`durationTo`/`Comparable`); clock-free core.
  - `ChangeDetectionTuning.kt` — named `Duration` constants (debounce 2s, self-write mute 10s).
  - `FolderChangeDetector.kt` — the pure trailing-debounce reducer (pulse → quiet window → `pendingChanges`; foreground gate; self-write mute; acknowledge re-arms a pulse preserved during the pending window).
  - `FolderWatchPort.kt` / `FlushScheduler.kt` — the two injected seam interfaces.
  - `ChangeDetectionMonitor.kt` — composes detector + watch + scheduler + `onChange`; main-thread-confined (no locks); start-failure rolls back the active gate.
  - test doubles `FakeFolderWatch`/`ManualFlushScheduler` in `src/test`.
- **`:kit` (real Android adapters):**
  - `MonotonicClock.kt` — `monotonicNow()` = `SystemClock.elapsedRealtimeNanos()`.
  - `HandlerFlushScheduler.kt` — `FlushScheduler` over a main-`Looper` `Handler` (single outstanding runnable).
  - `FileObserverFolderWatch.kt` — `FolderWatchPort` over ONE non-recursive `FileObserver` on the vault root; events stamped on the observer thread then posted to the main `Handler` before `onPulse` (so the monitor is only touched on main). API 29+ `FileObserver(File, mask)` / 26-28 `FileObserver(String, mask)` (`@Suppress("DEPRECATION")` scoped to the legacy branch).
  - `ChangeMonitorFactory.kt` — `makeChangeMonitor(folder, …)` with a `check(Looper.myLooper() == mainLooper)` fast-fail.
  - `FolderWatchInstrumentedTest.kt` (androidTest) — real temp-dir write → FileObserver → debounced `pendingChanges`.

### Acceptance (green — full gauntlet this session)
```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks   → BUILD SUCCESSFUL, host suites green, 0 warnings (host path NDK-free)
cd android && ./gradlew :kit:connectedDebugAndroidTest                            → BUILD SUCCESSFUL, 3 instrumented tests pass on Medium_Phone_API_36.1 (2 slice-2b + 1 new folder-watch)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           → empty
```

⚠️ **Gradle gotcha (carry forward, still true):** `connectedDebugAndroidTest` does NOT accept `--tests`. To run a single instrumented class: `./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.sync.FolderWatchInstrumentedTest`.

## (2) What's next — slice 4

- **Android slice 4 — Compose sync UI** (badge, sync-at-unlock, conflict-resolution sheet), mirroring iOS slice 3 (#233). This is where `SyncBadgeState`, the `ViewModel`/`StateFlow`, and a `WallClock` seam land, and where the folder-watch signal from this slice finally gets consumed. **Acceptance:** host-tested `ViewModel` + badge-state derivation over `pendingChanges` + `SyncStatus`; sync-at-unlock + on-demand re-prompt; metadata-only conflict-resolution sheet (per-record Keep mine / Accept delete, default Keep mine) mirroring desktop D.1.15; the self-write-mute wiring (slice 4 calls the monitor's public `muteUntil`/`acknowledge` directly — no separate hook was built this slice, deliberately). The monitor's `onChange` lambda is the integration seam: slice 4 passes a lambda that pokes its ViewModel.
  - **UI-slice caveat (carried from slice 1):** `SyncCoordinator` holds one `Mutex` across all four methods (held across the suspending port call = real Argon2id re-open), so a `status()`/`pendingConflict()` read parks behind an in-flight `runPass()`. The UI must not drive a status/badge refresh off the same coordinator while a pass is running; read status before/after a pass, or surface "syncing…" from the in-flight pass.
- **Optional WorkManager background detection (deferred this slice):** the design documents foreground-only per ADR-0003; a background poll would be a second `FolderWatchPort` conformer (WorkManager periodic poll comparing dir listings/mtimes) behind the same seam, with no change to the pure core. Doze defers WorkManager and SAF `content://` URIs aren't readable by the path-based FFI, so this was deliberately not built.
- **On-device veto round-trip (later, carried):** the golden vault is single-device → only `AppliedAutomatically`/`NothingToDo`, never `ConflictsPending`. Exercising `commitDecisions` on-device needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).

**Other open directions (carried):** C.4 KeepLocal-veto clean-room rung (needs veto semantics promoted into `docs/` first); N-device convergence topologies; durability/partition/clock-skew scenarios; iOS biometric re-auth before write; Rust-core backlog #193/#192/#190/#189.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session.)

## (3) Open decisions and risks

- **FileObserver is non-recursive → root-only watch (§1 headline).** Not a risk — a verified fact, now pinned in the design doc + `FileObserverFolderWatch` KDoc. Flagged so a future reader doesn't "fix" it back to recursive / per-subdir watching.
- **Foreground-only detection.** Per ADR-0003. WorkManager background polling is documented-deferred (see §2). If a product need arises, add it as a second port conformer, not a change to the pure core.
- **Instrumented test is the only on-device coverage and is NOT in host/`cargo` CI** (needs an emulator). Expected + matches the project model — the real FileObserver→Handler seam is proven when someone runs `connectedDebugAndroidTest`. Flagged so it isn't mistaken for host-covered.
- **No production-code change to anything pre-existing.** Purely additive `:vault-access`/`:kit` sources + one androidTest; `core/`, `ffi/`, `ios/`, and the on-disk format are untouched (both guardrail greps empty).
- **`armv7`/`x86_64` still not cross-built** (arm64-v8a only) — irrelevant here (no native code in this slice; the smoke is pure filesystem).

## (4) Exact commands to resume

```bash
# 0) ⚠️ FIRST — push the branch + open the PR (blocked by a network outage at session end):
cd /Users/hherb/src/secretary/.worktrees/c3-android-folder-watch
git push -u origin feature/c3-android-folder-watch
gh pr create --base main --head feature/c3-android-folder-watch \
  --title "C.3 Android slice 3: folder-change detection — detect-only FileObserver signal" \
  --body "Android mirror of iOS slice 2 (#230). Pure host-tested debounce core (FolderChangeDetector + ports + ChangeDetectionMonitor) in :vault-access; real root-only FileObserver + main-Looper Handler adapters in :kit; one emulator smoke. Detect-only, foreground-only (ADR-0003); WorkManager background deferred. Additive only — no core/ffi/ios/format change."

# 1) After review, squash-merge, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-folder-watch && git branch -D feature/c3-android-folder-watch
git worktree prune && git worktree list

# 2) Next direction (Android slice 4 = Compose sync UI): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch (emulator must be booted):
#   emulator/adb are NOT on the bare PATH — use absolute paths:
"$HOME/Library/Android/sdk/emulator/emulator" -avd Medium_Phone_API_36.1 -no-snapshot -no-window -no-audio &
"$HOME/Library/Android/sdk/platform-tools/adb" wait-for-device
cd /Users/hherb/src/secretary/.worktrees/c3-android-folder-watch/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks    # host suites green
cd /Users/hherb/src/secretary/.worktrees/c3-android-folder-watch/android && \
  ./gradlew :kit:connectedDebugAndroidTest                              # 3 instrumented tests pass
cd /Users/hherb/src/secretary/.worktrees/c3-android-folder-watch && \
  git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `2c7b9aa` == current `origin/main` as of the last successful fetch), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `2c7b9aa`; `feature/c3-android-folder-watch` carries spec + recursion correction + plan + 6 core/adapter files + 6 test files + 1 instrumented test + docs + this handoff/symlink. **Not yet pushed (network outage).** Squash-merge → one commit on `main`.
- **Acceptance:** green — `:vault-access` + `:kit` host suites, 0 warnings; 3 instrumented tests pass on `Medium_Phone_API_36.1`; host path NDK-free; both guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + two-stage spec/quality review per task; all per-task review items fixed in-task; plus a final whole-slice opus review). The reviews caught + fixed real items each task: test-file split + neutral param name (T1), mute-reset coverage gap (T2), scheduler doc + stop/emit-after-stop coverage (T3), muteUntil-forwarding coverage gap (T4), main-thread fast-fail + post-stop-delivery doc (T5), clearer assertion message (T6), sub-ms-truncation note (final review). One mid-brainstorm factual correction (FileObserver non-recursive) re-surfaced to the user before planning.
- **README.md / ROADMAP.md:** updated — Android C.3 folder-change detection ✅ (slice 4 Compose UI pending); corrected the stale "SAF + WorkManager" framing to the shipped FileObserver-foreground-only reality.
- **NEXT_SESSION.md:** symlink retargeted to this file.
