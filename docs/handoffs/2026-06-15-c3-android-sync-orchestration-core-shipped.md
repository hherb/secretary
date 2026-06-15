# NEXT_SESSION.md — C.3 Android sync orchestration core (slice 1) ✅

**Session date:** 2026-06-15. Flow: `/nextsession` → confirmed C.4 Python convergence mirror (#236, `87a66e2`) was squash-merged to `main` + removed its stale worktree/branch → chose **C.3 Android** (the remaining C.3 platform) → brainstormed (scope = slice-1 pure core only; build tool = introduce Gradle) → spec → 6-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; all review items fixed in-task; final whole-branch review = **READY TO MERGE**) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-android-sync-core`. PR: see §4. This slice delivers the **pure, host-testable Kotlin sync orchestration core** for Android — a faithful mirror of iOS slice 1 (#228) — plus the repo's **first Gradle project**. 22 host tests on JUnit5 + coroutines-test, **no emulator/NDK, no FFI, no UI, no folder-watch**. `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** Android consumes the *same* frozen Rust sync logic that iOS does, through the *same* uniffi surface (#187). So this slice builds only the pure Kotlin *shape* those calls adapt into — isolated behind a `VaultSyncPort` seam — and host-tests the two-call inspect→commit orchestration with a fake, before the real FFI adapter lands. Identical architecture to iOS's `SecretaryVaultAccess` pure core.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design doc + 6-task TDD plan | `b46497f` `c6d00c7` |
| **Task 1 — Gradle scaffold** | `android/` Gradle root + `:vault-access` `kotlin("jvm")` module + wrapper (8.14.3, sha256-pinned) + `jvmToolchain(21)` | `cc4ef7c` `b8848a3` |
| **Task 2 — SyncModels** | metadata-only value types + sealed `SyncOutcome` (`ConflictsPending` carries `ByteArray` w/ content-based equals/hashCode/toString) | `908f4a0` `0535aa8` |
| **Task 3 — VaultSyncError** | sealed `: Exception` hierarchy (9 arms), separate from vault-access, `WrongPasswordOrCorrupt` conflated (§13) | `603a9c6` `dd06bd0` `8bef95e` |
| **Task 4 — VaultSyncPort + fake** | the seam interface (3 suspend methods) + scriptable `FakeVaultSyncPort` (src/test) | `590b6a7` `2676612` |
| **Task 5 — SyncCoordinator** | `Mutex`-guarded two-call round-trip; stash-preserve-on-throw retry contract; serialization test | `a081d59` `3a9548c` |
| **Task 6 — docs** | README row + ROADMAP slice-1 entry + status captions | `dc48223` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `87a66e2`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live — all package `org.secretary.sync`)
- `android/` — the repo's first Gradle project. `settings.gradle.kts` includes only `:vault-access`. Later slices add `:kit` (Android lib, real uniffi adapter + `jniLibs`) and `:app` (Compose).
- `android/vault-access/src/main/kotlin/org/secretary/sync/`
  - `SyncModels.kt` — `DeviceClock`/`SyncStatus`/`SyncVeto`/`SyncCollision`/`SyncVetoDecision`/`PendingConflict` + sealed `SyncOutcome` (arms map **1:1** to uniffi `SyncOutcomeDto`; verified against `ffi/secretary-ffi-uniffi/src/secretary.udl`).
  - `VaultSyncError.kt` — sealed hierarchy; detail arms (`StateCorrupt`/`InvalidArgument`/`Failed`) carry detail as `.message`; `NoPendingConflict` is the coordinator-only guard (no FFI origin).
  - `VaultSyncPort.kt` — the seam the future `UniffiVaultSyncPort` implements; `status`/`sync`/`commitDecisions`, all `suspend`; password per-call, never retained.
  - `SyncCoordinator.kt` — the orchestration; see §3.
- `android/vault-access/src/test/kotlin/org/secretary/sync/` — `FakeVaultSyncPort.kt` + 4 test files (22 tests).

### Acceptance (green — full gauntlet this session)
```
cd android && ./gradlew :vault-access:test --rerun-tasks      → BUILD SUCCESSFUL, 22 tests, 0 failures, 0 warnings
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'           → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'         → empty
```
The `mutexSerializesConcurrentRunPasses` test (gated `CompletableDeferred` port under `StandardTestDispatcher`) ran deterministically across 4 repeats — it genuinely distinguishes mutex-held-across-call from a release-before-await design.

## (2) What's next — the rest of the Android C.3 adapter

Slice 1 stopped at the pure core (matching how iOS sliced #228 → #230 → #233). The remaining Android C.3 rungs, in dependency order:

- **Android slice 2 — the real `UniffiVaultSyncPort` adapter.** Wire `VaultSyncPort` over the generated `uniffi.secretary` Kotlin bindings (`syncStatus`/`syncVault`/`syncCommitDecisions`) + the native `.so` in `src/main/jniLibs/<abi>/`. **Acceptance:** an Android library module `:kit` (Android Gradle Plugin) that builds the NDK `.so`, a `UniffiVaultSyncPort` mapping `SyncOutcomeDto`→`SyncOutcome` and `VaultException`→`VaultSyncError` (separate from a vault-access mapping, §13), offloading `sync`/`commitDecisions` to `Dispatchers.IO` (Argon2id); instrumented (emulator) test that the coordinator round-trips against the golden vault. **Toolchain is ready** — this machine has a fully working Android setup (Android Studio, `adb`, `emulator` + AVD `Medium_Phone_API_36.1`, NDK 29.0.14206865, build-tools 34–36.1, platforms 35/36; the user ships real Android apps); the only gotcha is that `adb`/`emulator` aren't on the bare login-shell `PATH` (use `$ANDROID_HOME/platform-tools/adb` etc.). So slice 2 is about adding the AGP module + NDK cross-build + `jniLibs` wiring, NOT standing up infra. This is the natural next session.
- **Android slice 3 — folder-change detection** (Storage Access Framework + `WorkManager`), the pure `FolderChangeDetector`/monitor seams mirroring iOS slice 2, then the SAF/WorkManager adapter.
- **Android slice 4 — Compose sync UI** (badge, sync-at-unlock, conflict-resolution sheet) mirroring iOS slice 3 — this is where `SyncBadgeState`, the `ViewModel`/`StateFlow`, and the `WallClock` seam land (all deliberately deferred from slice 1, exactly as iOS deferred them to #233). **UI-slice caveat (carry forward):** `SyncCoordinator` shares one `Mutex` across *all four* methods (held across the suspending port call), so a `status()`/`pendingConflict()` read parks behind an in-flight `sync()` — which runs the full Argon2id re-open and can take seconds. This is intentional (documented in the `SyncCoordinator` KDoc + decision below), but the UI must not drive a status poll/badge refresh off the *same* coordinator while a pass is running, or the badge will hang for the pass duration. Read status before/after a pass, or surface "syncing…" from the in-flight pass itself rather than re-reading `status()`.

**Other open directions (carried from #236's handoff):** C.4 KeepLocal-veto clean-room rung (needs veto semantics promoted into `docs/` first); N-device convergence topologies; durability/partition/clock-skew scenarios; iOS biometric re-auth before write; Rust-core backlog #193/#192/#190/#189.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session.)

## (3) Open decisions and risks

- **Gradle is now in the repo (a deliberate, approved decision).** The existing `ffi/secretary-ffi-uniffi/tests/kotlin/` conformance harness stays raw-`kotlinc` (it's a test harness, not an app platform). Android genuinely needs Gradle for the NDK build/Compose/instrumented tests, so it was introduced correctly now. Pins: Gradle **8.14.3** (wrapper, `distributionSha256Sum` set), Kotlin **2.2.10**, coroutines **1.8.0**, JUnit BOM **5.10.2**, `jvmToolchain(21)`. All chosen for `~/.gradle` cache availability (offline-capable) and network is also available.
- **The `Mutex`-across-the-call divergence from iOS's reentrant `actor` is intentional** (documented in `SyncCoordinator` KDoc + spec §4.4). Kotlin holds a non-reentrant `Mutex` across the suspending port call → *stronger* (non-interleaving) serialization than the Swift actor; cannot deadlock (public methods never call one another); the per-vault FFI lockfile (`InProgress`) remains the cross-process guard. The `mutexSerializesConcurrentRunPasses` test guards this against a future "optimize by releasing the lock around the call" regression — **do not delete it**.
- **Retry contract is structural, not bookkept:** `applyStash` runs only on a *returned* outcome, so a thrown port error (`EvidenceStale`/`DecisionsIncomplete`) bypasses it and preserves the stash for retry. If you refactor `runPass`/`resolve`, preserve "exactly one statement between the port return and `applyStash`, and nothing on the throw path."
- **`SyncOutcome`/error arms are pinned 1:1 to the uniffi DTOs** so slice 2's adapter is a straight transcription. If the uniffi sync surface changes, update both the Kotlin arms AND (later) the mapping — don't let them drift.
- **No production-code change to anything pre-existing.** Purely additive new platform scaffold + pure core.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/c3-android-sync-core

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-sync-core && git branch -D feature/c3-android-sync-core
git worktree prune && git worktree list

# 3) Next direction (Android slice 2 = real UniffiVaultSyncPort adapter): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core/android && ./gradlew :vault-access:test --rerun-tasks   # 22 tests, 0 failures
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-core && \
  git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `87a66e2` == current `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `87a66e2`; `feature/c3-android-sync-core` carries spec + plan + Gradle scaffold + SyncModels + VaultSyncError + VaultSyncPort/fake + SyncCoordinator + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — 22 host tests, 0 warnings; guardrails clean (no core/ffi/ios/format change). See §1.
- **Process note:** subagent-driven (fresh implementer + two-stage spec/quality review per task; final whole-branch review on Opus = **READY TO MERGE**, no Critical/Important issues). Reviews caught + fixed real items each task — JVM-toolchain + distribution-sha256 pins (T1), `ConflictsPending` edge-case tests (T2), always-true-warning cleanup + full-object-arm coverage + shared-stacktrace KDoc (T3), fake seeding/`ByteArray` caveats (T4), the stash-clear-on-second-pass + **mutex-serialization** tests + read-blocking KDoc (T5).
- **README.md / ROADMAP.md:** updated — Android C.3 orchestration core ✅ (adapter/UI pending).
- **NEXT_SESSION.md:** symlink retargeted to this file.
