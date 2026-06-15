# NEXT_SESSION.md — C.3 Android slice 2b: emulator sync round-trip ✅

**Session date:** 2026-06-16. Flow: `/nextsession` → confirmed C.3 Android slice 2a (#238, `d20cc35`) was squash-merged to `main` + removed its stale worktree/branch → chose **Android slice 2b** (the emulator instrumented round-trip) → brainstormed (2 decisions: Gradle Copy task for fixture staging, drive port + coordinator both) → spec → 5-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; all review items fixed in-task) → docs + this handoff.

**Status:** ✅ **code-complete + all-green ON A REAL EMULATOR** on branch `feature/c3-android-sync-emulator`. PR: see §4. This slice delivers the **first on-device exercise of the native sync surface anywhere in the repo** — instrumented `androidTest`s that load the real cross-built `libsecretary_ffi_uniffi.so`, marshal across uniffi, and map a real `SyncOutcome`, round-tripping `golden_vault_001` through both the raw `UniffiVaultSyncPort` and the `SyncCoordinator` over it on the arm64 emulator `Medium_Phone_API_36.1`. `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** slice 2a built the *real* `UniffiVaultSyncPort` adapter and host-tested its offload/error-catch/mapping wiring with fakes — but the native round-trip (real `.so` load + uniffi marshalling + real `SyncOutcome`) was the explicit unverified scope boundary. Slice 2b closes it on a real Android runtime. Note: iOS proves the *open* path on the simulator (`VaultAccessIntegrationTests`) but its sync path is only host-tested with fakes — so this is **net-new** end-to-end coverage, not a mirror of an existing iOS test.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design doc + 5-task TDD plan | `5969db2` `69f4332` |
| **Task 1 — build wiring** | `stageGoldenVaultForAndroidTest` Copy task (fixture from `core/tests/data`, gitignored target) hooked to `mergeDebugAndroidTestAssets`; androidTest deps + `AndroidJUnitRunner`; `android.useAndroidX=true` (required by the AndroidX test deps) | `95bcce7` |
| **Task 2 — `GoldenVaultStaging` + raw-port test** | recursive asset→`cacheDir` copy + pinned-UUID parse; the `status→sync→status` round-trip through `UniffiVaultSyncPort` | `03c0c6f` |
| **Task 3 — coordinator test** | `SyncCoordinator` over the real port (assembled slice-1 + slice-2a stack on device) | `4b41ccf` |
| **Task 4 — gauntlet + docs** | full acceptance green; README + ROADMAP slice-2b ✅ | `9f6b4f9` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `d20cc35`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### 🔑 Headline finding — first-pass outcome arm is `AppliedAutomatically`, NOT `NothingToDo`

The plan hypothesized the single-device first pass over an empty state dir would return `SyncOutcome.NothingToDo` (from `core/src/sync/once.rs:87` `ClockRelation::Equal → NothingToDo`). **On-device it returns `AppliedAutomatically`** — with no prior persisted clock, the first sync establishes the current vault state as the baseline (an *advancing* arm that **writes** sync state), rather than treating a clean device as quiescent. This was characterized empirically per spec §4 (run → observe → pin), not assumed. Both instrumented tests assert `AppliedAutomatically`, and the raw-port test additionally asserts `status().hasState` flips `false → true` across the pass (consistent with an advancing arm persisting state). This is a real behavioral fact worth knowing for anyone reasoning about idempotent re-sync or expecting a fresh device to be a no-op.

### Architecture (where the pieces live — all package `org.secretary.sync`)
- `android/kit/src/androidTest/kotlin/org/secretary/sync/`
  - `GoldenVaultStaging.kt` — test helper: `stageWritableVault` (recursive `AssetManager`→fresh `cacheDir` copy — never opens the tracked fixture, per [[feedback_smoke_test_temp_copy_golden_vault]]), `freshStateDir`, `goldenVaultUuid` (parses `vault_uuid` from the bundled inputs JSON — single source of truth). Loud `IllegalStateException` if the fixture wasn't bundled (names the staging task). The `AssetManager.list()` "empty children == leaf file" heuristic is documented as exact-for-this-fixture (no empty dirs).
  - `SyncRoundTripInstrumentedTest.kt` — JUnit4 (`@RunWith(AndroidJUnit4::class)`), two tests using `runBlocking` (real dispatchers + real Argon2id, not virtual time): `rawPort_statusThenSync_roundTripsThroughNativeFfi` and `coordinator_overRealPort_runsAPassOnDevice`. Per-test unique temp dirs; `@After deleteRecursively()`.
- `android/kit/build.gradle.kts` — `stageGoldenVaultForAndroidTest` (`Copy`, gitignored dest) → `mergeDebugAndroidTestAssets`. The arm64 `.so` already reaches the androidTest APK via the **pre-existing** `cargoNdkBuildArm64` → `*JniLibFolders` hook (covers `mergeDebugAndroidTestJniLibFolders`) — **no new native-build wiring this slice.**
- `android/gradle.properties` — `android.useAndroidX=true` (new; the host-only slice 2a never pulled an AndroidX dep, so this gap was invisible until the androidTest deps landed). No Jetifier (no legacy support libs).
- `android/.gitignore` — `kit/src/androidTest/assets/` (staged fixture, never committed).

### Acceptance (green — full gauntlet this session)
```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks   → BUILD SUCCESSFUL, 22 + 14 host tests, 0 failures, 0 warnings (host path NDK-free)
cd android && ./gradlew :kit:connectedDebugAndroidTest                            → BUILD SUCCESSFUL, 2 instrumented tests pass on Medium_Phone_API_36.1
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           → empty
```

⚠️ **Gradle gotcha (carry forward):** `connectedDebugAndroidTest` does **NOT** accept `--tests` (that's a JVM-unit-test filter; it errors "Unknown command-line option '--tests'"). To run a single instrumented class use:
`./gradlew :kit:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.sync.SyncRoundTripInstrumentedTest`. (The plan's Task 2/3 Step-4 `--tests` form is wrong — the implementer corrected it on the fly.)

## (2) What's next — slice 3, then slice 4

- **Android slice 3 — folder-change detection** (Storage Access Framework + `WorkManager`): the pure `FolderChangeDetector`/monitor seams mirroring iOS slice 2, then the SAF/`WorkManager` adapter. **Acceptance:** pure detector host-tested with a fake clock/source; the SAF adapter exercised behind its seam; a documented decision on background-execution constraints (Doze/`WorkManager` backoff). No emulator strictly required for the pure core; the adapter may want an instrumented smoke like 2b.
- **Android slice 4 — Compose sync UI** (badge, sync-at-unlock, conflict-resolution sheet) mirroring iOS slice 3 — where `SyncBadgeState`, the `ViewModel`/`StateFlow`, and the `WallClock` seam land. **UI-slice caveat (carried from slice 1):** `SyncCoordinator` shares one `Mutex` across all four methods (held across the suspending port call), so a `status()`/`pendingConflict()` read parks behind an in-flight `runPass()` (now the *real* Argon2id re-open via `UniffiVaultSyncPort` — can take seconds). The UI must not drive a status/badge refresh off the same coordinator while a pass is running; read status before/after a pass, or surface "syncing…" from the in-flight pass itself.
- **On-device veto round-trip (later):** the golden vault is single-device → it can only produce `AppliedAutomatically`/`NothingToDo`, never `ConflictsPending`. Exercising `commitDecisions` on-device needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).

**Other open directions (carried):** C.4 KeepLocal-veto clean-room rung (needs veto semantics promoted into `docs/` first); N-device convergence topologies; durability/partition/clock-skew scenarios; iOS biometric re-auth before write; Rust-core backlog #193/#192/#190/#189.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session.)

## (3) Open decisions and risks

- **First-pass arm is `AppliedAutomatically` (§1 headline).** Not a risk — a characterized fact, now pinned in both tests. Flagged so a future reader doesn't "fix" the tests back to `NothingToDo`.
- **`armv7`/`x86_64` still not cross-built** (arm64-v8a only). Sufficient for the Apple-Silicon emulator + modern devices. Add `-t armeabi-v7a -t x86_64` to `cargoNdkBuildArm64` + install the targets when a real device matrix needs them.
- **Fixture staging couples the androidTest APK build to `core/tests/data`.** The `Copy` task tracks `from`/`into` (so Gradle skips when unchanged); the dest is gitignored (no committed duplicate of a frozen KAT — mirrors iOS's `build-xcframework.sh`). If the golden vault is ever regenerated, the staged copy refreshes automatically.
- **`AssetManager.list()` empty-dir heuristic** ("empty children == leaf file") is exact only because `golden_vault_001` has no empty directories (verified + documented in-code). A future fixture with an empty dir would mis-stage it — revisit the helper then.
- **No production-code change to anything pre-existing.** Purely additive androidTest + build wiring; `:kit`/`:vault-access` main sources, `core/`, `ffi/`, `ios/`, and the on-disk format are untouched.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/c3-android-sync-emulator

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-sync-emulator && git branch -D feature/c3-android-sync-emulator
git worktree prune && git worktree list

# 3) Next direction (Android slice 3 = SAF/WorkManager folder-change detection): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch (emulator must be booted):
#   emulator/adb are NOT on the bare PATH — use absolute paths:
"$HOME/Library/Android/sdk/emulator/emulator" -avd Medium_Phone_API_36.1 -no-snapshot -no-window -no-audio &
"$HOME/Library/Android/sdk/platform-tools/adb" wait-for-device
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-emulator/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks    # 22 + 14 host tests, 0 failures
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-emulator/android && \
  ./gradlew :kit:connectedDebugAndroidTest                              # 2 instrumented tests pass
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-emulator && \
  git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `d20cc35` == current `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `d20cc35`; `feature/c3-android-sync-emulator` carries spec + plan + build wiring + 2 instrumented tests + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — 22 (`:vault-access`) + 14 (`:kit`) host tests, 0 warnings; 2 instrumented tests pass on `Medium_Phone_API_36.1`; host path NDK-free; guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + two-stage spec/quality review per task; all per-task review items fixed in-task). One sanctioned plan deviation (the `AppliedAutomatically` characterization) + one authorized scope add (`android.useAndroidX=true`, required by the AndroidX test deps). Reviews caught + fixed real items each task: inputs/outputs comment accuracy (T1), empty-dir heuristic doc + loud missing-asset message (T2), class-KDoc accuracy (T3).
- **README.md / ROADMAP.md:** updated — Android C.3 emulator round-trip ✅ (slice 3 folder-watch + slice 4 Compose UI pending).
- **NEXT_SESSION.md:** symlink retargeted to this file.
