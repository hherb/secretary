# NEXT_SESSION.md — C.3 Android slice 2a: real `UniffiVaultSyncPort` adapter ✅

**Session date:** 2026-06-15. Flow: `/nextsession` → confirmed C.3 Android slice 1 (#237, `8cb6da4`) was squash-merged to `main` + removed its stale worktree/branch → chose **Android slice 2a** (the real uniffi adapter) → brainstormed (3 decisions: scope-split 2a/2b, cargo-ndk via Gradle exec task, bindings generated at build time) → spec → 6-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; all review items fixed in-task; final whole-branch review found 1 Important issue, fixed + re-verified) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-android-sync-adapter`. PR: see §4. This slice delivers the **real `VaultSyncPort` implementation for Android** — the pure slice-1 Kotlin core wired to the Rust FFI through a new `:kit` Android-library module: uniffi Kotlin bindings generated at build time, the `secretary-ffi-uniffi` cdylib cross-built for **arm64-v8a** via cargo-ndk into `jniLibs`, the `UniffiVaultSyncPort` adapter, and the pure DTO→domain + `VaultException`→`VaultSyncError` mappers. **Host-tested + build-verified, NO emulator** (the on-device round-trip is slice 2b). `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** Android consumes the *same* frozen Rust sync logic iOS does, through the *same* uniffi surface (#187). Slice 1 built the pure Kotlin *shape* behind a `VaultSyncPort` seam + host-tested it with a fake. Slice 2a now provides the *real* implementation of that seam — the only module that imports the generated `uniffi.secretary` bindings — a faithful Kotlin mirror of iOS's `UniffiVaultSyncPort.swift` + `VaultSyncErrorMapping.swift`. The DTO→domain mapping is pure and **host-testable on the JVM** (instantiating uniffi DTOs does not load the `.so`; only *calling* an FFI fn does), so the mapping logic gets full 1:1 coverage with zero emulator.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | design doc + 6-task TDD plan | `bf5070b` `2bd0f77` |
| **Task 1 — `:kit` scaffold + FFI build wiring** | new `com.android.library` `:kit` module (AGP 8.13.2, NDK 29 pinned), `generateUniffiKotlinBindings` + `buildHostCdylib` + `cargoNdkBuildArm64` Gradle tasks, depends on `:vault-access` | `c3e2573` `e836d62` `c0fead8` |
| **Task 2 — SyncOutcomeMapping** | pure `mapOutcome`/`mapStatus`/`mapVeto`/`mapCollision` (DTO→domain, 1:1, `when` exhaustive no-`else`) | `f6c1e62` `a1c242f` |
| **Task 3 — VaultSyncErrorMapping** | pure `mapVaultSyncError` (8 sync arms + `WrongPasswordOrCorrupt` conflation §13 + `else→Failed` fold) | `c516488` `ee7c4bd` |
| **Task 4 — UniffiVaultSyncPort** | the adapter: injectable FFI seams (default = real bindings) + dispatcher; `sync`/`commit` offload to `Dispatchers.IO`, `status` inline; password per-call, never stored | `e930056` `552128c` |
| **Task 5 — docs** | README row + ROADMAP slice-2a ✅/2b ⏳ entries + `android/README.md` module list | `a3864a3` |
| **Final-review fix** | keep arm64 cross-build off the host unit-test path (hook JNI-merge, not `preBuild`) | `1f09245` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `8cb6da4`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live — all package `org.secretary.sync`)
- `android/kit/` — new `com.android.library` module. `:kit` depends on `:vault-access` (the pure core owns the `VaultSyncPort` interface + domain types). `:kit` is the **only** module that invokes the generated `uniffi.secretary` bindings (the pure mappers reference the generated types as translators).
  - `UniffiVaultSyncPort.kt` — the adapter. Three FFI fns are constructor **seams** defaulting to `::syncStatus`/`::syncVault`/`::syncCommitDecisions`; `CoroutineDispatcher` seam defaults to `Dispatchers.IO`. Production uses all defaults (no native lib at construction); tests inject fakes + a `StandardTestDispatcher` to host-verify wiring with no `.so`.
  - `SyncOutcomeMapping.kt` — pure DTO→domain mappers; arms 1:1 to `SyncOutcomeDto`; exhaustive `when`, no `else` (a new DTO arm breaks compilation — intended tripwire).
  - `VaultSyncErrorMapping.kt` — pure `VaultException`→`VaultSyncError`; maps the 8 sync-relevant arms, folds all others to `Failed(e.toString())`. Carries a maintainer warning that the `else` fold silently swallows any *future* sync-relevant arm — the Swift/Kotlin conformance harnesses are the cross-language guard, not the compiler.
- `android/kit/build.gradle.kts` — `generateUniffiKotlinBindings` (depends on tracked `buildHostCdylib`, generates into `build/generated/uniffi/`, wired before `compileKotlin`); `cargoNdkBuildArm64` (`cargo ndk -t arm64-v8a -o src/main/jniLibs ...`, hooked to `*JniLibFolders` merge tasks — **off** the unit-test path). NDK path derived from `ANDROID_SDK_ROOT`/`ANDROID_HOME` (macOS fallback); single `ndkVer` const.
- `android/kit/src/test/kotlin/org/secretary/sync/` — 3 test files (12 host tests).

### Acceptance (green — full gauntlet this session)
```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks   → BUILD SUCCESSFUL, 22 + 12 tests, 0 failures, 0 compiler warnings
cd android && ./gradlew :kit:assembleRelease                                       → AAR contains jni/arm64-v8a/libsecretary_ffi_uniffi.so (2.5 MB)
cd android && ./gradlew :kit:testDebugUnitTest --dry-run                            → does NOT list cargoNdkBuildArm64 (host tests are NDK-free)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'           → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'         → empty
```

## (2) What's next — slice 2b, then the rest of Android C.3

- **Android slice 2b — emulator instrumented round-trip.** Exercise the `:kit` `UniffiVaultSyncPort` (and the `SyncCoordinator` over it) against the golden vault on the **arm64 emulator** (`Medium_Phone_API_36.1`). **Acceptance:** an instrumented `androidTest` that (a) stages a temp copy of `core/tests/data/golden_vault_001/` onto the device/emulator (per [[feedback_smoke_test_temp_copy_golden_vault]] — never mutate the tracked fixture), (b) loads the real `.so` from `jniLibs`, (c) round-trips `status()` then a `sync()` pass and asserts a real `SyncOutcome` (e.g. `NothingToDo`/`AppliedAutomatically`), proving the native load + uniffi marshalling + mapping all work end-to-end on device. **Toolchain is ready** ([[project_secretary_android_toolchain]]): emulator + AVD installed, NDK 29, cargo-ndk 3.5.4 now installed; only gotcha is `adb`/`emulator` aren't on the bare PATH (use `$ANDROID_HOME/platform-tools/adb`). Note the arm64 `.so` already packs into the AAR, so the wiring is proven to the packaging boundary — 2b is about the on-device exec + golden-vault staging, not new build infra.
- **Android slice 3 — folder-change detection** (Storage Access Framework + `WorkManager`), the pure `FolderChangeDetector`/monitor seams mirroring iOS slice 2, then the SAF/WorkManager adapter.
- **Android slice 4 — Compose sync UI** (badge, sync-at-unlock, conflict-resolution sheet) mirroring iOS slice 3 — where `SyncBadgeState`, the `ViewModel`/`StateFlow`, and the `WallClock` seam land. **UI-slice caveat (carry forward from slice 1):** `SyncCoordinator` shares one `Mutex` across all four methods (held across the suspending port call), so a `status()`/`pendingConflict()` read parks behind an in-flight `sync()` (which now runs the *real* Argon2id re-open via `UniffiVaultSyncPort` — can take seconds). The UI must not drive a status/badge refresh off the same coordinator while a pass is running; read status before/after a pass, or surface "syncing…" from the in-flight pass itself.

**Other open directions (carried):** C.4 KeepLocal-veto clean-room rung (needs veto semantics promoted into `docs/` first); N-device convergence topologies; durability/partition/clock-skew scenarios; iOS biometric re-auth before write; Rust-core backlog #193/#192/#190/#189.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session.)

## (3) Open decisions and risks

- **Build-time binding generation couples `:kit` Kotlin compilation to cargo** (chosen over vendoring the generated `secretary.kt`). `generateUniffiKotlinBindings` builds a tracked host cdylib (`buildHostCdylib`, declared `outputs.file`) then runs `uniffi-bindgen`; Gradle up-to-date keys on the `.udl`/crate sources, so it only reruns on protocol change. Acceptable — the repo is a Rust workspace, cargo is always present. The host-test path needs cargo (for the host cdylib + bindings) but **NOT** the NDK/cargo-ndk/arm64 target — that decoupling is the final-review fix (`1f09245`), enforced by `cargoNdkBuildArm64` being hooked to `*JniLibFolders` merge tasks, not `preBuild`. **Do not re-hook it to `preBuild`** — that silently drags the NDK onto `:kit:testDebugUnitTest`.
- **Only `arm64-v8a` is cross-built.** Sufficient for the Apple-Silicon emulator + modern devices; `armv7`/`x86_64` are deferred (add `-t armeabi-v7a -t x86_64` to `cargoNdkBuildArm64` + install the targets when a real device matrix needs them).
- **The adapter's injectable FFI seams are a testability device, not API.** Defaults are the real bindings; production constructs `UniffiVaultSyncPort()`. They exist so the offload/error-catch/decision-mapping wiring is host-testable without the `.so`. The real native round-trip is genuinely unverified until slice 2b — that's the explicit scope boundary.
- **`mapVaultSyncError`'s `else` fold can silently swallow a future *sync-relevant* `VaultException` arm** (the compiler won't flag a non-exhaustive `when` over a ~30-arm sealed type). The KDoc says so; the cross-language conformance harnesses ([[project_secretary_ffivaulterror_workspace_match]]) are the guard. If the sync FFI surface gains an arm, add an explicit branch.
- **No production-code change to anything pre-existing.** Purely additive new module + adapter; `:vault-access`, `core/`, `ffi/`, `ios/`, and the on-disk format are untouched.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/c3-android-sync-adapter

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-sync-adapter && git branch -D feature/c3-android-sync-adapter
git worktree prune && git worktree list

# 3) Next direction (Android slice 2b = emulator round-trip): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks    # 22 + 12 tests, 0 failures
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && \
  ./gradlew :kit:assembleRelease && \
  unzip -l kit/build/outputs/aar/kit-release.aar | grep arm64-v8a       # the .so is packed
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter && \
  git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `8cb6da4` == current `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `8cb6da4`; `feature/c3-android-sync-adapter` carries spec + plan + `:kit` scaffold + 2 build fixups + SyncOutcomeMapping + VaultSyncErrorMapping + UniffiVaultSyncPort + polish + docs + the final-review fix + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — 22 (`:vault-access`) + 12 (`:kit`) host tests, 0 compiler warnings; AAR packs the arm64 `.so`; host tests NDK-free; guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + two-stage spec/quality review per task; all per-task review items fixed in-task; final whole-branch review found 1 Important issue — the NDK/host-test coupling — fixed in `1f09245` and re-verified). Reviews caught + fixed real items each task: build-cache/untracked-cdylib + hardcoded-NDK-path (T1), ConflictsPending content-equals coverage (T2), silent-swallow KDoc + general-fold coverage (T3), KDoc accuracy + test-stub clarity (T4), and the host-test/NDK decoupling (final).
- **README.md / ROADMAP.md:** updated — Android C.3 real adapter ✅ (slice 2b emulator round-trip + UI pending).
- **NEXT_SESSION.md:** symlink retargeted to this file.
