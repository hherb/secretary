# C.3 (Android) — Sync emulator round-trip (slice 2b)

**Date:** 2026-06-16
**Milestone:** C.3 (mobile sync adapters), Android portion, slice 2b of N
**Status:** design — approved approach, pending spec review
**Scope:** Android only. New instrumented (`androidTest`) coverage + the build wiring to
stage the golden vault into the test APK. No production-code change to `:kit`/`:vault-access`,
no `core/`/`ffi/`/`ios/` change, no on-disk format change, no Compose UI.

## 1. Purpose

Slice 2a built the **real** `UniffiVaultSyncPort` (`:kit`) and host-tested its offload/error-catch/
mapping wiring with fakes — but the native round-trip (load the cross-built `.so`, marshal across
uniffi, map a real `SyncOutcome`) was the explicit unverified scope boundary. Slice 2b closes it:
drive the golden vault through the real adapter **and** the `SyncCoordinator` over it on the
**arm64 emulator**, proving native-load + uniffi marshalling + DTO/error mapping all work
end-to-end on a real Android runtime.

Project note: this is the **first** on-device exercise of the native *sync* surface anywhere in the
repo. iOS proves the *open* path on the simulator (`VaultAccessIntegrationTests`) but its sync path
is only host-tested with fakes (`UniffiVaultSyncPortOffMainActorTests`). 2b is therefore net-new
end-to-end coverage, not a mirror of an existing iOS test.

## 2. Non-goals

- No new native-build infra. The arm64 `.so` already reaches a library `androidTest` APK via the
  existing `cargoNdkBuildArm64` → `*JniLibFolders` hook (`mergeDebugAndroidTestJniLibFolders` ends
  in `JniLibFolders`, so it is already covered). 2b only stages the *fixture* and adds the tests.
- No production-code change to `UniffiVaultSyncPort`, the mappers, or `:vault-access`.
- No conflict/veto round-trip (`commitDecisions`) — the golden vault is single-device with no peer
  evidence, so it cannot produce a `ConflictsPending`. Veto on-device coverage is a later slice
  (it needs a seeded concurrent state, per [[project_secretary_sync_veto_needs_seeded_state]]).
- No `armv7`/`x86_64` cross-build (arm64-v8a only, sufficient for the Apple-Silicon emulator —
  carried decision from 2a).

## 3. Architecture

All additive, package `org.secretary.sync`, under `android/kit/src/androidTest/`.

### 3.1 Fixture staging (build-time, gitignored)

- New Gradle `Copy` task `stageGoldenVaultForAndroidTest` in `android/kit/build.gradle.kts`:
  copies `repoRoot/core/tests/data/golden_vault_001/` (the whole tree) and
  `golden_vault_001_inputs.json` into `src/androidTest/assets/`. The destination is **gitignored**
  (single source of truth stays `core/tests/data/`; no committed duplicate of a frozen KAT —
  mirrors how iOS stages it via `build-xcframework.sh`). Input/output declared so Gradle skips it
  when the fixture is unchanged.
- Wire it ahead of the androidTest asset merge: `tasks.matching { it.name == "mergeDebugAndroidTestAssets" }.configureEach { dependsOn(stageGoldenVaultForAndroidTest) }` (the exact task name is verified during implementation; fallback is a `withType<...>`/`endsWith("AndroidTestAssets")` match — the implementation pins whichever AGP 8.13.2 actually exposes).
- `android/.gitignore`: add `kit/src/androidTest/assets/`.

### 3.2 `GoldenVaultStaging` test helper

A small `androidTest` helper (one file) providing:
- `stageWritableVault(context): File` — recursively copies the bundled `golden_vault_001` asset
  tree from `context.assets` into a fresh unique dir under `context.cacheDir` and returns it. The
  copy is the **only** thing the test opens, so the tracked fixture is never mutated
  ([[feedback_smoke_test_temp_copy_golden_vault]]). A sibling fresh dir under `cacheDir` is the
  empty `stateDir`.
- `goldenVaultUuid(context): ByteArray` — reads `golden_vault_001_inputs.json` from assets, parses
  `vault_uuid` (`00112233-4455-6677-8899-aabbccddeeff`), strips dashes, decodes to the 16-byte
  array `sync_status` requires (mirrors iOS `goldenPinnedVaultUuidHex()` — JSON is the single source
  of truth, so the test stays honest if the fixture is ever regenerated).
- A recursive asset-copy is the only non-pure part (it needs `AssetManager`); kept minimal and
  isolated so the test bodies read cleanly.

Cleanup: each test removes its `cacheDir` temp tree in a `@After` (best-effort, like iOS tearDown).

### 3.3 Tests (`@RunWith(AndroidJUnit4::class)`)

Constants (no magic literals): the golden password
`"correct horse battery staple"` and a fixed `nowMs` are named `val`s in the test (sourced
conceptually from the inputs JSON; the password is a test constant exactly as iOS hardcodes it in
`VaultAccessIntegrationTests`).

- **Test A — raw `UniffiVaultSyncPort`:**
  1. Stage writable vault + empty `stateDir`.
  2. `port.status(stateDir, goldenVaultUuid)` → assert `hasState == false` (empty state dir; mirrors
     the bridge `sync_status_in_..._reports_no_state_on_empty_dir` invariant).
  3. `port.sync(stateDir, vaultFolder, password.toByteArray(), nowMs)` → assert the real
     `SyncOutcome` arm (see §4 — pinned empirically).
  4. `port.status(...)` again → assert the post-pass status is self-consistent with the outcome
     (e.g. if the pass advanced state, `hasState == true`; if `NothingToDo`, still `false`).
  This is the core proof: a real `.so` loaded, a real uniffi call marshalled, a real DTO mapped to
  a domain `SyncOutcome` — none of which the host tests can touch.

- **Test B — `SyncCoordinator` over the real port:**
  Construct `SyncCoordinator` wrapping a real `UniffiVaultSyncPort`, run one `sync` pass through it,
  assert the same outcome. Proves the assembled **slice-1 (pure core) + slice-2a (adapter)** stack
  works on device, not just the adapter in isolation. (No concurrent `status()` read is driven
  during the in-flight pass — the coordinator's shared `Mutex` would serialize it behind the real
  Argon2id re-open; carried caveat from slice 1.)

### 3.4 Build deps (`android/kit/build.gradle.kts`)

- `androidTestImplementation`: `androidx.test:runner`, `androidx.test:core`, `androidx.test.ext:junit`
  (JUnit4 instrumentation — instrumented tests run on the device VM via the AndroidJUnitRunner, a
  separate world from the JUnit5 host unit tests; the two test source sets do not share a runner).
- `android { defaultConfig { testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" } }`.
- Pinned versions resolved during implementation against what the repo's Gradle/AGP already fetches;
  follow the existing `strictly(...)` discipline where a transitive pin matters.

## 4. The asserted outcome arm (characterization)

A single-device golden vault with an empty `stateDir` has no peer evidence, so
`core/src/sync/once.rs:87` (`ClockRelation::Equal → NothingToDo`) suggests the first pass returns
`SyncOutcome.NothingToDo` and writes no state (`status.hasState` stays `false` after). **This is a
hypothesis, not an assumption.** The implementation runs the test on the emulator first, observes
the actual arm, then pins the assertion to the observed value with a one-line rationale comment. If
the observed arm is *not* `NothingToDo`, that is a real finding to record in the handoff, not a test
to force-green — the spec/code disagreement discipline applies ([[feedback_security_no_assumptions]]).

## 5. Error handling

- Missing `.so` (native-load failure) → `UnsatisfiedLinkError` from the first FFI call. Acceptable
  as a hard failure; the test does not catch it. (The staging wiring makes this not happen, but if
  the emulator ABI ever mismatches the single arm64 build, the failure is loud and obvious.)
- Missing/empty staged asset → the helper fails loudly with a message naming
  `stageGoldenVaultForAndroidTest`, the iOS-style "you forgot to run the staging" hint.
- A `VaultException` from the FFI is already mapped to `VaultSyncError` by the adapter under test;
  an unexpected one surfaces as a test failure with the mapped type — which is itself useful signal.

## 6. Acceptance criteria

```bash
cd android
# 1. Emulator round-trip — the headline gate (emulator must be booted):
./gradlew :kit:connectedDebugAndroidTest        # BOTH instrumented tests pass on Medium_Phone_API_36.1

# 2. Host path unchanged — still NDK-free and green:
./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks   # 22 + 14 host tests, 0 warnings
./gradlew :kit:testDebugUnitTest --dry-run | grep -q cargoNdkBuildArm64 && echo LEAK || echo "host tests NDK-free"

# 3. Scope guardrails:
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'            # empty
```

Emulator boot uses absolute tool paths (`$ANDROID_HOME/platform-tools/adb`,
`$ANDROID_HOME/emulator/emulator`) — `adb`/`emulator` are not on the bare PATH
([[project_secretary_android_toolchain]]). cargo-ndk 3.5.4 is installed.

## 7. Risks / open items

- **Emulator availability in this environment.** The headline gate needs a booted arm64 emulator.
  If the AVD will not boot headless in this session, the fallback is: keep the tests + wiring (they
  are correct and host-compiled/lint-clean), document the un-run gate explicitly in the handoff, and
  do NOT claim the on-device gate passed ([[feedback_verify_deferred_items]]). The tests are written
  to pass; an un-run gate is a stated risk, never a silent one.
- **AGP androidTest asset-merge task name.** Pinned during implementation by listing tasks; the
  design names the expected `mergeDebugAndroidTestAssets` with a documented fallback match.
- **First-pass outcome arm** — characterized, not assumed (§4).

## 8. Out-of-scope follow-ups (carried)

Slice 3 (folder-change detection: SAF + `WorkManager`), slice 4 (Compose sync UI), on-device veto
round-trip (needs seeded concurrent state), `armv7`/`x86_64` device matrix.
