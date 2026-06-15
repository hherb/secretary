# Design — Android slice 2a: real `UniffiVaultSyncPort` adapter + `:kit` module

**Date:** 2026-06-15
**Sub-project:** C.3 Android (sync orchestration), slice 2a
**Branch:** `feature/c3-android-sync-adapter` (from `main` @ `8cb6da4`)
**Predecessor:** slice 1 (#237) — pure Kotlin `:vault-access` core (`VaultSyncPort` interface, `SyncCoordinator`, `SyncModels`, `VaultSyncError`, `FakeVaultSyncPort`, 22 host tests).

## 1. Goal & boundary

Ship the **real** `VaultSyncPort` implementation for Android — wiring the pure slice-1 core over the
generated `uniffi.secretary` Kotlin bindings and the arm64 native `.so` — **host-verified and
build-verified, no emulator**. The instrumented round-trip against the golden vault is **slice 2b**.

This slice is purely additive: zero change to `core/`, `ffi/`, `ios/`, the frozen on-disk format, or
the slice-1 `:vault-access` sources. It is a faithful Kotlin mirror of the iOS adapter
(`ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift` +
`VaultSyncErrorMapping.swift`).

## 2. Decisions taken (brainstorming)

1. **Scope split.** Slice 2a (this) = adapter + full host-test coverage of the mappers + NDK arm64
   build wiring verified to build. Slice 2b (next session) = emulator instrumented round-trip
   against the golden vault. Rationale: the DTO→domain mapping is pure and host-testable on the JVM
   (instantiating uniffi DTOs does **not** load the `.so`; only *calling* an FFI fn does), so the
   logic gets full 1:1 coverage with zero emulator. Matches the repo's proactive-split discipline
   and how iOS isolated on-device proof (#202).
2. **NDK cross-build = cargo-ndk invoked from a Gradle exec task.** Transparent (the exact `cargo ndk`
   command is visible), no extra Gradle plugin to pin, mirrors how the conformance harness shells out
   to cargo. cargo-ndk installed via `cargo install cargo-ndk` (network available), documented in
   `android/README.md`.
3. **Generated bindings = generated at build time** via a Gradle task. The `.udl` stays the single
   source of truth; no machine-generated code is checked in (mirrors iOS's build-script generation).
   Cost accepted: `:kit` compilation invokes cargo (Gradle-caches it; only reruns when the `.udl`/crate
   sources change).

## 3. Module layout (new `:kit` Android library)

```
android/
  settings.gradle.kts          → add include(":kit")
  kit/
    build.gradle.kts           → com.android.library; AGP pinned; NDK 29 pinned;
                                  generateUniffiKotlinBindings + cargoNdkBuildArm64 tasks;
                                  depends on :vault-access
    src/main/kotlin/org/secretary/sync/
      UniffiVaultSyncPort.kt    → the adapter (thin shell: call FFI → map → offload)
      SyncOutcomeMapping.kt     → pure mapOutcome(SyncOutcomeDto) + mapStatus + mapVeto + mapCollision
      VaultSyncErrorMapping.kt  → pure mapVaultSyncError(VaultException): VaultSyncError
    src/test/kotlin/org/secretary/sync/
      SyncOutcomeMappingTest.kt    → 1:1 arm coverage (6 SyncOutcome arms + ConflictsPending ByteArray)
      VaultSyncErrorMappingTest.kt → every sync arm + WrongPasswordOrCorrupt conflation + non-sync default→Failed
    (generated, NOT committed) build/generated/uniffi/.../secretary.kt
    src/main/jniLibs/arm64-v8a/libsecretary_ffi_uniffi.so   (staged by cargo-ndk; gitignored)
```

**Layering.** `:vault-access` stays pure (no Android, no uniffi — it owns the `VaultSyncPort`
interface + domain types). `:kit` is the **only** module importing `uniffi.secretary`, mirroring iOS
where the Swift `UniffiVaultSyncPort` is the sole uniffi importer. `:kit` depends on `:vault-access`.
An Android library module depending on a `kotlin("jvm")` module is supported.

## 4. Components

### 4.1 Pure mappers (host-tested)

- **`mapOutcome` / `mapStatus` / `mapVeto` / `mapCollision`** — pure top-level functions, a direct
  transcription of iOS's `mapOutcome` etc. `SyncOutcomeDto` (uniffi `[Enum] interface`) → `SyncOutcome`
  sealed arms 1:1. The six arms: `NothingToDo`, `AppliedAutomatically`, `SilentMerge`, `MergedClean`,
  `RollbackRejected`, and `ConflictsPending(vetoes, collisions, manifestHash)` — the last carries
  `manifestHash: ByteArray`. `mapStatus` maps `SyncStatusDto`→`SyncStatus` (incl. `DeviceClockDto`→
  `DeviceClock`).
- **`mapVaultSyncError(VaultException): VaultSyncError`** — transcription of iOS
  `VaultSyncErrorMapping.swift`:
  - `SyncInProgress → InProgress`
  - `SyncStateVaultMismatch → StateVaultMismatch`
  - `SyncStateCorrupt(detail) → StateCorrupt(detail)`
  - `SyncEvidenceStale → EvidenceStale`
  - `SyncDecisionsIncomplete → DecisionsIncomplete`
  - `SyncFailed(detail) → Failed(detail)`
  - `WrongPasswordOrCorrupt → WrongPasswordOrCorrupt` (kept **conflated**, threat-model §13 — do not split)
  - `InvalidArgument(detail) → InvalidArgument(detail)`
  - **every other `VaultException` arm → `Failed(e.toString())`** (the catch-all; matches iOS `default`)

  Exact generated arm/field names are verified against the generated `secretary.kt` during
  implementation — per memory, uniffi 0.31 codegen may rename `message → detail` and `Error → Exception`
  (`VaultException`). `NoPendingConflict` is **not** mapped here — it is a coordinator-only guard with
  no FFI origin (slice 1).

### 4.2 `UniffiVaultSyncPort : VaultSyncPort`

Thin shell over the three uniffi functions (`syncStatus` / `syncVault` / `syncCommitDecisions`):

- `status()` runs **inline** (cheap disk read).
- `sync()` / `commitDecisions()` **offload** to an injected `CoroutineDispatcher`
  (default `Dispatchers.IO`) because they re-open the vault → full Argon2id. The dispatcher is a
  constructor parameter for slice-2b testability (per memory `..._sendable_offload`: sync runs Argon2id
  so must offload).
- Password is passed per-call as `ByteArray` and **never stored in a field** (the FFI fn takes it by
  value each call).
- Each FFI call is wrapped to catch `VaultException` → `mapVaultSyncError`.

The shell's real behavior (native loading, round-trip) is verified in **slice 2b** on the emulator;
this slice verifies it **compiles + assembles** with the arm64 `.so` packaged.

## 5. Build wiring (Gradle)

- **`generateUniffiKotlinBindings`** task: builds a **host** cdylib (`cargo build -p secretary-ffi-uniffi`),
  runs `uniffi-bindgen generate --library <host .so/.dylib> --language kotlin` into
  `build/generated/uniffi/`; output added to the main source set, wired before `compileKotlin`. Gradle
  up-to-date keyed on the `.udl` + crate sources.
- **`cargoNdkBuildArm64`** task: runs
  `cargo ndk -t arm64-v8a -o src/main/jniLibs build --release -p secretary-ffi-uniffi`, staging
  `libsecretary_ffi_uniffi.so`. Wired into the Android variant build; **not** required for
  `:kit:testDebugUnitTest` (host mapper tests don't load the `.so`).
- **Pins** (exact, per repo discipline): AGP (version compatible with Gradle 8.14.3, verified
  cache-available), `compileSdk=36`, `minSdk=26`, `targetSdk=36`, `ndkVersion=29.0.14206865`,
  JNA `5.14.0@aar`, coroutines `1.8.0` (strictly). Reuse slice-1 Kotlin 2.2.10 / JUnit BOM 5.10.2.

## 6. Testing (host only this slice)

- **Full 1:1 host unit coverage of the mappers** via JVM unit tests (`:kit:testDebugUnitTest`): every
  `SyncOutcome` arm incl. `ConflictsPending` `ByteArray` round-trip; every `VaultSyncError` arm incl.
  the `WrongPasswordOrCorrupt` conflation and the non-sync `default → Failed` catch-all. These construct
  uniffi DTOs/exceptions directly — **no `.so`, no emulator**.
- **Build verification:** `cargoNdkBuildArm64` produces the arm64 `.so`; `:kit:assembleRelease` packages
  it into the AAR's `jniLibs`.
- Slice-1's 22 `:vault-access` tests stay green (unchanged).
- The adapter shell's real round-trip is explicitly deferred to **slice 2b**.

## 7. Acceptance gauntlet

```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks
    → BUILD SUCCESSFUL, 0 failures, 0 warnings
cd android && ./gradlew :kit:assembleRelease
    → AAR contains lib/arm64-v8a/libsecretary_ffi_uniffi.so
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'
    → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
    → empty
```

## 8. Out of scope (deferred)

- Emulator instrumented round-trip against the golden vault — **slice 2b**.
- armv7 / x86_64 ABIs (only arm64-v8a needed for the Apple-Silicon emulator + modern devices).
- `:app` Compose UI + ViewModel/StateFlow/badge — **slice 4**.
- Folder-change detection (SAF + WorkManager) — **slice 3**.
- Checked-in / regenerated-and-reviewed bindings (chose generate-at-build instead).

## 9. Risks

- **uniffi codegen naming drift.** Generated Kotlin arm/field names (e.g. `VaultException`,
  `detail` vs `message`) are verified against the actual generated `secretary.kt`, not assumed.
- **cargo on the host-test path.** `generateUniffiKotlinBindings` couples `:kit` compilation to cargo +
  uniffi-bindgen; acceptable since the repo is a Rust workspace (cargo always present). Gradle caching
  keeps it off the hot loop.
- **AGP↔Gradle compatibility.** AGP version must be compatible with Gradle 8.14.3 and cache-available;
  pinned and verified during Task 1.
