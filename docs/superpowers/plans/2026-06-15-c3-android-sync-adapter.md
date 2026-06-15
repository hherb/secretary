# Android slice 2a — real `UniffiVaultSyncPort` adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the pure slice-1 Kotlin sync core to the real Rust FFI on Android — a `UniffiVaultSyncPort` over the generated `uniffi.secretary` bindings + the arm64 native `.so` — host-verified and build-verified, with the emulator round-trip deferred to slice 2b.

**Architecture:** A new `:kit` Android-library module (the only module importing `uniffi.secretary`) depends on the pure `:vault-access` module. Gradle generates the uniffi Kotlin bindings at build time and cross-builds the cdylib for arm64 via cargo-ndk into `jniLibs`. The adapter delegates all DTO→domain and `VaultException`→`VaultSyncError` translation to pure, fully host-tested mapper functions; the adapter's own wiring (background offload, error catch, decision→DTO mapping) is host-tested by injecting fake FFI function seams + a test dispatcher.

**Tech Stack:** Kotlin 2.2.10, Android Gradle Plugin 8.13.2, Gradle 8.14.3, NDK 29.0.14206865, cargo-ndk, uniffi 0.31, JNA 5.14.0 (aar), kotlinx-coroutines 1.8.0 (+ coroutines-test), JUnit 5 (BOM 5.10.2).

**Reference (1:1 transcription source):** `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift` and `VaultSyncErrorMapping.swift`.

**Confirmed generated names** (from `ffi/secretary-ffi-uniffi/tests/kotlin/` — not assumed):
- Package: `uniffi.secretary`. Top-level fns: `syncStatus(stateDir: String, vaultUuid: ByteArray): SyncStatusDto`, `syncVault(stateDir: String, vaultFolder: String, password: ByteArray, nowMs: ULong): SyncOutcomeDto`, `syncCommitDecisions(stateDir: String, vaultFolder: String, password: ByteArray, decisions: List<VetoDecisionDto>, manifestHash: ByteArray, nowMs: ULong): SyncOutcomeDto`.
- `SyncOutcomeDto` sealed arms: `NothingToDo`, `AppliedAutomatically`, `SilentMerge`, `MergedClean`, `RollbackRejected`, `ConflictsPending(vetoes: List<VetoDto>, collisions: List<CollisionDto>, manifestHash: ByteArray)`.
- `SyncStatusDto(hasState: Boolean, deviceClocks: List<DeviceClockDto>, lastStateWriteMs: ULong?)`; `DeviceClockDto(deviceUuidHex: String, counter: ULong)`.
- `VetoDto(recordUuidHex, recordType, tags, fieldNames, localLastModMs, peerTombstonedAtMs, peerDeviceHex)`; `CollisionDto(recordUuidHex, fieldNames)`; `VetoDecisionDto(recordUuidHex: String, keepLocal: Boolean)`.
- `VaultException` arms (carry `.detail: String` where noted): `WrongPasswordOrCorrupt`, `SyncStateVaultMismatch`, `SyncStateCorrupt(detail)`, `SyncEvidenceStale`, `SyncInProgress`, `SyncFailed(detail)`, `SyncDecisionsIncomplete`, `InvalidArgument(detail)`, and ~25 non-sync arms (e.g. `RecordNotFound`, `BlockNotFound`, …).

---

## File Structure

- **Create** `android/kit/build.gradle.kts` — `:kit` Android-library build: AGP/SDK/NDK pins, JNA dep, JUnit5 test wiring, `generateUniffiKotlinBindings` + `cargoNdkBuildArm64` tasks, dependency on `:vault-access`.
- **Modify** `android/settings.gradle.kts` — add `include(":kit")`.
- **Modify** `android/build.gradle.kts` — declare `kotlin("android")` + `com.android.library` plugins `apply false`.
- **Modify** `android/.gitignore` — ignore `kit/src/main/jniLibs/`.
- **Create** `android/kit/src/main/AndroidManifest.xml` — minimal manifest (namespace-only).
- **Create** `android/kit/src/main/kotlin/org/secretary/sync/SyncOutcomeMapping.kt` — pure DTO→domain mappers (`mapOutcome`, `mapStatus`, `mapVeto`, `mapCollision`).
- **Create** `android/kit/src/main/kotlin/org/secretary/sync/VaultSyncErrorMapping.kt` — pure `mapVaultSyncError(VaultException): VaultSyncError`.
- **Create** `android/kit/src/main/kotlin/org/secretary/sync/UniffiVaultSyncPort.kt` — the adapter (injectable FFI seams + dispatcher; private `toDto` decision mapper).
- **Create** `android/kit/src/test/kotlin/org/secretary/sync/SyncOutcomeMappingTest.kt`
- **Create** `android/kit/src/test/kotlin/org/secretary/sync/VaultSyncErrorMappingTest.kt`
- **Create** `android/kit/src/test/kotlin/org/secretary/sync/UniffiVaultSyncPortTest.kt`
- **Modify** `android/README.md`, repo `README.md`, repo `ROADMAP.md` — slice-2a status.

All production Kotlin lives in package `org.secretary.sync` (same as slice 1); `:kit` is the sole importer of `uniffi.secretary`.

---

## Task 0: Install cargo-ndk (one-time host setup)

**Files:** none (host tooling).

- [ ] **Step 1: Install cargo-ndk**

Run: `cargo install cargo-ndk --version 3.5.4`
Expected: `Installed package cargo-ndk` (or "already installed"). Network is available.

- [ ] **Step 2: Verify**

Run: `cargo ndk --version`
Expected: prints `cargo-ndk 3.5.4`.

(No commit — host tooling only.)

---

## Task 1: `:kit` Android-library scaffold + Gradle build wiring

**Files:**
- Modify: `android/build.gradle.kts`
- Modify: `android/settings.gradle.kts`
- Modify: `android/.gitignore`
- Create: `android/kit/build.gradle.kts`
- Create: `android/kit/src/main/AndroidManifest.xml`

This task has no unit test — its acceptance is "the module configures, generates bindings, and the host build resolves." Follow the steps and verify each command's output.

- [ ] **Step 1: Declare the Android + Kotlin-android plugins at the root (apply false)**

Replace `android/build.gradle.kts` with:

```kotlin
plugins {
    // :vault-access is pure-JVM Kotlin; :kit is an Android library (uniffi adapter + jniLibs).
    kotlin("jvm") version "2.2.10" apply false
    kotlin("android") version "2.2.10" apply false
    id("com.android.library") version "8.13.2" apply false
}
```

- [ ] **Step 2: Include `:kit` in the build**

In `android/settings.gradle.kts`, change the final line `include(":vault-access")` to:

```kotlin
include(":vault-access")
include(":kit")
```

- [ ] **Step 3: Ignore the staged native libs**

Append to `android/.gitignore`:

```
# cargo-ndk-staged native libraries (built, never committed)
kit/src/main/jniLibs/
```

- [ ] **Step 4: Minimal manifest**

Create `android/kit/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest />
```

- [ ] **Step 5: Write the `:kit` build script**

Create `android/kit/build.gradle.kts`:

```kotlin
import org.gradle.api.tasks.Exec
import org.gradle.nativeplatform.platform.internal.DefaultNativePlatform

plugins {
    id("com.android.library")
    kotlin("android")
}

// Repo root (the cargo workspace) is the parent of the `android/` gradle root project.
val repoRoot: java.io.File = rootProject.projectDir.parentFile
val hostCdylibExt: String = if (DefaultNativePlatform.getCurrentOperatingSystem().isMacOsX) "dylib" else "so"
val generatedBindingsDir = layout.buildDirectory.dir("generated/uniffi")

android {
    namespace = "org.secretary.sync"
    compileSdk = 36
    ndkVersion = "29.0.14206865"

    defaultConfig {
        minSdk = 26
    }

    // Kotlin/JVM 21 bytecode (matches :vault-access jvmToolchain(21)).
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    // Host JVM unit tests use JUnit 5 (matches :vault-access).
    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }

    sourceSets {
        getByName("main") {
            // uniffi bindings are generated into build/ and never committed.
            kotlin.srcDir(generatedBindingsDir.map { it.dir("uniffi/secretary") })
        }
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api(project(":vault-access"))

    // uniffi 0.31 Kotlin bindings load the cdylib through JNA (aar variant for Android).
    // 5.14.0 satisfies uniffi's >=5.12 floor; fetched from mavenCentral (network available).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// --- FFI build wiring -------------------------------------------------------

// Generate the uniffi Kotlin bindings from the .udl-derived host cdylib metadata.
// uniffi-bindgen --library reads the built cdylib, so we build the host cdylib first.
val generateUniffiKotlinBindings by tasks.registering(Exec::class) {
    workingDir = repoRoot
    inputs.dir(repoRoot.resolve("ffi/secretary-ffi-uniffi/src"))
    outputs.dir(generatedBindingsDir)
    doFirst {
        exec {
            workingDir = repoRoot
            commandLine("cargo", "build", "--release", "-p", "secretary-ffi-uniffi")
        }
    }
    commandLine(
        "cargo", "run", "--release", "--features", "cli",
        "-p", "secretary-ffi-uniffi", "--bin", "uniffi-bindgen", "--",
        "generate",
        "--library", "target/release/libsecretary_ffi_uniffi.$hostCdylibExt",
        "--language", "kotlin",
        "--out-dir", generatedBindingsDir.get().asFile.absolutePath,
    )
}

// Bindings must exist before Kotlin compiles.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(generateUniffiKotlinBindings)
}

// Cross-build the cdylib for arm64-v8a and stage it into jniLibs.
val cargoNdkBuildArm64 by tasks.registering(Exec::class) {
    workingDir = repoRoot
    environment("ANDROID_NDK_HOME", "${System.getProperty("user.home")}/Library/Android/sdk/ndk/29.0.14206865")
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", layout.projectDirectory.dir("src/main/jniLibs").asFile.absolutePath,
        "build", "--release", "-p", "secretary-ffi-uniffi",
    )
}

// The native lib is required to assemble the AAR, but NOT for host unit tests.
tasks.named("preBuild").configure { dependsOn(cargoNdkBuildArm64) }
```

- [ ] **Step 6: Verify bindings generation works standalone**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:generateUniffiKotlinBindings`
Expected: BUILD SUCCESSFUL; file `kit/build/generated/uniffi/uniffi/secretary/secretary.kt` exists.

Verify: `test -f kit/build/generated/uniffi/uniffi/secretary/secretary.kt && echo OK`
Expected: `OK`.

- [ ] **Step 7: Verify the module configures and the host source set compiles (empty Kotlin + generated bindings)**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:compileDebugKotlin`
Expected: BUILD SUCCESSFUL (the generated `secretary.kt` compiles against JNA; no `:kit` source yet).

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter
git add android/build.gradle.kts android/settings.gradle.kts android/.gitignore android/kit/build.gradle.kts android/kit/src/main/AndroidManifest.xml
git commit -m "build(C.3 Android): :kit Android-library scaffold + uniffi/cargo-ndk wiring

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `SyncOutcomeMapping.kt` — pure DTO→domain mappers (TDD)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/sync/SyncOutcomeMapping.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/sync/SyncOutcomeMappingTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/kit/src/test/kotlin/org/secretary/sync/SyncOutcomeMappingTest.kt`:

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.CollisionDto
import uniffi.secretary.DeviceClockDto
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VetoDto

class SyncOutcomeMappingTest {
    @Test
    fun `maps the five singleton outcome arms 1 to 1`() {
        assertEquals(SyncOutcome.NothingToDo, mapOutcome(SyncOutcomeDto.NothingToDo))
        assertEquals(SyncOutcome.AppliedAutomatically, mapOutcome(SyncOutcomeDto.AppliedAutomatically))
        assertEquals(SyncOutcome.SilentMerge, mapOutcome(SyncOutcomeDto.SilentMerge))
        assertEquals(SyncOutcome.MergedClean, mapOutcome(SyncOutcomeDto.MergedClean))
        assertEquals(SyncOutcome.RollbackRejected, mapOutcome(SyncOutcomeDto.RollbackRejected))
    }

    @Test
    fun `maps ConflictsPending preserving vetoes collisions and manifest hash`() {
        val veto = VetoDto(
            recordUuidHex = "aa", recordType = "login", tags = listOf("t1"),
            fieldNames = listOf("password"), localLastModMs = 10uL,
            peerTombstonedAtMs = 20uL, peerDeviceHex = "bb",
        )
        val collision = CollisionDto(recordUuidHex = "cc", fieldNames = listOf("note"))
        val hash = byteArrayOf(1, 2, 3)

        val mapped = mapOutcome(SyncOutcomeDto.ConflictsPending(listOf(veto), listOf(collision), hash))

        assertTrue(mapped is SyncOutcome.ConflictsPending)
        mapped as SyncOutcome.ConflictsPending
        assertEquals(
            listOf(SyncVeto("aa", "login", listOf("t1"), listOf("password"), 10uL, 20uL, "bb")),
            mapped.vetoes,
        )
        assertEquals(listOf(SyncCollision("cc", listOf("note"))), mapped.collisions)
        assertTrue(hash.contentEquals(mapped.manifestHash))
    }

    @Test
    fun `maps status with device clocks and optional last write`() {
        val dto = SyncStatusDto(
            hasState = true,
            deviceClocks = listOf(DeviceClockDto(deviceUuidHex = "dd", counter = 7uL)),
            lastStateWriteMs = 99uL,
        )

        val mapped = mapStatus(dto)

        assertEquals(true, mapped.hasState)
        assertEquals(listOf(DeviceClock("dd", 7uL)), mapped.deviceClocks)
        assertEquals(99uL, mapped.lastStateWriteMs)
    }

    @Test
    fun `maps status with null last write`() {
        val dto = SyncStatusDto(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null)
        assertEquals(null, mapStatus(dto).lastStateWriteMs)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.SyncOutcomeMappingTest"`
Expected: FAIL — `mapOutcome` / `mapStatus` unresolved reference.

- [ ] **Step 3: Write the implementation**

Create `android/kit/src/main/kotlin/org/secretary/sync/SyncOutcomeMapping.kt`:

```kotlin
package org.secretary.sync

import uniffi.secretary.CollisionDto
import uniffi.secretary.DeviceClockDto
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VetoDto

/**
 * Pure DTO→domain mappers for the uniffi sync surface. The arms map 1:1 to the
 * `SyncOutcomeDto` definition in `ffi/secretary-ffi-uniffi/src/secretary.udl`; if that
 * surface changes, update both these functions and the `SyncOutcome` domain arms.
 * A faithful transcription of iOS `UniffiVaultSyncPort.swift`'s `mapOutcome`/`mapStatus`.
 */
internal fun mapOutcome(dto: SyncOutcomeDto): SyncOutcome = when (dto) {
    is SyncOutcomeDto.NothingToDo -> SyncOutcome.NothingToDo
    is SyncOutcomeDto.AppliedAutomatically -> SyncOutcome.AppliedAutomatically
    is SyncOutcomeDto.SilentMerge -> SyncOutcome.SilentMerge
    is SyncOutcomeDto.MergedClean -> SyncOutcome.MergedClean
    is SyncOutcomeDto.RollbackRejected -> SyncOutcome.RollbackRejected
    is SyncOutcomeDto.ConflictsPending -> SyncOutcome.ConflictsPending(
        vetoes = dto.vetoes.map(::mapVeto),
        collisions = dto.collisions.map(::mapCollision),
        manifestHash = dto.manifestHash,
    )
}

internal fun mapStatus(dto: SyncStatusDto): SyncStatus = SyncStatus(
    hasState = dto.hasState,
    deviceClocks = dto.deviceClocks.map(::mapDeviceClock),
    lastStateWriteMs = dto.lastStateWriteMs,
)

internal fun mapVeto(dto: VetoDto): SyncVeto = SyncVeto(
    recordUuidHex = dto.recordUuidHex,
    recordType = dto.recordType,
    tags = dto.tags,
    fieldNames = dto.fieldNames,
    localLastModMs = dto.localLastModMs,
    peerTombstonedAtMs = dto.peerTombstonedAtMs,
    peerDeviceHex = dto.peerDeviceHex,
)

internal fun mapCollision(dto: CollisionDto): SyncCollision = SyncCollision(
    recordUuidHex = dto.recordUuidHex,
    fieldNames = dto.fieldNames,
)

private fun mapDeviceClock(dto: DeviceClockDto): DeviceClock = DeviceClock(
    deviceUuidHex = dto.deviceUuidHex,
    counter = dto.counter,
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.SyncOutcomeMappingTest"`
Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter
git add android/kit/src/main/kotlin/org/secretary/sync/SyncOutcomeMapping.kt android/kit/src/test/kotlin/org/secretary/sync/SyncOutcomeMappingTest.kt
git commit -m "feat(C.3 Android): pure SyncOutcomeDto/SyncStatusDto -> domain mappers

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `VaultSyncErrorMapping.kt` — pure `VaultException`→`VaultSyncError` (TDD)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/sync/VaultSyncErrorMapping.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/sync/VaultSyncErrorMappingTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/kit/src/test/kotlin/org/secretary/sync/VaultSyncErrorMappingTest.kt`:

```kotlin
package org.secretary.sync

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.VaultException

class VaultSyncErrorMappingTest {
    @Test
    fun `maps each sync-specific arm to its domain counterpart`() {
        assertEquals(VaultSyncError.InProgress, mapVaultSyncError(VaultException.SyncInProgress()))
        assertEquals(VaultSyncError.StateVaultMismatch, mapVaultSyncError(VaultException.SyncStateVaultMismatch()))
        assertEquals(VaultSyncError.EvidenceStale, mapVaultSyncError(VaultException.SyncEvidenceStale()))
        assertEquals(VaultSyncError.DecisionsIncomplete, mapVaultSyncError(VaultException.SyncDecisionsIncomplete()))
    }

    @Test
    fun `maps detail-carrying arms preserving the detail string`() {
        assertEquals(VaultSyncError.StateCorrupt("boom"), mapVaultSyncError(VaultException.SyncStateCorrupt("boom")))
        assertEquals(VaultSyncError.Failed("nope"), mapVaultSyncError(VaultException.SyncFailed("nope")))
        assertEquals(VaultSyncError.InvalidArgument("bad uuid"), mapVaultSyncError(VaultException.InvalidArgument("bad uuid")))
    }

    @Test
    fun `keeps wrong-password-or-corrupt conflated per threat model`() {
        assertEquals(VaultSyncError.WrongPasswordOrCorrupt, mapVaultSyncError(VaultException.WrongPasswordOrCorrupt()))
    }

    @Test
    fun `folds any non-sync arm into Failed with a descriptive detail`() {
        val mapped = mapVaultSyncError(VaultException.RecordNotFound())
        assertTrue(mapped is VaultSyncError.Failed)
        mapped as VaultSyncError.Failed
        assertTrue(mapped.detail.contains("RecordNotFound"))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.VaultSyncErrorMappingTest"`
Expected: FAIL — `mapVaultSyncError` unresolved reference.

- [ ] **Step 3: Write the implementation**

Create `android/kit/src/main/kotlin/org/secretary/sync/VaultSyncErrorMapping.kt`:

```kotlin
package org.secretary.sync

import uniffi.secretary.VaultException

/**
 * Pure `VaultException`→`VaultSyncError` mapper. Deliberately maps only the sync-relevant
 * `VaultException` arms; every other arm folds into [VaultSyncError.Failed] carrying the
 * variant name (matching iOS `mapVaultSyncError`'s `default` branch).
 *
 * [VaultException.WrongPasswordOrCorrupt] stays conflated (wrong password vs. corruption)
 * per the threat model's anti-oracle rule (§13) — do NOT split it. [VaultSyncError.NoPendingConflict]
 * has no FFI origin (it is a coordinator-only guard) and is intentionally absent here.
 */
internal fun mapVaultSyncError(e: VaultException): VaultSyncError = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> VaultSyncError.WrongPasswordOrCorrupt
    is VaultException.SyncInProgress -> VaultSyncError.InProgress
    is VaultException.SyncStateVaultMismatch -> VaultSyncError.StateVaultMismatch
    is VaultException.SyncStateCorrupt -> VaultSyncError.StateCorrupt(e.detail)
    is VaultException.SyncEvidenceStale -> VaultSyncError.EvidenceStale
    is VaultException.SyncDecisionsIncomplete -> VaultSyncError.DecisionsIncomplete
    is VaultException.InvalidArgument -> VaultSyncError.InvalidArgument(e.detail)
    is VaultException.SyncFailed -> VaultSyncError.Failed(e.detail)
    else -> VaultSyncError.Failed(e.toString())
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.VaultSyncErrorMappingTest"`
Expected: PASS — 4 tests.

> If a `VaultException.*` arm name or `.detail` accessor in the test fails to resolve, open
> `kit/build/generated/uniffi/uniffi/secretary/secretary.kt` and correct the arm name/accessor to
> match the generated code (the generated `.kt` is the source of truth). Constructors for no-field
> arms are `VaultException.SyncInProgress()`; detail arms are `VaultException.SyncFailed("…")`.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter
git add android/kit/src/main/kotlin/org/secretary/sync/VaultSyncErrorMapping.kt android/kit/src/test/kotlin/org/secretary/sync/VaultSyncErrorMappingTest.kt
git commit -m "feat(C.3 Android): pure VaultException -> VaultSyncError mapper (conflation + default fold)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `UniffiVaultSyncPort.kt` — the adapter (TDD with injected seams)

**Files:**
- Create: `android/kit/src/main/kotlin/org/secretary/sync/UniffiVaultSyncPort.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/sync/UniffiVaultSyncPortTest.kt`

**Design note:** the adapter takes the three uniffi functions as constructor seams whose
**defaults are the real `uniffi.secretary` functions** (`::syncStatus`, `::syncVault`,
`::syncCommitDecisions`), plus a `CoroutineDispatcher` (default `Dispatchers.IO`). Production
code constructs `UniffiVaultSyncPort()` with all defaults; tests inject fakes + a test
dispatcher to host-verify the wiring (offload, error catch, decision→DTO mapping, password
passthrough) with no `.so` loaded.

- [ ] **Step 1: Write the failing test**

Create `android/kit/src/test/kotlin/org/secretary/sync/UniffiVaultSyncPortTest.kt`:

```kotlin
package org.secretary.sync

import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VaultException
import uniffi.secretary.VetoDecisionDto

class UniffiVaultSyncPortTest {
    @Test
    fun `status maps the dto and forwards args`() = runTest {
        var seenDir: String? = null
        var seenUuid: ByteArray? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { dir, uuid ->
                seenDir = dir; seenUuid = uuid
                SyncStatusDto(hasState = true, deviceClocks = emptyList(), lastStateWriteMs = null)
            },
            syncFn = { _, _, _, _ -> error("unused") },
            commitFn = { _, _, _, _, _, _ -> error("unused") },
        )

        val status = port.status(stateDir = "/s", vaultUuid = ByteArray(16) { 1 })

        assertEquals("/s", seenDir)
        assertArrayEquals(ByteArray(16) { 1 }, seenUuid)
        assertEquals(true, status.hasState)
    }

    @Test
    fun `sync forwards password and maps the outcome`() = runTest {
        var seenPassword: ByteArray? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("unused") },
            syncFn = { _, _, pw, _ -> seenPassword = pw; SyncOutcomeDto.AppliedAutomatically },
            commitFn = { _, _, _, _, _, _ -> error("unused") },
        )

        val outcome = port.sync("/s", "/v", byteArrayOf(7, 8, 9), nowMs = 5uL)

        assertArrayEquals(byteArrayOf(7, 8, 9), seenPassword)
        assertEquals(SyncOutcome.AppliedAutomatically, outcome)
    }

    @Test
    fun `commitDecisions maps domain decisions to dtos and maps the outcome`() = runTest {
        var seenDecisions: List<VetoDecisionDto>? = null
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("unused") },
            syncFn = { _, _, _, _ -> error("unused") },
            commitFn = { _, _, _, decisions, _, _ -> seenDecisions = decisions; SyncOutcomeDto.MergedClean },
        )

        val outcome = port.commitDecisions(
            stateDir = "/s", vaultFolder = "/v", password = byteArrayOf(1),
            decisions = listOf(SyncVetoDecision("rec", keepLocal = true)),
            manifestHash = byteArrayOf(2), nowMs = 5uL,
        )

        assertEquals(listOf(VetoDecisionDto(recordUuidHex = "rec", keepLocal = true)), seenDecisions)
        assertEquals(SyncOutcome.MergedClean, outcome)
    }

    @Test
    fun `a thrown VaultException is mapped to VaultSyncError`() = runTest {
        val port = UniffiVaultSyncPort(
            ioDispatcher = StandardTestDispatcher(testScheduler),
            statusFn = { _, _ -> error("unused") },
            syncFn = { _, _, _, _ -> throw VaultException.SyncInProgress() },
            commitFn = { _, _, _, _, _, _ -> error("unused") },
        )

        val thrown = assertThrows(VaultSyncError.InProgress::class.java) {
            kotlinx.coroutines.runBlocking { port.sync("/s", "/v", byteArrayOf(1), nowMs = 0uL) }
        }
        assertTrue(thrown is VaultSyncError.InProgress)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.UniffiVaultSyncPortTest"`
Expected: FAIL — `UniffiVaultSyncPort` unresolved reference.

- [ ] **Step 3: Write the implementation**

Create `android/kit/src/main/kotlin/org/secretary/sync/UniffiVaultSyncPort.kt`:

```kotlin
package org.secretary.sync

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VaultException
import uniffi.secretary.VetoDecisionDto
import uniffi.secretary.syncCommitDecisions
import uniffi.secretary.syncStatus
import uniffi.secretary.syncVault

/**
 * The real [VaultSyncPort] over the generated `uniffi.secretary` bindings — the ONLY type
 * that imports them. A faithful Kotlin mirror of iOS `UniffiVaultSyncPort.swift`.
 *
 * [sync] and [commitDecisions] re-open the vault from the password (full Argon2id), so they run
 * on [ioDispatcher] (default [Dispatchers.IO]) to keep the caller responsive; [status] is a cheap
 * disk read and runs inline. The password [ByteArray] is forwarded per call and never retained.
 *
 * The three FFI functions are injectable seams defaulting to the real bindings, so the adapter's
 * wiring is host-testable with fakes (no native library loaded). Production code uses all defaults.
 */
class UniffiVaultSyncPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val statusFn: (String, ByteArray) -> SyncStatusDto = ::syncStatus,
    private val syncFn: (String, String, ByteArray, ULong) -> SyncOutcomeDto = ::syncVault,
    private val commitFn: (String, String, ByteArray, List<VetoDecisionDto>, ByteArray, ULong) -> SyncOutcomeDto =
        ::syncCommitDecisions,
) : VaultSyncPort {

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        mapStatus(callMappingErrors { statusFn(stateDir, vaultUuid) })

    override suspend fun sync(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = withContext(ioDispatcher) {
        mapOutcome(callMappingErrors { syncFn(stateDir, vaultFolder, password, nowMs) })
    }

    override suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = withContext(ioDispatcher) {
        val dtoDecisions = decisions.map(::toVetoDecisionDto)
        mapOutcome(callMappingErrors {
            commitFn(stateDir, vaultFolder, password, dtoDecisions, manifestHash, nowMs)
        })
    }
}

/** Run an FFI call, translating any [VaultException] into the domain [VaultSyncError]. */
private inline fun <T> callMappingErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultSyncError(e)
    }

private fun toVetoDecisionDto(d: SyncVetoDecision): VetoDecisionDto =
    VetoDecisionDto(recordUuidHex = d.recordUuidHex, keepLocal = d.keepLocal)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:testDebugUnitTest --tests "org.secretary.sync.UniffiVaultSyncPortTest"`
Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter
git add android/kit/src/main/kotlin/org/secretary/sync/UniffiVaultSyncPort.kt android/kit/src/test/kotlin/org/secretary/sync/UniffiVaultSyncPortTest.kt
git commit -m "feat(C.3 Android): UniffiVaultSyncPort adapter over uniffi bindings (offload + seams)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Full host gauntlet + native build verification + docs

**Files:**
- Modify: `android/README.md`
- Modify: `README.md` (repo root)
- Modify: `ROADMAP.md` (repo root)

- [ ] **Step 1: Run the whole host gauntlet (both modules, zero warnings)**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :vault-access:test :kit:testDebugUnitTest --rerun-tasks`
Expected: BUILD SUCCESSFUL; `:vault-access` 22 tests, `:kit` 12 tests, 0 failures, 0 warnings.

- [ ] **Step 2: Verify the arm64 native library cross-builds and the AAR packages it**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter/android && ./gradlew :kit:assembleRelease`
Expected: BUILD SUCCESSFUL; the `.so` is staged.

Verify the AAR contains the native lib:
Run: `unzip -l kit/build/outputs/aar/kit-release.aar | grep arm64-v8a`
Expected: a line listing `jni/arm64-v8a/libsecretary_ffi_uniffi.so`.

- [ ] **Step 3: Update `android/README.md`**

Add a short note under the module list that `:kit` is the Android-library module hosting the real `UniffiVaultSyncPort` over the uniffi bindings + arm64 `jniLibs` (built via cargo-ndk), host- and build-verified; the emulator round-trip is slice 2b. Keep it brief (dot points), per the README style.

- [ ] **Step 4: Update repo `README.md` and `ROADMAP.md`**

- `README.md`: update the Android C.3 status line to note the real adapter (`:kit`) landed (host/build-verified), emulator round-trip pending (2b).
- `ROADMAP.md`: add the slice-2a entry under the Android C.3 track; mark slice 2b (emulator round-trip) as the next rung.

- [ ] **Step 5: Verify guardrails (additive-only, no core/ffi/ios/format change)**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)'
```
Expected: empty.

Run:
```bash
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```
Expected: empty.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-adapter
git add android/README.md README.md ROADMAP.md
git commit -m "docs(C.3 Android): slice-2a status — real UniffiVaultSyncPort adapter (:kit)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review (completed during planning)

**1. Spec coverage:**
- §3 module layout → Task 1 (scaffold), all source-file tasks. ✓
- §4.1 pure mappers → Task 2 (outcome/status) + Task 3 (error). ✓
- §4.2 adapter (inline status, offloaded sync/commit, password not retained) → Task 4. ✓
- §5 build wiring (generateUniffiKotlinBindings, cargoNdkBuildArm64, pins) → Task 0 + Task 1. ✓
- §6 host-only testing → Tasks 2–4 host tests; §7 acceptance gauntlet → Task 5. ✓
- §8 out-of-scope (emulator, other ABIs, UI, folder watch) → not implemented (deferred). ✓

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code; every command has expected output.

**3. Type consistency:** Domain types (`SyncOutcome`, `SyncStatus`, `SyncVeto`, `SyncCollision`, `DeviceClock`, `SyncVetoDecision`, `VaultSyncError`) match slice-1 definitions. Generated names (`SyncOutcomeDto`, `SyncStatusDto`, `VetoDto`, `CollisionDto`, `DeviceClockDto`, `VetoDecisionDto`, `VaultException.*`, `.detail`, `syncStatus`/`syncVault`/`syncCommitDecisions`) confirmed against `ffi/secretary-ffi-uniffi/tests/kotlin/`. Adapter seam signatures match the FFI fn signatures and the `VaultSyncPort` interface from slice 1. ✓
