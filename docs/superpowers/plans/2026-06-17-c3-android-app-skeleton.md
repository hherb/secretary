# C.3 Android slice 6 — `:app` walking skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first runnable Android app target — a Compose `:app` module that wires the real `makeVaultSync` into an unlock/lock lifecycle over a staged `golden_vault_001` copy and hosts the slice-5 `SyncScreen`, with an instrumented smoke that closes the `makeVaultSync` + real-coordinator `syncAtUnlock` gap.

**Architecture:** New `:app` (`com.android.application`) depending on `:sync-ui`, `:kit`, `:vault-access`. Production `AppVaultProvisioning` stages a writable golden-vault copy into `filesDir`; a single `MainActivity` routes `Unlock → Sync`; unlock builds `makeVaultSync` on the main thread, starts the monitor, awaits a silent `syncAtUnlock`, then hosts `SyncScreen`. Pure helpers (uuid parse, state-dir) are host-tested (JUnit5); the real FFI wiring is proven by an emulator instrumented smoke. Sync-only — Android has no open/browse port yet.

**Tech Stack:** Kotlin, Jetpack Compose (BOM 2025.05.00), AndroidX Lifecycle, Gradle KTS, JUnit5 (host) + AndroidJUnit4/Espresso (instrumented), uniffi `.so` via `:kit`.

**Spec:** `docs/superpowers/specs/2026-06-17-c3-android-app-skeleton-design.md`

---

## File Structure

```
android/settings.gradle.kts                                   # MODIFY: include(":app")
android/build.gradle.kts                                      # MODIFY: add com.android.application plugin (apply false)
android/app/build.gradle.kts                                  # CREATE: application module + asset staging task
android/app/.gitignore                                        # CREATE: untrack staged assets
android/app/src/main/AndroidManifest.xml                      # CREATE: application + MainActivity launcher
android/app/src/main/res/values/strings.xml                   # CREATE: app_name
android/app/src/main/kotlin/org/secretary/app/VaultUuidParsing.kt       # CREATE: pure hex→bytes (Task 2)
android/app/src/main/kotlin/org/secretary/app/AppSyncStateDir.kt        # CREATE: pure syncStateDir(base) (Task 3)
android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt   # CREATE: asset staging + uuid (Task 4)
android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt           # CREATE: Compose unlock surface (Task 6)
android/app/src/main/kotlin/org/secretary/app/AppRoot.kt                # CREATE: routing + lifecycle + orchestration (Task 6)
android/app/src/main/kotlin/org/secretary/app/MainActivity.kt           # CREATE: activity + FLAG_SECURE (Task 6)
android/app/src/test/kotlin/org/secretary/app/VaultUuidParsingTest.kt   # CREATE (Task 2)
android/app/src/test/kotlin/org/secretary/app/AppSyncStateDirTest.kt    # CREATE (Task 3)
android/app/src/androidTest/kotlin/org/secretary/app/MakeVaultSyncSmokeTest.kt   # CREATE (Task 7)
android/sync-ui/src/main/kotlin/org/secretary/sync/ui/VaultSyncViewModel.kt      # MODIFY: syncAtUnlock → suspend (Task 5)
android/sync-ui/src/test/kotlin/org/secretary/sync/ui/VaultSyncViewModelTest.kt  # MODIFY: add suspend test (Task 5)
README.md                                                     # MODIFY (Task 8)
ROADMAP.md                                                    # MODIFY (Task 8)
```

All commands assume the worktree root `/Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton`. Gradle commands run from its `android/` subdir. The arm64 emulator must be running for instrumented tasks; host tasks need no emulator/NDK.

---

## Task 1: `:app` module scaffold

**Files:**
- Modify: `android/build.gradle.kts`
- Modify: `android/settings.gradle.kts`
- Create: `android/app/build.gradle.kts`
- Create: `android/app/.gitignore`
- Create: `android/app/src/main/AndroidManifest.xml`
- Create: `android/app/src/main/res/values/strings.xml`

- [ ] **Step 1: Register the application plugin at the root**

Edit `android/build.gradle.kts` — add the application plugin alongside the existing library plugin:

```kotlin
plugins {
    // :vault-access is pure-JVM Kotlin; :kit is an Android library (uniffi adapter + jniLibs).
    kotlin("jvm") version "2.2.10" apply false
    kotlin("android") version "2.2.10" apply false
    id("com.android.library") version "8.13.2" apply false
    // :app is the runnable walking skeleton (slice 6).
    id("com.android.application") version "8.13.2" apply false
    // :sync-ui is a Compose Android library; the Compose compiler ships with Kotlin 2.x as a plugin.
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
}
```

- [ ] **Step 2: Include `:app` in the settings**

Edit `android/settings.gradle.kts` — append after `include(":sync-ui")`:

```kotlin
include(":app")
```

- [ ] **Step 3: Create the `:app` build script**

Create `android/app/build.gradle.kts`:

```kotlin
// Repo root (the cargo workspace) is the parent of the `android/` gradle root project.
val repoRoot: java.io.File = rootProject.projectDir.parentFile

plugins {
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.secretary.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.secretary.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Kotlin/JVM 21 bytecode (matches :vault-access / :kit / :sync-ui).
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
    }

    // Host JVM unit tests use JUnit 5 (matches the sibling modules).
    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
}

kotlin {
    jvmToolchain(21)
}

// Same test-tooling version forces as :sync-ui: the API-36 emulator needs Espresso 3.7.0
// (InputManager reflection removed in API 35+), and the espresso-pulled coroutines BOM
// constraint must yield to the workspace 1.8.0 production pin. See :sync-ui/build.gradle.kts
// for the full rationale.
configurations.configureEach {
    resolutionStrategy {
        force("androidx.test.espresso:espresso-core:3.7.0")
        force("androidx.test.espresso:espresso-idling-resource:3.7.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.0")
        force("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")
    }
}

dependencies {
    // :kit brings the real makeVaultSync + the packaged arm64 .so (transitively into the APK).
    // :sync-ui brings SyncScreen + VaultSyncViewModel. :vault-access (the pure model) is
    // transitive via both, declared explicitly for the model types used in the unlock orchestration.
    implementation(project(":kit"))
    implementation(project(":sync-ui"))
    implementation(project(":vault-access"))

    val composeBom = platform("androidx.compose:compose-bom:2025.05.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.activity:activity-compose")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android") {
        version { strictly("1.8.0") }
    }

    // --- Host JUnit5 unit tests (pure helpers) ---
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // --- Instrumented tests (real .so makeVaultSync smoke on the emulator) ---
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
}

// --- Production golden-vault asset staging ---------------------------------
//
// Stage golden_vault_001 (+ its inputs JSON) from the canonical core/tests/data location
// into the app's MAIN assets so the runnable demo bundles a vault to open. The destination
// is gitignored: the tracked fixture stays the single source of truth (no committed duplicate
// of a frozen KAT), mirroring :kit's androidTest staging and iOS's bundle staging. `.DS_Store`
// is excluded so a macOS finder artifact never ships in the APK. `Copy` tracks from/into as
// inputs/outputs, so Gradle skips the copy when the fixture is unchanged.
val stageGoldenVaultForApp by tasks.registering(Copy::class) {
    val fixtureRoot = repoRoot.resolve("core/tests/data")
    from(fixtureRoot.resolve("golden_vault_001")) {
        into("golden_vault_001")
        exclude("**/.DS_Store")
    }
    from(fixtureRoot.resolve("golden_vault_001_inputs.json"))
    into(layout.projectDirectory.dir("src/main/assets"))
}

// The main asset merge (both debug and release) must see the staged fixture.
tasks.matching { it.name == "mergeDebugAssets" || it.name == "mergeReleaseAssets" }.configureEach {
    dependsOn(stageGoldenVaultForApp)
}
```

- [ ] **Step 4: Gitignore the staged assets**

Create `android/app/.gitignore`:

```
# Golden vault is staged from core/tests/data at build time (single source of truth) — never committed.
/src/main/assets/golden_vault_001/
/src/main/assets/golden_vault_001_inputs.json
```

- [ ] **Step 5: Create the manifest**

Create `android/app/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <application
        android:allowBackup="false"
        android:label="@string/app_name"
        android:theme="@android:style/Theme.Material.NoActionBar">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
```

- [ ] **Step 6: Create the string resource**

Create `android/app/src/main/res/values/strings.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Secretary</string>
</resources>
```

- [ ] **Step 7: Verify the module configures and assets stage**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:dependencies --configuration debugRuntimeClasspath -q`
Expected: succeeds, listing `:kit`, `:sync-ui`, `:vault-access`, Compose, lifecycle artifacts (no version-conflict error).

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:stageGoldenVaultForApp -q && ls src/../app/src/main/assets/golden_vault_001/manifest.cbor.enc`
Expected: the staged file exists (golden vault copied into the app assets).

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add android/build.gradle.kts android/settings.gradle.kts android/app/build.gradle.kts \
  android/app/.gitignore android/app/src/main/AndroidManifest.xml android/app/src/main/res/values/strings.xml
git commit -m "feat(android-app): scaffold :app module + golden-vault asset staging

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Pure vault-UUID hex parsing

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/VaultUuidParsing.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/VaultUuidParsingTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/app/src/test/kotlin/org/secretary/app/VaultUuidParsingTest.kt`:

```kotlin
package org.secretary.app

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class VaultUuidParsingTest {

    @Test
    fun parsesDashedHexInto16Bytes() {
        val uuid = parseVaultUuidHex("00112233-4455-6677-8899-aabbccddeeff")
        val expected = byteArrayOf(
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77.toByte(),
            0x88.toByte(), 0x99.toByte(), 0xaa.toByte(), 0xbb.toByte(),
            0xcc.toByte(), 0xdd.toByte(), 0xee.toByte(), 0xff.toByte(),
        )
        assertArrayEquals(expected, uuid)
    }

    @Test
    fun rejectsWrongLength() {
        assertThrows(IllegalArgumentException::class.java) {
            parseVaultUuidHex("00112233")
        }
    }

    @Test
    fun rejectsNonHex() {
        assertThrows(IllegalArgumentException::class.java) {
            parseVaultUuidHex("zz112233-4455-6677-8899-aabbccddeeff")
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.VaultUuidParsingTest"`
Expected: FAIL — `parseVaultUuidHex` unresolved (compilation error).

- [ ] **Step 3: Write minimal implementation**

Create `android/app/src/main/kotlin/org/secretary/app/VaultUuidParsing.kt`:

```kotlin
package org.secretary.app

private const val UUID_BYTES = 16

/**
 * Parses a vault UUID from its canonical dashed-hex form (e.g.
 * "00112233-4455-6677-8899-aabbccddeeff") into the 16 raw bytes the sync FFI expects.
 *
 * Pure (no Android dependency) so it is host-testable. The single source of truth for the
 * golden vault's UUID is the bundled `golden_vault_001_inputs.json`; [AppVaultProvisioning]
 * reads that JSON and calls this to decode it — there is no hardcoded UUID constant.
 *
 * @throws IllegalArgumentException if, after removing dashes, the string is not exactly 32
 *   hex digits.
 */
fun parseVaultUuidHex(dashedHex: String): ByteArray {
    val hex = dashedHex.replace("-", "")
    require(hex.length == UUID_BYTES * 2) {
        "vault UUID must be $UUID_BYTES bytes (32 hex digits), got ${hex.length} digits"
    }
    return ByteArray(UUID_BYTES) { i ->
        val byteHex = hex.substring(i * 2, i * 2 + 2)
        byteHex.toIntOrNull(16)?.toByte()
            ?: throw IllegalArgumentException("vault UUID contains non-hex characters: '$byteHex'")
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.VaultUuidParsingTest"`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add android/app/src/main/kotlin/org/secretary/app/VaultUuidParsing.kt \
  android/app/src/test/kotlin/org/secretary/app/VaultUuidParsingTest.kt
git commit -m "feat(android-app): pure vault-UUID hex parse + host tests

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Pure sync-state-dir resolver

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/AppSyncStateDir.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/AppSyncStateDirTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/app/src/test/kotlin/org/secretary/app/AppSyncStateDirTest.kt`:

```kotlin
package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File

class AppSyncStateDirTest {

    @Test
    fun resolvesSyncStateSubdirOfBase() {
        val base = File("/data/user/0/org.secretary.app/files")
        assertEquals(File(base, "sync-state"), syncStateDir(base))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.AppSyncStateDirTest"`
Expected: FAIL — `syncStateDir` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/app/src/main/kotlin/org/secretary/app/AppSyncStateDir.kt`:

```kotlin
package org.secretary.app

import java.io.File

/** Subdirectory of the app's private storage that holds per-vault sync state. */
private const val SYNC_STATE_DIRNAME = "sync-state"

/**
 * Resolves the sync-state directory under a given base (the app's `filesDir` in production).
 * Pure (no Android dependency) so the base→subdir mapping is host-testable; the production
 * caller passes `context.filesDir` and is responsible for creating the directory.
 */
fun syncStateDir(base: File): File = File(base, SYNC_STATE_DIRNAME)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.AppSyncStateDirTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add android/app/src/main/kotlin/org/secretary/app/AppSyncStateDir.kt \
  android/app/src/test/kotlin/org/secretary/app/AppSyncStateDirTest.kt
git commit -m "feat(android-app): pure sync-state-dir resolver + host test

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Production vault provisioning

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt`

This object needs `Context`/`AssetManager`, so it is not host-unit-tested; its behavior is
proven end-to-end by the Task 7 instrumented smoke (which stages through it). The recursive
asset-copy mirrors `:kit`'s `GoldenVaultStaging.copyAsset` (the empty-children == leaf-file
heuristic is exact for this fixture, which has no empty directories).

- [ ] **Step 1: Write the implementation**

Create `android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt`:

```kotlin
package org.secretary.app

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * Stages a WRITABLE copy of the bundled read-only golden_vault_001 into the app's private
 * storage on first launch (the asset is read-only; a sync pass rewrites manifest/blocks).
 * Never mutates the bundled asset, so the frozen KAT is never touched. Idempotent. Mirror of
 * iOS `AppVaultProvisioning.swift`.
 *
 * The vault + its inputs JSON are bundled by the `stageGoldenVaultForApp` Gradle task from the
 * canonical `core/tests/data` location (see build.gradle.kts).
 */
object AppVaultProvisioning {
    private const val VAULT_ASSET = "golden_vault_001"
    private const val INPUTS_ASSET = "golden_vault_001_inputs.json"

    /** Returns the writable staged vault dir, copying it from assets on first call. */
    fun stageGoldenVault(context: Context): File {
        // A present vault asset dir has children; empty children here means it was never
        // bundled (the stage task didn't run), not a leaf file at the top level.
        check(!context.assets.list(VAULT_ASSET).isNullOrEmpty()) {
            "$VAULT_ASSET not bundled in the APK — the stageGoldenVaultForApp Gradle task did not run"
        }
        val dest = File(context.filesDir, VAULT_ASSET)
        if (dest.exists()) return dest
        copyAsset(context, VAULT_ASSET, dest)
        return dest
    }

    /** The pinned 16-byte vault UUID, parsed from the bundled inputs JSON (single source of truth). */
    fun goldenVaultUuid(context: Context): ByteArray {
        val json = try {
            context.assets.open(INPUTS_ASSET).bufferedReader().use { it.readText() }
        } catch (e: IOException) {
            throw IllegalStateException(
                "$INPUTS_ASSET not bundled in the APK — the stageGoldenVaultForApp Gradle task did not run",
                e,
            )
        }
        return parseVaultUuidHex(JSONObject(json).getString("vault_uuid"))
    }

    // AssetManager.list() returns the children of a directory, or an empty array for a leaf
    // file. The golden vault has no empty directories, so empty-children == file. A genuinely
    // empty asset directory would be mis-staged as a leaf file, but this pinned fixture has none.
    private fun copyAsset(context: Context, assetPath: String, dest: File) {
        val children = context.assets.list(assetPath) ?: emptyArray()
        if (children.isEmpty()) {
            dest.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                dest.outputStream().use { input.copyTo(it) }
            }
        } else {
            dest.mkdirs()
            for (child in children) copyAsset(context, "$assetPath/$child", File(dest, child))
        }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:compileDebugKotlin -q`
Expected: BUILD SUCCESSFUL (no emulator needed to compile).

- [ ] **Step 3: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add android/app/src/main/kotlin/org/secretary/app/AppVaultProvisioning.kt
git commit -m "feat(android-app): production golden-vault provisioning (stage + uuid)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Make `VaultSyncViewModel.syncAtUnlock` awaitable

**Files:**
- Modify: `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/VaultSyncViewModel.kt`
- Test: `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/VaultSyncViewModelTest.kt`

The slice-5 `syncAtUnlock` was a fire-and-forget stub "wired by a future :app unlock hook". The
app is that hook, and it must zeroize the unlock password only **after** the pass completes (to
avoid a use-after-zero race with the async Argon2id re-open). So `syncAtUnlock` becomes a
`suspend` function the caller can await. No other caller exists, so this is a clean replacement
(not a second method).

- [ ] **Step 1: Write the failing test**

Add to `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/VaultSyncViewModelTest.kt` (a new `@Test` inside the existing class; reuse the existing `viewModel(outcome)` helper and `dispatcher`):

```kotlin
    @Test
    fun syncAtUnlock_awaitsPass_andForwardsBadge() = runTest(dispatcher) {
        val vm = viewModel(SyncOutcome.AppliedAutomatically)

        // Returns only after the silent pass settles (suspend, not fire-and-forget).
        vm.syncAtUnlock("pw".toByteArray())

        // A clean silent pass leaves no error and clears review state.
        assertNull(vm.lastError.value)
        assertFalse(vm.reviewNeeded.value)
    }
```

If `assertNull` / `assertFalse` are not already imported in this file, add:

```kotlin
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :sync-ui:testDebugUnitTest --tests "org.secretary.sync.ui.VaultSyncViewModelTest"`
Expected: FAIL — calling `vm.syncAtUnlock(...)` from a `suspend` test context where the method is currently non-suspend launches into `viewModelScope` and the assertions race / the signature is `Unit` (no suspension). (If it spuriously passes due to the launch resolving on the test dispatcher, the change in Step 3 still makes the await explicit and the test the contract.)

- [ ] **Step 3: Change `syncAtUnlock` to suspend + await the model**

In `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/VaultSyncViewModel.kt`, replace the existing `syncAtUnlock` method (the fire-and-forget `viewModelScope.launch { model.syncAtUnlock(password) }` version) with:

```kotlin
    /**
     * Silent sync immediately after a password unlock (trigger-1). Suspends until the pass
     * settles so the caller (the :app unlock orchestration) can zeroize the password buffer
     * only AFTER the async Argon2id re-open has consumed it — avoiding a use-after-zero race.
     * A conflict only raises the review badge (the password is dropped, no sheet).
     *
     * Secret hygiene: [password] is forwarded straight to the model and never stored on this VM.
     * The VM deliberately does NOT zeroize the buffer; the owning caller zeroizes after this
     * suspend call returns (it is never reused for a conflict resolve on the silent path).
     */
    suspend fun syncAtUnlock(password: ByteArray) {
        model.syncAtUnlock(password)
    }
```

Remove the now-unused `kotlinx.coroutines.launch` import only if no other method in the file still uses `viewModelScope.launch` (several do — `submitPassword`, `resolve`, `refreshStatus` — so the import stays).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :sync-ui:testDebugUnitTest --tests "org.secretary.sync.ui.VaultSyncViewModelTest"`
Expected: PASS (all VM tests including the new one).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add android/sync-ui/src/main/kotlin/org/secretary/sync/ui/VaultSyncViewModel.kt \
  android/sync-ui/src/test/kotlin/org/secretary/sync/ui/VaultSyncViewModelTest.kt
git commit -m "refactor(android-sync-ui): make VaultSyncViewModel.syncAtUnlock awaitable

The :app unlock hook must zeroize the unlock password only after the silent
pass completes; a suspend syncAtUnlock lets the caller await. No other caller
existed (it was a slice-5 stub for the future app).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Unlock screen, app routing, lifecycle & MainActivity

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`
- Create: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`
- Create: `android/app/src/main/kotlin/org/secretary/app/MainActivity.kt`

This is the Compose glue. Per the approved spec, the new unlock surface is NOT separately
UI-tested (the slice-5 `SyncScreen` is already covered in `:sync-ui`; the genuinely-novel
runtime behavior — real FFI wiring + lifecycle — is proven by the Task 7 instrumented smoke).
Verification here is compilation + assembling a debug APK.

- [ ] **Step 1: Create the unlock screen**

Create `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`:

```kotlin
package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * Minimal unlock surface for the walking skeleton: a masked password field + an "Unlock & Sync"
 * button. On submit it hands the password (UTF-8 bytes) to [onUnlock], which runs the real
 * makeVaultSync + silent sync (see [AppRoot]).
 *
 * Password hygiene: Compose `TextField` is String-backed (like iOS `SecureField`), so the typed
 * String lingers until GC — acceptable for this demo skeleton. The byte buffer derived on submit
 * IS zeroized by [AppRoot] after the pass. No vault plaintext is ever shown (sync-only; no browse).
 */
@Composable
fun UnlockScreen(onUnlock: (ByteArray) -> Unit) {
    var password by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Secretary — demo vault")
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Vault password") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { onUnlock(password.toByteArray(Charsets.UTF_8)) },
            enabled = password.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Unlock & Sync")
        }
    }
}
```

- [ ] **Step 2: Create the app root (routing + lifecycle + orchestration)**

Create `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`:

```kotlin
package org.secretary.app

import android.content.Context
import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.launch
import org.secretary.sync.ChangeDetectionMonitor
import org.secretary.sync.makeVaultSync
import org.secretary.sync.ui.SyncScreen
import org.secretary.sync.ui.VaultSyncViewModel

private const val TAG = "AppRoot"

/** The app's two screens; Sync carries the live model + monitor for the unlocked session. */
private sealed interface Route {
    data object Unlock : Route
    data class Sync(
        val viewModel: VaultSyncViewModel,
        val monitor: ChangeDetectionMonitor,
    ) : Route
}

/**
 * Top-level routing for the walking skeleton: Unlock → Sync. On unlock it builds the REAL
 * makeVaultSync pair on the main thread (Compose runs on main), starts the folder monitor
 * (advisory — a failed start is logged, not fatal), awaits a silent syncAtUnlock, zeroizes the
 * password, then routes to the slice-5 SyncScreen. On background (ON_STOP) it stops the monitor
 * and returns to Unlock, dropping the session (mirrors iOS scenePhase == .background; Android has
 * no session to resume since the password is transient per pass).
 */
@Composable
fun AppRoot() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var route by remember { mutableStateOf<Route>(Route.Unlock) }

    // Background → stop monitor + return to Unlock, dropping the model.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, route) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                (route as? Route.Sync)?.let { it.monitor.stop() }
                route = Route.Unlock
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    when (val r = route) {
        is Route.Unlock -> UnlockScreen(onUnlock = { password ->
            scope.launch {
                route = unlockAndSync(context, password)
            }
        })
        is Route.Sync -> SyncScreen(viewModel = r.viewModel)
    }
}

/**
 * Builds makeVaultSync (main thread), starts the monitor, awaits the silent unlock pass, zeroizes
 * the password, kicks a best-effort status refresh (for the "synced N ago" label), and returns the
 * Sync route. Called from a main-dispatched coroutine (the heavy Argon2id work hops to IO inside
 * the sync port). The password buffer is zeroized only after the awaited pass consumes it.
 */
private suspend fun unlockAndSync(context: Context, password: ByteArray): Route {
    val folder = AppVaultProvisioning.stageGoldenVault(context)
    val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
    val uuid = AppVaultProvisioning.goldenVaultUuid(context)

    val (model, monitor) = makeVaultSync(folder, stateDir, uuid)
    try {
        monitor.start()
    } catch (e: Exception) {
        // Advisory-blind detection (badge falls back to manual "Sync now"); not fatal.
        Log.w(TAG, "folder-change monitor failed to start", e)
    }

    val viewModel = VaultSyncViewModel(model)
    try {
        viewModel.syncAtUnlock(password)
    } finally {
        password.fill(0) // zeroize after the pass has consumed it
    }
    viewModel.refreshStatus() // best-effort "synced N ago" label; reactive via the badge flow

    return Route.Sync(viewModel, monitor)
}
```

- [ ] **Step 3: Create MainActivity (FLAG_SECURE + setContent)**

Create `android/app/src/main/kotlin/org/secretary/app/MainActivity.kt`:

```kotlin
package org.secretary.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface

/**
 * The single Activity for the walking skeleton. Sets FLAG_SECURE so the password field never
 * appears in screenshots or the app-switcher snapshot (the cheap stand-in for iOS's PrivacyCover;
 * a full cover is deferred with browse). Hosts the Compose [AppRoot].
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent {
            MaterialTheme {
                Surface {
                    AppRoot()
                }
            }
        }
    }
}
```

- [ ] **Step 4: Verify it compiles and a debug APK assembles**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL. (This also runs `cargoNdkBuildArm64` via `:kit` to package the `.so`, and stages the golden vault into assets — first run is slower.)

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt \
  android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
  android/app/src/main/kotlin/org/secretary/app/MainActivity.kt
git commit -m "feat(android-app): unlock screen + routing + lifecycle wiring over makeVaultSync

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Instrumented `makeVaultSync` smoke (real `.so`)

**Files:**
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/MakeVaultSyncSmokeTest.kt`

This is the headline proof: the production `AppVaultProvisioning` → `makeVaultSync` (Looper-gated
factory) → `VaultSyncModel.syncAtUnlock` over the REAL `SyncCoordinator` and native `.so`,
asserting a clean badge on the happy path and a surfaced error on wrong password. `makeVaultSync`
must run on the main thread (Looper check); the test drives it via `runOnMainSync` and awaits the
suspend pass with `runBlocking`. Requires the arm64 emulator running.

- [ ] **Step 1: Write the test**

Create `android/app/src/androidTest/kotlin/org/secretary/app/MakeVaultSyncSmokeTest.kt`:

```kotlin
package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.ChangeDetectionMonitor
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.VaultSyncModel
import org.secretary.sync.makeVaultSync
import java.io.File

/**
 * The first on-device exercise of the FULL app wiring: production provisioning → makeVaultSync
 * (Looper-gated factory) → VaultSyncModel.syncAtUnlock over the REAL SyncCoordinator + native
 * libsecretary_ffi_uniffi.so. Host tests (fakes) cannot touch makeVaultSync or the .so. This
 * complements :kit's SyncRoundTripInstrumentedTest, which proves only the raw port + bare
 * coordinator runPass — bypassing both the factory and the model state machine asserted here.
 *
 * Single-device golden vault: the first pass against a fresh state dir is an AppliedAutomatically
 * fast-forward (characterized in :kit), a clean arm — never ConflictsPending.
 */
@RunWith(AndroidJUnit4::class)
class MakeVaultSyncSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    // The published golden-vault KAT password — not a real secret, so not zeroized here.
    private val goldenPassword = "correct horse battery staple"

    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        // Reset provisioning so each test stages fresh (stageGoldenVault is idempotent on filesDir).
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    /** Build the real model+monitor on the main thread (makeVaultSync fast-fails off-main). */
    private fun buildOnMain(): Pair<VaultSyncModel, ChangeDetectionMonitor> {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val stateDir = File(context.cacheDir, "state-${System.nanoTime()}").apply { mkdirs() }
        toClean += stateDir
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)
        lateinit var pair: Pair<VaultSyncModel, ChangeDetectionMonitor>
        instrumentation.runOnMainSync {
            pair = makeVaultSync(folder, stateDir, uuid)
        }
        return pair
    }

    @Test
    fun syncAtUnlock_correctPassword_reachesSyncedBadge() = runBlocking {
        val (model, monitor) = buildOnMain()
        instrumentation.runOnMainSync { monitor.start() }

        model.syncAtUnlock(goldenPassword.toByteArray())

        // Clean silent pass: no error, review cleared.
        assertNull("clean pass surfaces no error", model.lastError.value)
        assertFalse("clean pass clears review", model.reviewNeeded.value)

        // The Synced label needs a status read (the model does not refresh inside a pass).
        model.refreshStatus()
        assertTrue(
            "after a clean pass + status refresh the badge is Synced, was ${model.badge.value}",
            model.badge.value is SyncBadgeState.Synced,
        )

        instrumentation.runOnMainSync { monitor.stop() }
    }

    @Test
    fun syncAtUnlock_wrongPassword_surfacesError() = runBlocking {
        val (model, monitor) = buildOnMain()
        instrumentation.runOnMainSync { monitor.start() }

        model.syncAtUnlock("definitely-the-wrong-password".toByteArray())

        assertNotNull("wrong password surfaces a VaultSyncError", model.lastError.value)
        assertFalse(
            "a failed pass does not reach Synced, was ${model.badge.value}",
            model.badge.value is SyncBadgeState.Synced,
        )

        instrumentation.runOnMainSync { monitor.stop() }
    }
}
```

- [ ] **Step 2: Run the instrumented test on the emulator**

Ensure an arm64 emulator is running (`Medium_Phone_API_36.1` or similar), then run:

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest
```

Expected: BUILD SUCCESSFUL, 2 tests passed on the connected device.

If the emulator is not running, start it first (absolute paths — adb/emulator are not on the bare PATH):

```bash
"$HOME/Library/Android/sdk/emulator/emulator" -avd Medium_Phone_API_36.1 -no-snapshot -no-boot-anim &
"$HOME/Library/Android/sdk/platform-tools/adb" wait-for-device
```

- [ ] **Step 3: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add android/app/src/androidTest/kotlin/org/secretary/app/MakeVaultSyncSmokeTest.kt
git commit -m "test(android-app): instrumented makeVaultSync + syncAtUnlock smoke (real .so)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Docs — README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Locate the Android C.3 status lines**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton && grep -n -i 'slice 5\|sync-ui\|Compose sync render\|Android' README.md ROADMAP.md`
Expected: the slice-5 status lines that need a slice-6 follow-on.

- [ ] **Step 2: Update README.md**

Add a brief dot-point under the Android status section noting the new runnable `:app` walking
skeleton: first runnable Android app target — Compose `:app` hosting the slice-5 `SyncScreen` over
the real `makeVaultSync` lifecycle (unlock → silent sync → badge), proven by an on-device
`makeVaultSync` smoke against a staged `golden_vault_001`. Keep it brief (per the README style:
dot points, no test-count walls). Match the existing surrounding phrasing.

- [ ] **Step 3: Update ROADMAP.md**

Mark the Android `:app` walking skeleton (slice 6) shipped in the C.3 section, mirroring how
slice 5 was marked. Note that record browse/edit remains deferred (needs a vault open port) and
that the slice is sync-only. Match the existing checkbox/▢/✅ convention used in the file.

- [ ] **Step 4: Run the full host gauntlet (regression check)**

Run: `cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && ./gradlew :app:test :sync-ui:test :vault-access:test :kit:testDebugUnitTest`
Expected: BUILD SUCCESSFUL, all host suites green (no warnings).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git add README.md ROADMAP.md
git commit -m "docs: C.3 Android slice 6 — :app walking skeleton shipped

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (whole-slice gauntlet)

Run before opening the PR:

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android
./gradlew :app:test :sync-ui:test :vault-access:test :kit:testDebugUnitTest          # host JUnit5 green
PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest                                            # 2 instrumented tests green
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # expect empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           # expect empty
```

Both guardrail greps must be empty (additive `android/` + `docs/` + README/ROADMAP only; no
`core/`/`ffi/`/`ios/`/format change). The one non-`:app` source change is the `:sync-ui`
`syncAtUnlock` → suspend refactor (Task 5), under `android/`.
