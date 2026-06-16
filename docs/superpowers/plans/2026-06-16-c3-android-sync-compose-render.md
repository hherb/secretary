# C.3 Android slice 5 — Compose sync render — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render the slice-4 `VaultSyncModel` on Android — a Compose sync badge, password sheet, and metadata-only conflict-resolution sheet, plus the thin `ViewModel` that bridges the model to Compose.

**Architecture:** A new FFI-free `:sync-ui` Compose library depending on `:vault-access` only. A thin `androidx.lifecycle.ViewModel` wraps the injected `VaultSyncModel`; three stateless/hoisted `@Composable`s render its state; pure render helpers compute labels/icons. Pure logic is host-tested (JUnit5); rendering is tested with instrumented Compose UI tests on the emulator, driven by a fake-backed model so no native `.so` is needed.

**Tech Stack:** Kotlin 2.2.10, AGP 8.13.2, Jetpack Compose (Material3), `androidx.lifecycle` ViewModel + coroutines, JUnit5 (host) + Compose UI test / AndroidJUnitRunner (instrumented).

**Spec:** `docs/superpowers/specs/2026-06-16-c3-android-sync-compose-render-design.md`

---

## Background the implementer needs

The slice-4 module `:vault-access` (pure Kotlin/JVM, package `org.secretary.sync`) already ships, **unchanged by this plan**, these public types:

- `class VaultSyncModel(coordinator: SyncCoordinator, wallClock: WallClock, monitorHook: SyncMonitorHook, vaultUuid: ByteArray?)` exposing read-only `StateFlow`s `badge`, `isSyncing`, `reviewNeeded`, `pendingConflict`, `lastError`, and `suspend` methods `syncAtUnlock(password)`, `runInteractivePass(password)`, `resolve(decisions, password)`, plus `cancelConflict()`, `pendingChangesRaised()`, `refreshStatus()`.
- `sealed interface SyncBadgeState { NeverSynced; data class Synced(val sinceMs: ULong); ChangesDetected; ReviewNeeded; Syncing }` and the pure `syncBadgeState(...)`.
- `class SyncCoordinator(port: VaultSyncPort, stateDir: String, vaultFolder: String)`.
- `interface VaultSyncPort { suspend fun status(...); suspend fun sync(...): SyncOutcome; suspend fun commitDecisions(...): SyncOutcome }`.
- `interface WallClock { fun nowMs(): ULong }`, `interface SyncMonitorHook { fun muteSelfWrite(); fun acknowledge() }`.
- `data class PendingConflict(val vetoes: List<SyncVeto>, val collisions: List<SyncCollision>)`.
- `data class SyncVeto(recordUuidHex, recordType, tags: List<String>, fieldNames: List<String>, localLastModMs: ULong, peerTombstonedAtMs: ULong, peerDeviceHex)`.
- `data class SyncCollision(recordUuidHex, fieldNames: List<String>)`, `data class SyncVetoDecision(recordUuidHex, keepLocal: Boolean)`.
- `fun collectDecisions(vetoes, overrides: Map<String, Boolean>): List<SyncVetoDecision>` (default `keepLocal = true` for any record absent from `overrides`).
- `sealed class VaultSyncError` with arms incl. `EvidenceStale`, `DecisionsIncomplete`, `WrongPasswordOrCorrupt`.
- `sealed interface SyncOutcome { NothingToDo; AppliedAutomatically; SilentMerge; MergedClean; RollbackRejected; class ConflictsPending(vetoes, collisions, manifestHash: ByteArray) }`.

**`:vault-access`'s own test fakes (`FakeVaultSyncPort`, etc.) live in its `src/test` and are NOT visible to `:sync-ui`.** This plan therefore defines its own tiny fakes against the public interfaces above — no change to `:vault-access`.

## File structure (what each new file is responsible for)

```
android/
  settings.gradle.kts                       MODIFY: include(":sync-ui")
  build.gradle.kts                          MODIFY: add kotlin compose plugin (apply false)
  gradle.properties                         MODIFY (if missing): android.useAndroidX=true
  sync-ui/
    build.gradle.kts                        NEW: Android library + Compose + deps
    src/main/AndroidManifest.xml            NEW: minimal manifest (namespace-only)
    src/main/kotlin/org/secretary/sync/ui/
      SyncRenderHelpers.kt                  NEW: relativeSyncedLabel / badgeLabel / badgeIcon (pure)
      VaultSyncViewModel.kt                 NEW: ViewModel bridge over VaultSyncModel
      SyncBadge.kt                          NEW: @Composable badge (5 states)
      SyncPasswordSheet.kt                  NEW: ModalBottomSheet + PasswordSheetContent
      ConflictResolutionSheet.kt            NEW: ModalBottomSheet + ConflictSheetContent
      SyncScreen.kt                         NEW: wires VM state into the three surfaces
    src/test/kotlin/org/secretary/sync/ui/
      SyncRenderHelpersTest.kt              NEW: host JUnit5
      VaultSyncViewModelTest.kt             NEW: host JUnit5 (+ inline fakes)
      Fakes.kt                              NEW: ScriptedSyncPort / ZeroWallClock / NoopHook (host)
    src/androidTest/kotlin/org/secretary/sync/ui/
      InstrumentedFakes.kt                  NEW: ScriptedSyncPort / ZeroWallClock / NoopHook (device)
      SyncBadgeUiTest.kt                    NEW: instrumented Compose UI test
      SyncPasswordSheetUiTest.kt            NEW: instrumented Compose UI test
      ConflictResolutionSheetUiTest.kt      NEW: instrumented Compose UI test
      SyncScreenUiTest.kt                   NEW: instrumented end-to-end UI test
```

**Naming convention for testable sheets:** each sheet is split into a thin `XxxSheet` (the `ModalBottomSheet` wrapper) and a pure `XxxSheetContent` (TextField/cards/buttons). Unit-rendering tests target `…SheetContent` directly (no bottom-sheet window/animation), while the `SyncScreen` end-to-end test exercises the full `…Sheet`.

**Emulator note:** instrumented tasks need a running emulator and `adb`/`emulator` on PATH. They live at `~/Library/Android/sdk/platform-tools` and `~/Library/Android/sdk/emulator`; prepend them for the run (shown in each instrumented step).

---

## Task 1: Scaffold the `:sync-ui` Compose module

**Files:**
- Modify: `android/settings.gradle.kts`
- Modify: `android/build.gradle.kts`
- Modify (if missing): `android/gradle.properties`
- Create: `android/sync-ui/build.gradle.kts`
- Create: `android/sync-ui/src/main/AndroidManifest.xml`

- [ ] **Step 1: Add the Compose plugin alias to the root build script**

In `android/build.gradle.kts`, add one line to the `plugins { }` block:

```kotlin
plugins {
    // :vault-access is pure-JVM Kotlin; :kit is an Android library (uniffi adapter + jniLibs).
    kotlin("jvm") version "2.2.10" apply false
    kotlin("android") version "2.2.10" apply false
    id("com.android.library") version "8.13.2" apply false
    // :sync-ui is a Compose Android library; the Compose compiler ships with Kotlin 2.x as a plugin.
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
}
```

- [ ] **Step 2: Register the module**

In `android/settings.gradle.kts`, add below `include(":kit")`:

```kotlin
include(":sync-ui")
```

- [ ] **Step 3: Ensure AndroidX is enabled**

Confirm `android/gradle.properties` contains `android.useAndroidX=true` (it should, since `:kit` already uses AndroidX test deps). If the file or line is absent, add:

```properties
android.useAndroidX=true
```

- [ ] **Step 4: Write the module build script**

Create `android/sync-ui/build.gradle.kts`:

```kotlin
plugins {
    id("com.android.library")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.secretary.sync.ui"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Kotlin/JVM 21 bytecode (matches :vault-access jvmToolchain(21) and :kit).
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        compose = true
    }

    // Host JVM unit tests use JUnit 5 (matches :vault-access / :kit).
    testOptions {
        unitTests.all { it.useJUnitPlatform() }
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    // FFI-free: the UI layer depends only on the pure model module, never on :kit.
    api(project(":vault-access"))

    // Compose BOM aligns all Compose artifact versions. If resolution fails, bump to the
    // current stable BOM — the Compose compiler is the Kotlin-bundled plugin (no separate pin).
    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // ViewModel + lifecycle-aware state collection in Compose.
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.activity:activity-compose:1.9.2")

    // coroutines pinned to match the rest of the workspace.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core") {
        version { strictly("1.8.0") }
    }

    // --- Host JUnit5 unit tests (helpers + ViewModel forwarding) ---
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test") {
        version { strictly("1.8.0") }
    }
    testImplementation("androidx.lifecycle:lifecycle-viewmodel:2.8.6")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // --- Instrumented Compose UI tests (run on the emulator) ---
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
```

- [ ] **Step 5: Add the minimal manifest**

Create `android/sync-ui/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" />
```

- [ ] **Step 6: Verify the module assembles**

Run: `cd android && ./gradlew :sync-ui:assembleDebug`
Expected: `BUILD SUCCESSFUL` (an empty Compose library compiles).

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-compose
git add android/settings.gradle.kts android/build.gradle.kts android/gradle.properties android/sync-ui/build.gradle.kts android/sync-ui/src/main/AndroidManifest.xml
git commit -m "feat(android-sync-ui): scaffold :sync-ui Compose module"
```

---

## Task 2: Pure render helpers

**Files:**
- Create: `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncRenderHelpers.kt`
- Test: `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/SyncRenderHelpersTest.kt`

- [ ] **Step 1: Write the failing test**

Create `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/SyncRenderHelpersTest.kt`:

```kotlin
package org.secretary.sync.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.sync.SyncBadgeState

class SyncRenderHelpersTest {
    private val now = 10_000_000uL // arbitrary fixed "now" in epoch millis

    @Test
    fun relativeLabel_underAMinute_isJustNow() {
        assertEquals("just now", relativeSyncedLabel(sinceMs = now - 30_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_minutes() {
        assertEquals("3m ago", relativeSyncedLabel(sinceMs = now - 180_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_hours() {
        assertEquals("2h ago", relativeSyncedLabel(sinceMs = now - 7_200_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_days() {
        assertEquals("3d ago", relativeSyncedLabel(sinceMs = now - 259_200_000uL, nowMs = now))
    }

    @Test
    fun relativeLabel_futureClampsToJustNow() {
        // Clock skew: a sinceMs ahead of now must not underflow ULong subtraction.
        assertEquals("just now", relativeSyncedLabel(sinceMs = now + 5_000uL, nowMs = now))
    }

    @Test
    fun badgeLabel_coversEveryState() {
        assertEquals("Never synced", badgeLabel(SyncBadgeState.NeverSynced, now))
        assertEquals("Synced 3m ago", badgeLabel(SyncBadgeState.Synced(now - 180_000uL), now))
        assertEquals("Changes detected", badgeLabel(SyncBadgeState.ChangesDetected, now))
        assertEquals("Review needed", badgeLabel(SyncBadgeState.ReviewNeeded, now))
        assertEquals("Syncing…", badgeLabel(SyncBadgeState.Syncing, now))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :sync-ui:testDebugUnitTest`
Expected: FAIL — `relativeSyncedLabel` / `badgeLabel` unresolved.

- [ ] **Step 3: Write the implementation**

Create `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncRenderHelpers.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Warning
import androidx.compose.ui.graphics.vector.ImageVector
import org.secretary.sync.SyncBadgeState

// Relative-time bucket thresholds (epoch-millis deltas). Named so no magic numbers leak into logic.
private const val MINUTE_MS = 60_000L
private const val HOUR_MS = 60 * MINUTE_MS
private const val DAY_MS = 24 * HOUR_MS
private const val JUST_NOW_CUTOFF_MS = MINUTE_MS // under a minute reads as "just now"

/**
 * Render a "synced N ago" relative-time label from a last-write timestamp and the current time,
 * both epoch millis. `nowMs` is a parameter (no real-clock call) so the function is pure and
 * host-tested; the composable passes `System.currentTimeMillis()` at render. A `sinceMs` ahead of
 * `nowMs` (clock skew) clamps to "just now" rather than underflowing the ULong subtraction.
 */
fun relativeSyncedLabel(sinceMs: ULong, nowMs: ULong): String {
    val deltaMs = if (nowMs >= sinceMs) (nowMs - sinceMs).toLong() else 0L
    return when {
        deltaMs < JUST_NOW_CUTOFF_MS -> "just now"
        deltaMs < HOUR_MS -> "${deltaMs / MINUTE_MS}m ago"
        deltaMs < DAY_MS -> "${deltaMs / HOUR_MS}h ago"
        else -> "${deltaMs / DAY_MS}d ago"
    }
}

/** Pure state → display string. The `Synced` arm delegates to [relativeSyncedLabel]. */
fun badgeLabel(state: SyncBadgeState, nowMs: ULong): String = when (state) {
    is SyncBadgeState.NeverSynced -> "Never synced"
    is SyncBadgeState.Synced -> "Synced ${relativeSyncedLabel(state.sinceMs, nowMs)}"
    is SyncBadgeState.ChangesDetected -> "Changes detected"
    is SyncBadgeState.ReviewNeeded -> "Review needed"
    is SyncBadgeState.Syncing -> "Syncing…"
}

/** Pure state → icon. (Syncing renders a spinner instead, so it maps to a placeholder icon.) */
fun badgeIcon(state: SyncBadgeState): ImageVector = when (state) {
    is SyncBadgeState.NeverSynced -> Icons.Filled.CloudOff
    is SyncBadgeState.Synced -> Icons.Filled.CheckCircle
    is SyncBadgeState.ChangesDetected -> Icons.Filled.Refresh
    is SyncBadgeState.ReviewNeeded -> Icons.Filled.Warning
    is SyncBadgeState.Syncing -> Icons.Filled.Sync
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :sync-ui:testDebugUnitTest`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncRenderHelpers.kt android/sync-ui/src/test/kotlin/org/secretary/sync/ui/SyncRenderHelpersTest.kt
git commit -m "feat(android-sync-ui): pure badge label/icon render helpers"
```

---

## Task 3: `VaultSyncViewModel` (host-tested bridge)

**Files:**
- Create: `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/VaultSyncViewModel.kt`
- Create: `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/Fakes.kt`
- Test: `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/VaultSyncViewModelTest.kt`

- [ ] **Step 1: Write the host fakes**

Create `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/Fakes.kt`:

```kotlin
package org.secretary.sync.ui

import org.secretary.sync.SyncMonitorHook
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncStatus
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncPort
import org.secretary.sync.WallClock

/** Returns a fixed outcome for sync/commit and an empty status. Records the password seen. */
class ScriptedSyncPort(
    private val syncOutcome: SyncOutcome,
    private val commitOutcome: SyncOutcome = syncOutcome,
) : VaultSyncPort {
    val passwords: MutableList<ByteArray> = mutableListOf()

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        SyncStatus(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null)

    override suspend fun sync(stateDir: String, vaultFolder: String, password: ByteArray, nowMs: ULong): SyncOutcome {
        passwords += password
        return syncOutcome
    }

    override suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome {
        passwords += password
        return commitOutcome
    }
}

class ZeroWallClock : WallClock {
    override fun nowMs(): ULong = 0uL
}

object NoopMonitorHook : SyncMonitorHook {
    override fun muteSelfWrite() {}
    override fun acknowledge() {}
}
```

- [ ] **Step 2: Write the failing ViewModel test**

Create `android/sync-ui/src/test/kotlin/org/secretary/sync/ui/VaultSyncViewModelTest.kt`:

```kotlin
package org.secretary.sync.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.SyncCoordinator
import org.secretary.sync.SyncOutcome
import org.secretary.sync.VaultSyncModel

@OptIn(ExperimentalCoroutinesApi::class)
class VaultSyncViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @BeforeEach fun setUp() = Dispatchers.setMain(dispatcher)
    @AfterEach fun tearDown() = Dispatchers.resetMain()

    private fun viewModel(outcome: SyncOutcome): VaultSyncViewModel {
        val port = ScriptedSyncPort(outcome)
        val coordinator = SyncCoordinator(port, stateDir = "s", vaultFolder = "f")
        val model = VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null)
        return VaultSyncViewModel(model)
    }

    @Test
    fun beginInteractiveSync_showsPasswordSheet() {
        val vm = viewModel(SyncOutcome.MergedClean)
        assertFalse(vm.passwordSheetVisible.value)
        vm.beginInteractiveSync()
        assertTrue(vm.passwordSheetVisible.value)
    }

    @Test
    fun submitPassword_cleanOutcome_hidesSheetAndForwardsBadge() = runTest(dispatcher) {
        val vm = viewModel(SyncOutcome.MergedClean)
        vm.beginInteractiveSync()
        vm.submitPassword("pw".toByteArray())
        advanceUntilIdle()
        assertFalse(vm.passwordSheetVisible.value)
        // A clean pass with no prior status leaves the badge at NeverSynced (status not refreshed).
        assertEquals(SyncBadgeState.NeverSynced, vm.badge.value)
    }

    @Test
    fun dismissPasswordSheet_hidesIt() {
        val vm = viewModel(SyncOutcome.MergedClean)
        vm.beginInteractiveSync()
        vm.dismissPasswordSheet()
        assertFalse(vm.passwordSheetVisible.value)
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd android && ./gradlew :sync-ui:testDebugUnitTest --tests '*VaultSyncViewModelTest'`
Expected: FAIL — `VaultSyncViewModel` unresolved.

- [ ] **Step 4: Write the ViewModel**

Create `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/VaultSyncViewModel.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncError
import org.secretary.sync.VaultSyncModel

/**
 * Thin Compose bridge over the host-tested [VaultSyncModel]. Holds NO badge/conflict logic — it
 * re-exposes the model's StateFlows for `collectAsStateWithLifecycle`, owns the password-sheet
 * presentation flag (the one piece of UI state the model deliberately omits), and launches the
 * model's suspend methods on [viewModelScope]. The injected [model] is built by `:kit`'s
 * `makeVaultSync` in production and over a fake port in tests; this class never touches the FFI.
 */
class VaultSyncViewModel(private val model: VaultSyncModel) : ViewModel() {
    val badge: StateFlow<SyncBadgeState> = model.badge
    val isSyncing: StateFlow<Boolean> = model.isSyncing
    val reviewNeeded: StateFlow<Boolean> = model.reviewNeeded
    val pendingConflict: StateFlow<PendingConflict?> = model.pendingConflict
    val lastError: StateFlow<VaultSyncError?> = model.lastError

    private val _passwordSheetVisible = MutableStateFlow(false)
    val passwordSheetVisible: StateFlow<Boolean> = _passwordSheetVisible.asStateFlow()

    /** Trigger-2 entry: present the password sheet (badge tap / "Sync now"). */
    fun beginInteractiveSync() {
        _passwordSheetVisible.value = true
    }

    /** Run one interactive pass with the re-entered password, then close the password sheet. */
    fun submitPassword(password: ByteArray) {
        viewModelScope.launch {
            model.runInteractivePass(password)
            _passwordSheetVisible.value = false
        }
    }

    /** Commit the user's veto decisions for the paused conflict. */
    fun resolve(decisions: List<SyncVetoDecision>, password: ByteArray) {
        viewModelScope.launch { model.resolve(decisions, password) }
    }

    /** Close the conflict sheet without writing; the review badge keeps nagging. */
    fun cancelConflict() = model.cancelConflict()

    /** Dismiss the password sheet without running a pass. */
    fun dismissPasswordSheet() {
        _passwordSheetVisible.value = false
    }

    /** Best-effort "synced N ago" label refresh (read before/after a pass, never during). */
    fun refreshStatus() {
        viewModelScope.launch { model.refreshStatus() }
    }

    /**
     * Silent sync immediately after a password unlock — for the FUTURE app's unlock hook. No UI in
     * this slice drives it; a conflict only raises the review badge (password dropped, no sheet).
     */
    fun syncAtUnlock(password: ByteArray) {
        viewModelScope.launch { model.syncAtUnlock(password) }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd android && ./gradlew :sync-ui:testDebugUnitTest`
Expected: PASS (all host tests, incl. Task 2).

- [ ] **Step 6: Commit**

```bash
git add android/sync-ui/src/main/kotlin/org/secretary/sync/ui/VaultSyncViewModel.kt android/sync-ui/src/test/kotlin/org/secretary/sync/ui/Fakes.kt android/sync-ui/src/test/kotlin/org/secretary/sync/ui/VaultSyncViewModelTest.kt
git commit -m "feat(android-sync-ui): VaultSyncViewModel bridge over VaultSyncModel"
```

---

## Task 4: `SyncBadge` composable + instrumented test

**Files:**
- Create: `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncBadge.kt`
- Create: `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncBadgeUiTest.kt`

- [ ] **Step 1: Write the failing instrumented test**

Create `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncBadgeUiTest.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.SyncBadgeState

@RunWith(AndroidJUnit4::class)
class SyncBadgeUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun reviewNeeded_showsLabel() {
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.ReviewNeeded, nowMs = 0uL, onTap = {})
        }
        composeRule.onNodeWithText("Review needed").assertIsDisplayed()
    }

    @Test
    fun syncing_showsSpinner_andTapIsDisabled() {
        var tapped = false
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.Syncing, nowMs = 0uL, onTap = { tapped = true })
        }
        composeRule.onNodeWithTag(SYNC_BADGE_SPINNER_TAG).assertIsDisplayed()
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).performClick()
        assertTrue("tap must be ignored while syncing", !tapped)
    }

    @Test
    fun synced_tap_invokesCallback() {
        var tapped = false
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.Synced(sinceMs = 0uL), nowMs = 0uL, onTap = { tapped = true })
        }
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).performClick()
        assertTrue(tapped)
    }
}
```

- [ ] **Step 2: Run to verify it fails (compile error)**

Run (emulator must be running):
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
```
Expected: FAIL — `SyncBadge` / `SYNC_BADGE_TAG` unresolved.

- [ ] **Step 3: Write the composable**

Create `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncBadge.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.secretary.sync.SyncBadgeState

const val SYNC_BADGE_TAG = "sync-badge"
const val SYNC_BADGE_SPINNER_TAG = "sync-badge-spinner"

private val BADGE_ICON_SIZE = 18.dp
private val BADGE_GAP = 6.dp

/**
 * The sync-status badge. Renders all five [SyncBadgeState]s as icon (or spinner for Syncing) +
 * a short label from [badgeLabel]. Tapping invokes [onTap], except while syncing (the badge is
 * advisory and a second pass cannot start mid-flight). [nowMs] feeds the relative "synced N ago"
 * label; the caller passes `System.currentTimeMillis().toULong()` at render.
 */
@Composable
fun SyncBadge(
    state: SyncBadgeState,
    nowMs: ULong,
    onTap: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isSyncing = state is SyncBadgeState.Syncing
    Row(
        modifier = modifier
            .testTag(SYNC_BADGE_TAG)
            .clickable(enabled = !isSyncing, onClick = onTap)
            .padding(BADGE_GAP),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(BADGE_GAP),
    ) {
        if (isSyncing) {
            CircularProgressIndicator(modifier = Modifier.size(BADGE_ICON_SIZE).testTag(SYNC_BADGE_SPINNER_TAG))
        } else {
            Icon(imageVector = badgeIcon(state), contentDescription = null, modifier = Modifier.size(BADGE_ICON_SIZE))
        }
        Text(text = badgeLabel(state, nowMs))
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
```
Expected: PASS (3 SyncBadge tests).

- [ ] **Step 5: Commit**

```bash
git add android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncBadge.kt android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncBadgeUiTest.kt
git commit -m "feat(android-sync-ui): SyncBadge composable + instrumented test"
```

---

## Task 5: `SyncPasswordSheet` composable + instrumented test

**Files:**
- Create: `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncPasswordSheet.kt`
- Create: `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncPasswordSheetUiTest.kt`

- [ ] **Step 1: Write the failing instrumented test (targets the inner content)**

Create `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncPasswordSheetUiTest.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.VaultSyncError

@RunWith(AndroidJUnit4::class)
class SyncPasswordSheetUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun typingAndSubmitting_forwardsPasswordBytes() {
        var captured: ByteArray? = null
        composeRule.setContent {
            PasswordSheetContent(error = null, onSubmit = { captured = it }, onDismiss = {})
        }
        composeRule.onNodeWithTag(PASSWORD_FIELD_TAG).performTextInput("hunter2")
        composeRule.onNodeWithText("Sync").performClick()
        assertNotNull(captured)
        assertTrue(captured!!.contentEquals("hunter2".toByteArray()))
    }

    @Test
    fun error_isShownInline() {
        composeRule.setContent {
            PasswordSheetContent(error = VaultSyncError.WrongPasswordOrCorrupt, onSubmit = {}, onDismiss = {})
        }
        composeRule.onNodeWithTag(PASSWORD_ERROR_TAG).assertIsDisplayed()
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest --tests '*SyncPasswordSheetUiTest'
```
Expected: FAIL — `PasswordSheetContent` unresolved. (Note: `connectedAndroidTest` ignores `--tests`; if so, the whole suite runs and these fail to compile.)

- [ ] **Step 3: Write the composable**

Create `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncPasswordSheet.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.secretary.sync.VaultSyncError

const val PASSWORD_FIELD_TAG = "password-field"
const val PASSWORD_ERROR_TAG = "password-error"

private val SHEET_PADDING = 16.dp
private val SHEET_GAP = 12.dp

/**
 * Bottom-sheet wrapper. Shown only when [visible]; dismissal routes through [onDismiss]. The
 * testable body lives in [PasswordSheetContent] so unit-rendering tests skip the sheet window.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncPasswordSheet(
    visible: Boolean,
    error: VaultSyncError?,
    onSubmit: (ByteArray) -> Unit,
    onDismiss: () -> Unit,
) {
    if (!visible) return
    ModalBottomSheet(onDismissRequest = onDismiss) {
        PasswordSheetContent(error = error, onSubmit = onSubmit, onDismiss = onDismiss)
    }
}

/**
 * The password entry body. The password lives only in transient composition state (NOT
 * `rememberSaveable`, so it is never persisted/restored), is encoded to a [ByteArray] on submit,
 * and the field is cleared on every terminal path. Inline error stays visible; the sheet stays
 * open on failure (the caller keeps [SyncPasswordSheet] visible until a terminal success).
 */
@Composable
fun PasswordSheetContent(
    error: VaultSyncError?,
    onSubmit: (ByteArray) -> Unit,
    onDismiss: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxWidth().padding(SHEET_PADDING),
        verticalArrangement = Arrangement.spacedBy(SHEET_GAP),
    ) {
        Text(text = "Enter your vault password to sync")
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().testTag(PASSWORD_FIELD_TAG),
        )
        if (error != null) {
            Text(
                text = syncErrorLabel(error),
                modifier = Modifier.testTag(PASSWORD_ERROR_TAG),
            )
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = { password = ""; onDismiss() }) { Text("Cancel") }
            Button(onClick = {
                val bytes = password.toByteArray()
                password = "" // clear ASAP; String is immutable so this is minimal-lifetime, not zeroize
                onSubmit(bytes)
            }) { Text("Sync") }
        }
    }
}
```

- [ ] **Step 4: Add the shared error-label helper**

Append to `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncRenderHelpers.kt`:

```kotlin
/** Pure, user-facing label for a sync error (used by both sheets' inline error rows). */
fun syncErrorLabel(error: org.secretary.sync.VaultSyncError): String = when (error) {
    is org.secretary.sync.VaultSyncError.WrongPasswordOrCorrupt -> "Wrong password, or the vault is corrupt."
    is org.secretary.sync.VaultSyncError.EvidenceStale -> "The vault changed while resolving — please try again."
    is org.secretary.sync.VaultSyncError.DecisionsIncomplete -> "Choose an option for every record."
    is org.secretary.sync.VaultSyncError.InProgress -> "A sync is already running."
    is org.secretary.sync.VaultSyncError.StateVaultMismatch -> "Sync state belongs to a different vault."
    is org.secretary.sync.VaultSyncError.StateCorrupt -> "Sync state is corrupt."
    is org.secretary.sync.VaultSyncError.NoPendingConflict -> "Nothing to resolve."
    is org.secretary.sync.VaultSyncError.InvalidArgument -> "Invalid sync request."
    is org.secretary.sync.VaultSyncError.Failed -> "Sync failed."
}
```

Add a host test for it in `SyncRenderHelpersTest.kt`:

```kotlin
    @Test
    fun syncErrorLabel_coversWrongPassword() {
        assertEquals(
            "Wrong password, or the vault is corrupt.",
            syncErrorLabel(org.secretary.sync.VaultSyncError.WrongPasswordOrCorrupt),
        )
    }
```

- [ ] **Step 5: Run host tests, then the instrumented test**

Run: `cd android && ./gradlew :sync-ui:testDebugUnitTest` → Expected: PASS.
Then:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
```
Expected: PASS (SyncBadge + SyncPasswordSheet tests).

- [ ] **Step 6: Commit**

```bash
git add android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncPasswordSheet.kt android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncRenderHelpers.kt android/sync-ui/src/test/kotlin/org/secretary/sync/ui/SyncRenderHelpersTest.kt android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncPasswordSheetUiTest.kt
git commit -m "feat(android-sync-ui): SyncPasswordSheet + inline error labels"
```

---

## Task 6: `ConflictResolutionSheet` composable + instrumented test

**Files:**
- Create: `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/ConflictResolutionSheet.kt`
- Create: `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/ConflictResolutionSheetUiTest.kt`

- [ ] **Step 1: Write the failing instrumented test**

Create `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/ConflictResolutionSheetUiTest.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncCollision
import org.secretary.sync.SyncVeto

@RunWith(AndroidJUnit4::class)
class ConflictResolutionSheetUiTest {
    @get:Rule val composeRule = createComposeRule()

    private val veto = SyncVeto(
        recordUuidHex = "aabb",
        recordType = "login",
        tags = listOf("work"),
        fieldNames = listOf("password"),
        localLastModMs = 100uL,
        peerTombstonedAtMs = 200uL,
        peerDeviceHex = "deadbeefcafef00d",
    )
    private val conflict = PendingConflict(
        vetoes = listOf(veto),
        collisions = listOf(SyncCollision(recordUuidHex = "ccdd", fieldNames = listOf("url"))),
    )

    @Test
    fun showsRecordMetadata_andDefaultsToKeepMine() {
        var decisions: List<org.secretary.sync.SyncVetoDecision>? = null
        composeRule.setContent {
            ConflictSheetContent(conflict = conflict, error = null, onResolve = { decisions = it }, onCancel = {})
        }
        composeRule.onNodeWithText("login").assertIsDisplayed()
        composeRule.onNodeWithText("Apply").performClick()
        // No toggle touched → default keepLocal = true for the single veto.
        assertEquals(listOf(org.secretary.sync.SyncVetoDecision("aabb", true)), decisions)
    }

    @Test
    fun acceptDelete_flipsDecisionToKeepLocalFalse() {
        var decisions: List<org.secretary.sync.SyncVetoDecision>? = null
        composeRule.setContent {
            ConflictSheetContent(conflict = conflict, error = null, onResolve = { decisions = it }, onCancel = {})
        }
        composeRule.onNodeWithText("Accept delete").performClick()
        composeRule.onNodeWithText("Apply").performClick()
        assertEquals(listOf(org.secretary.sync.SyncVetoDecision("aabb", false)), decisions)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
```
Expected: FAIL — `ConflictSheetContent` unresolved.

- [ ] **Step 3: Write the composable**

Create `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/ConflictResolutionSheet.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncVeto
import org.secretary.sync.VaultSyncError
import org.secretary.sync.collectDecisions

const val CONFLICT_APPLY_TAG = "conflict-apply"

private val CONFLICT_PADDING = 16.dp
private val CONFLICT_GAP = 12.dp
private const val PEER_DEVICE_PREFIX_LEN = 8 // show only the device-id prefix, never the full hex

/** Bottom-sheet wrapper; testable body is [ConflictSheetContent]. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConflictResolutionSheet(
    conflict: PendingConflict,
    error: VaultSyncError?,
    onResolve: (List<org.secretary.sync.SyncVetoDecision>) -> Unit,
    onCancel: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onCancel) {
        ConflictSheetContent(conflict = conflict, error = error, onResolve = onResolve, onCancel = onCancel)
    }
}

/**
 * Metadata-only conflict resolution, mirroring desktop D.1.15. One card per [SyncVeto] with a
 * per-record Keep-mine / Accept-delete choice (default Keep mine). A read-only summary lists the
 * auto-merged field collisions. NO secret field VALUE is shown — `fieldNames` only (anti-oracle).
 * Decisions are assembled via the shared [collectDecisions] (default `keepLocal = true`). The sheet
 * stays open on error; the caller keeps it presented until a clean resolve clears `pendingConflict`.
 */
@Composable
fun ConflictSheetContent(
    conflict: PendingConflict,
    error: VaultSyncError?,
    onResolve: (List<org.secretary.sync.SyncVetoDecision>) -> Unit,
    onCancel: () -> Unit,
) {
    // recordUuidHex -> keepLocal override; absent means "Keep mine" (default via collectDecisions).
    val overrides = remember { mutableStateMapOf<String, Boolean>() }
    Column(
        modifier = Modifier.fillMaxWidth().padding(CONFLICT_PADDING),
        verticalArrangement = Arrangement.spacedBy(CONFLICT_GAP),
    ) {
        Text(text = "Resolve sync conflicts")
        conflict.vetoes.forEach { veto -> VetoCard(veto, overrides) }

        val mergedFieldCount = conflict.collisions.sumOf { it.fieldNames.size }
        if (mergedFieldCount > 0) {
            Text(text = "$mergedFieldCount field(s) auto-merged — no action needed")
        }
        if (error != null) {
            Text(text = syncErrorLabel(error), modifier = Modifier.testTag("conflict-error"))
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = onCancel) { Text("Cancel") }
            Button(
                onClick = { onResolve(collectDecisions(conflict.vetoes, overrides.toMap())) },
                modifier = Modifier.testTag(CONFLICT_APPLY_TAG),
            ) { Text("Apply") }
        }
    }
}

@Composable
private fun VetoCard(veto: SyncVeto, overrides: MutableMap<String, Boolean>) {
    val keepLocal = overrides[veto.recordUuidHex] ?: true
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(CONFLICT_PADDING),
            verticalArrangement = Arrangement.spacedBy(CONFLICT_GAP),
        ) {
            Text(text = veto.recordType)
            if (veto.tags.isNotEmpty()) Text(text = veto.tags.joinToString(" · "))
            if (veto.fieldNames.isNotEmpty()) Text(text = veto.fieldNames.joinToString(", "))
            Text(text = "deleted on device ${veto.peerDeviceHex.take(PEER_DEVICE_PREFIX_LEN)}")
            Row(horizontalArrangement = Arrangement.spacedBy(CONFLICT_GAP)) {
                FilterChip(
                    selected = keepLocal,
                    onClick = { overrides[veto.recordUuidHex] = true },
                    label = { Text("Keep mine") },
                )
                FilterChip(
                    selected = !keepLocal,
                    onClick = { overrides[veto.recordUuidHex] = false },
                    label = { Text("Accept delete") },
                )
            }
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
```
Expected: PASS (SyncBadge + SyncPasswordSheet + ConflictResolutionSheet tests).

- [ ] **Step 5: Commit**

```bash
git add android/sync-ui/src/main/kotlin/org/secretary/sync/ui/ConflictResolutionSheet.kt android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/ConflictResolutionSheetUiTest.kt
git commit -m "feat(android-sync-ui): metadata-only ConflictResolutionSheet"
```

---

## Task 7: `SyncScreen` wiring + instrumented end-to-end test

**Files:**
- Create: `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncScreen.kt`
- Create: `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/InstrumentedFakes.kt`
- Create: `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncScreenUiTest.kt`

- [ ] **Step 1: Write the instrumented fakes**

Create `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/InstrumentedFakes.kt` (same shape as the host `Fakes.kt`, in the androidTest source set; the two source sets do not share code):

```kotlin
package org.secretary.sync.ui

import org.secretary.sync.SyncMonitorHook
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncStatus
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncPort
import org.secretary.sync.WallClock

/** sync() returns [syncOutcome], commitDecisions() returns [commitOutcome]. */
class ScriptedSyncPort(
    private val syncOutcome: SyncOutcome,
    private val commitOutcome: SyncOutcome,
) : VaultSyncPort {
    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        SyncStatus(hasState = false, deviceClocks = emptyList(), lastStateWriteMs = null)

    override suspend fun sync(stateDir: String, vaultFolder: String, password: ByteArray, nowMs: ULong): SyncOutcome =
        syncOutcome

    override suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = commitOutcome
}

class ZeroWallClock : WallClock {
    override fun nowMs(): ULong = 0uL
}

object NoopMonitorHook : SyncMonitorHook {
    override fun muteSelfWrite() {}
    override fun acknowledge() {}
}
```

- [ ] **Step 2: Write the failing end-to-end test**

Create `android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncScreenUiTest.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncCollision
import org.secretary.sync.SyncCoordinator
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncVeto
import org.secretary.sync.VaultSyncModel

@RunWith(AndroidJUnit4::class)
class SyncScreenUiTest {
    @get:Rule val composeRule = createComposeRule()

    private fun model(): VaultSyncModel {
        val veto = SyncVeto("aabb", "login", listOf("work"), listOf("password"), 1uL, 2uL, "deadbeefcafef00d")
        val conflict = SyncOutcome.ConflictsPending(listOf(veto), listOf(SyncCollision("ccdd", listOf("url"))), byteArrayOf(1, 2, 3))
        // First interactive pass surfaces a conflict; the resolve commit comes back clean.
        val port = ScriptedSyncPort(syncOutcome = conflict, commitOutcome = SyncOutcome.MergedClean)
        val coordinator = SyncCoordinator(port, stateDir = "s", vaultFolder = "f")
        return VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null)
    }

    @Test
    fun badgeTap_password_conflict_resolve_endToEnd() {
        composeRule.setContent { SyncScreen(viewModel = VaultSyncViewModel(model())) }

        // Badge starts at "Never synced"; tap opens the password sheet.
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag(PASSWORD_FIELD_TAG).performTextInput("pw")
        composeRule.onNodeWithText("Sync").performClick()
        composeRule.waitForIdle()

        // Conflict sheet appears; Apply resolves it clean and the sheet closes.
        composeRule.onNodeWithTag(CONFLICT_APPLY_TAG).performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag(CONFLICT_APPLY_TAG).assertDoesNotExist()
    }
}
```

(Imports `assertDoesNotExist` from `androidx.compose.ui.test.assertDoesNotExist` — add it.)

- [ ] **Step 3: Run to verify it fails**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
```
Expected: FAIL — `SyncScreen` unresolved.

- [ ] **Step 4: Write the screen**

Create `android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncScreen.kt`:

```kotlin
package org.secretary.sync.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.secretary.sync.SyncVetoDecision

/**
 * Wires a [VaultSyncViewModel]'s collected state into the three surfaces: the always-visible badge,
 * the password sheet (gated on `passwordSheetVisible`), and the conflict sheet (gated on
 * `pendingConflict != null`). The composables stay stateless; the VM owns the durable state.
 *
 * Interactive password lifetime (mirrors desktop D.1.15 / iOS): the just-submitted password is held
 * ONLY in this screen's transient Compose state ([heldPassword]) — never on the VM or the model
 * (spec §6) — so it can be reused for the conflict resolve. It is zeroized + dropped on every
 * terminal path: a clean pass (when `pendingConflict` clears), conflict cancel, or sheet dismiss.
 */
@Composable
fun SyncScreen(viewModel: VaultSyncViewModel) {
    val badge by viewModel.badge.collectAsStateWithLifecycle()
    val passwordVisible by viewModel.passwordSheetVisible.collectAsStateWithLifecycle()
    val pendingConflict by viewModel.pendingConflict.collectAsStateWithLifecycle()
    val lastError by viewModel.lastError.collectAsStateWithLifecycle()

    // The interactive password, retained from submit until the conflict resolves. UI state only.
    var heldPassword by remember { mutableStateOf<ByteArray?>(null) }
    fun dropPassword() {
        heldPassword?.fill(0) // zeroize the byte buffer before dropping the reference
        heldPassword = null
    }

    // When a pass completes clean (no conflict pending) and no sheet is up, drop the held password.
    LaunchedEffect(pendingConflict, passwordVisible) {
        if (pendingConflict == null && !passwordVisible) dropPassword()
    }

    SyncBadge(
        state = badge,
        nowMs = System.currentTimeMillis().toULong(),
        onTap = { viewModel.beginInteractiveSync() },
    )

    SyncPasswordSheet(
        visible = passwordVisible,
        error = lastError,
        onSubmit = { pw -> heldPassword = pw; viewModel.submitPassword(pw) },
        onDismiss = { dropPassword(); viewModel.dismissPasswordSheet() },
    )

    pendingConflict?.let { conflict ->
        ConflictResolutionSheet(
            conflict = conflict,
            error = lastError,
            onResolve = { decisions: List<SyncVetoDecision> ->
                heldPassword?.let { viewModel.resolve(decisions, it) }
            },
            onCancel = { dropPassword(); viewModel.cancelConflict() },
        )
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
```
Expected: PASS (all four instrumented test classes).

- [ ] **Step 6: Commit**

```bash
git add android/sync-ui/src/main/kotlin/org/secretary/sync/ui/SyncScreen.kt android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/InstrumentedFakes.kt android/sync-ui/src/androidTest/kotlin/org/secretary/sync/ui/SyncScreenUiTest.kt
git commit -m "feat(android-sync-ui): SyncScreen wiring + end-to-end UI test"
```

---

## Task 8: Docs (README + ROADMAP)

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Update README**

In `README.md`, find the Android C.3 status section (slice 4 marked ✅) and add a line marking slice 5 — the Compose sync render (`:sync-ui` module) — as ✅. Keep it a brief dot point per the project's README style.

- [ ] **Step 2: Update ROADMAP**

In `ROADMAP.md`, mark Android C.3 slice 5 (Compose sync render) ✅; note the deferred `:app`-module lifecycle wiring as the next Android step. Correct any stale forward-reference.

- [ ] **Step 3: Run the full gauntlet**

```bash
cd android && ./gradlew :sync-ui:test :vault-access:test :kit:testDebugUnitTest
PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-compose
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   # expect empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           # expect empty
```
Expected: all suites green; both guardrail greps empty.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: mark C.3 Android slice 5 (Compose sync render) shipped"
```

---

## Self-review notes (for the executor)

- **Stateless surfaces, single state owner:** the three composables hold only transient UI state (password field text, conflict overrides); all durable state lives in `VaultSyncModel`/the VM. Do not move badge/conflict logic into the composables.
- **Metadata-only:** the conflict sheet renders `recordType` / `tags` / `fieldNames` / device-id prefix only. Never render a secret field value — there is no API on the surfaced types that exposes one, and there must not be.
- **No `:kit` dependency:** if you find yourself importing `org.secretary.sync` FFI types (`UniffiVaultSyncPort`, `ChangeDetectionMonitor`, `makeVaultSync`), stop — `:sync-ui` must stay FFI-free and the tests `.so`-free.
- **`connectedAndroidTest` + `--tests`:** the Android plugin ignores `--tests` for connected tests; to run a single class use `-Pandroid.testInstrumentationRunnerArguments.class=org.secretary.sync.ui.SyncBadgeUiTest`.
- **Interactive password lifetime:** the password is held only in `SyncScreen`'s transient Compose state (`heldPassword`), reused for the conflict resolve, and zeroized+dropped on every terminal path — never on the VM or model (spec §6). Do not "simplify" this by storing it on the VM.
