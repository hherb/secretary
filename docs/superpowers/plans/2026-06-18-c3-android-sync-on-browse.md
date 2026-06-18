# C.3 Android — Sync badge + sync-at-unlock on the browse screen — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Android `:app` to iOS parity — one screen that shows both the vault browser and a live sync badge, runs sync-at-unlock in the background, and hosts the interactive sync/conflict flow — by reusing the existing `SyncScreen` stacked above `BrowseScreen`.

**Architecture:** A new app-level composable `BrowseWithSyncScreen` stacks the untouched `SyncScreen` (`:sync-ui`) above the untouched `BrowseScreen` (`:browse-ui`). `AppRoot`'s `Browse` route carries a `BrowseSession` holder (browse VM + sync VM + monitor) assembled by a new `openBrowseWithSync` orchestration helper; sync-at-unlock runs in the background via a pure `launchSyncAtUnlock` helper that copies-then-zeroizes the password. Mirrors iOS, whose unified `VaultBrowseScreen` lives in the app target.

**Tech Stack:** Kotlin, Jetpack Compose (Material3), kotlinx-coroutines, JUnit5 (host) + AndroidX instrumented tests + Compose UI test, Gradle.

## Global Constraints

- **No `core/`, `ffi/`, on-disk vault format, or UDL/FFI-surface change.** This is an Android-only slice.
- **No `ios/` change** (unlike #254 — that guardrail re-applies here).
- **No edits to `:vault-access`, `:browse-ui`, or `:sync-ui` library source.** They stay decoupled sibling libraries; the composition is an `:app` concern. (Test source sets and `:app` are fair game.)
- **`makeVaultSync` must be called on the main thread** — it fast-fails (`Looper.myLooper() == Looper.getMainLooper()`) otherwise.
- **Coroutines pinned to 1.8.0** (existing `:app` resolution force — do not change).
- **Zeroize discipline:** every password `ByteArray` is overwritten with `fill(0)` on every exit path. A buffer handed to a background coroutine is a *copy* of the caller's buffer, zeroized when the background pass settles.
- **Files under ~500 lines; one concept per file; pure functions in reusable modules where reasonable.**
- **Tests use the published golden-vault KAT password `"correct horse battery staple"`** (not a real secret) for on-device exercises.

---

### Task 1: `launchSyncAtUnlock` — copy-then-zeroize background sync helper

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/SyncAtUnlock.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/SyncAtUnlockTest.kt`

**Interfaces:**
- Consumes: nothing (pure Kotlin + coroutines).
- Produces: `fun launchSyncAtUnlock(scope: CoroutineScope, password: ByteArray, syncAtUnlock: suspend (ByteArray) -> Unit): Job`

**Why a helper:** the password copy MUST be taken synchronously (before `launchSyncAtUnlock` returns) so the caller can zeroize its own buffer immediately without racing the background read; the copy is then zeroized when the suspend pass settles. This ordering is the secret-hygiene core and is the one genuinely host-testable unit in this slice.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.secretary.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SyncAtUnlockTest {

    @Test
    fun passesADistinctCopy_originalUntouchedByHelper() = runTest {
        val original = byteArrayOf(1, 2, 3, 4)
        val seen = CompletableDeferred<ByteArray>()
        val job = launchSyncAtUnlock(this, original) { copy -> seen.complete(copy) }
        job.join()
        val received = seen.await()
        // The pass receives the SAME CONTENTS but a DISTINCT array (so the caller may zeroize
        // `original` independently without corrupting the background read).
        assertFalse("must be a distinct array", received === original)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), original) // helper itself never mutates the original
    }

    @Test
    fun copySurvivesCallerZeroizingOriginal_thenCopyZeroizedAfterPass() = runTest {
        val original = byteArrayOf(5, 6, 7, 8)
        val gate = CompletableDeferred<Unit>()
        val contentsDuringPass = CompletableDeferred<ByteArray>()
        lateinit var copyRef: ByteArray
        val job = launchSyncAtUnlock(this, original) { copy ->
            copyRef = copy
            gate.await()                       // hold the pass open
            contentsDuringPass.complete(copy.copyOf())
        }
        original.fill(0)                       // caller zeroizes its buffer while the pass is parked
        gate.complete(Unit)
        job.join()
        // The copy still held the ORIGINAL contents during the pass, despite the caller zeroizing.
        assertArrayEquals(byteArrayOf(5, 6, 7, 8), contentsDuringPass.await())
        // After the pass settles, the copy is zeroized.
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), copyRef)
    }

    @Test
    fun copyZeroizedEvenWhenPassThrows() = runTest {
        val original = byteArrayOf(9, 9)
        lateinit var copyRef: ByteArray
        val job = launchSyncAtUnlock(this, original) { copy ->
            copyRef = copy
            throw RuntimeException("pass failed")
        }
        runCatching { job.join() }
        assertArrayEquals("copy zeroized on the throwing path too", byteArrayOf(0, 0), copyRef)
        assertTrue(job.isCompleted)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.SyncAtUnlockTest'`
Expected: FAIL — `launchSyncAtUnlock` unresolved (compilation error).

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Launches [syncAtUnlock] on [scope] with a PRIVATE COPY of [password], zeroizing the copy when
 * the pass settles (success or throw).
 *
 * The copy is taken synchronously — before this function returns — so the caller may zeroize its
 * own [password] buffer immediately after this call without racing the background read. The copy
 * never outlives the launched pass.
 *
 * Secret hygiene: this is the sole owner of the COPY's lifetime; the caller remains the owner of
 * [password] and is responsible for zeroizing it. Mirrors the iOS `Task { await syncAtUnlock() }`
 * fire-and-forget at unlock, with the copy/zeroize made explicit because Android's caller zeroizes
 * the original in its own `finally`.
 *
 * @return the [Job] running the pass (await it in tests; production fires and forgets).
 */
fun launchSyncAtUnlock(
    scope: CoroutineScope,
    password: ByteArray,
    syncAtUnlock: suspend (ByteArray) -> Unit,
): Job {
    val copy = password.copyOf() // synchronous: safe against the caller zeroizing `password`
    return scope.launch {
        try {
            syncAtUnlock(copy)
        } finally {
            copy.fill(0)
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'org.secretary.app.SyncAtUnlockTest'`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/SyncAtUnlock.kt \
        android/app/src/test/kotlin/org/secretary/app/SyncAtUnlockTest.kt
git commit -m "feat(android): launchSyncAtUnlock — copy-then-zeroize background sync helper (#TBD)"
```

---

### Task 2: `openBrowseWithSync` — assemble browse VM + sync VM + monitor from the real stack

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt`
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseWithSyncSmokeTest.kt`

**Interfaces:**
- Consumes: `launchSyncAtUnlock` (Task 1, not called here — referenced by Task 3); `org.secretary.browse.{VaultOpenPort, VaultBrowseModel, DeviceUuidStore, uniffiVaultOpenPort}`; `org.secretary.browse.ui.VaultBrowseViewModel`; `org.secretary.sync.{makeVaultSync, ChangeDetectionMonitor}`; `org.secretary.sync.ui.VaultSyncViewModel`; `org.secretary.app.syncStateDir`.
- Produces:
  - `data class BrowseSession(val browse: VaultBrowseViewModel, val sync: VaultSyncViewModel, val monitor: ChangeDetectionMonitor)`
  - `suspend fun openBrowseWithSync(openPort: VaultOpenPort, folder: File, stateDir: File, vaultUuid: ByteArray, password: ByteArray): BrowseSession`

**Notes for the implementer:**
- `openBrowseWithSync` does NOT launch sync-at-unlock and does NOT zeroize `password` (the caller owns the original buffer's lifetime — see Task 3).
- It MUST run on the main thread because `makeVaultSync` is Looper-gated. `openPort.openWithPassword` suspends and hops to IO internally, returning control to the caller's (main) dispatcher afterward — so calling `makeVaultSync` after the `await` is still on main.
- `VaultBrowseModel(session)` and `model.loadBlocks()` mirror the current `AppRoot.unlockAndOpen`.
- This task's test exercises the REAL native `.so` (host fakes cannot reach the FFI), mirroring `MakeVaultSyncSmokeTest` / `OpenBrowseSmokeTest`.

- [ ] **Step 1: Write the failing test** (instrumented — requires a running emulator)

```kotlin
package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * On-device proof that the unlock orchestration assembles a coherent browse+sync session over the
 * REAL libsecretary_ffi_uniffi.so: a browse VM with blocks loaded, a sync VM, and a monitor — then
 * a background sync-at-unlock settles cleanly on the single-device golden vault (an
 * AppliedAutomatically fast-forward against a fresh state dir).
 */
@RunWith(AndroidJUnit4::class)
class OpenBrowseWithSyncSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val goldenPassword = "correct horse battery staple"
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun assemblesBrowseAndSync_thenSyncAtUnlockSettlesClean() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        toClean += stateBase
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        // Assemble on the main thread (makeVaultSync is Looper-gated).
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                goldenPassword.toByteArray())
        }

        assertTrue("browse VM loaded blocks", session.browse.blocks.value.isNotEmpty())

        // Background sync-at-unlock with a password copy; join the job (test-only) and assert clean.
        val job = withContext(Dispatchers.Main) {
            launchSyncAtUnlock(this, goldenPassword.toByteArray(), session.sync::syncAtUnlock)
        }
        job.join()
        assertNull("clean silent pass surfaces no error", session.sync.lastError.value)
        assertTrue("review not raised on a clean single-device pass", !session.sync.reviewNeeded.value)

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest --tests 'org.secretary.app.OpenBrowseWithSyncSmokeTest'
```
Expected: FAIL — `openBrowseWithSync` / `BrowseSession` unresolved (compilation error).

- [ ] **Step 3: Write minimal implementation**

```kotlin
package org.secretary.app

import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.VaultOpenPort
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.sync.ChangeDetectionMonitor
import org.secretary.sync.makeVaultSync
import org.secretary.sync.ui.VaultSyncViewModel
import java.io.File

/**
 * The three handles for an unlocked, browsable, sync-aware session. Mirrors the iOS
 * `.browse(VaultBrowseViewModel, VaultSyncViewModel, ChangeDetectionMonitor)` route payload.
 * The caller owns the monitor lifecycle (`start()` on screen entry, `stop()` on dispose).
 */
data class BrowseSession(
    val browse: VaultBrowseViewModel,
    val sync: VaultSyncViewModel,
    val monitor: ChangeDetectionMonitor,
)

/**
 * Opens the vault for browsing and assembles the sync model+monitor for the same folder.
 *
 * MUST be called on the main thread: [makeVaultSync] is Looper-gated. [openPort.openWithPassword]
 * suspends and hops to IO internally, returning to the caller's (main) dispatcher afterward, so the
 * subsequent [makeVaultSync] call is still on main.
 *
 * Does NOT launch sync-at-unlock and does NOT zeroize [password] — the caller owns the original
 * buffer (it zeroizes the original after handing a copy to [launchSyncAtUnlock]; see AppRoot).
 *
 * @throws the same typed open errors as [VaultOpenPort.openWithPassword] (e.g. wrong password) —
 *   the caller catches and returns the user to Unlock.
 */
suspend fun openBrowseWithSync(
    openPort: VaultOpenPort,
    folder: File,
    stateDir: File,
    vaultUuid: ByteArray,
    password: ByteArray,
): BrowseSession {
    val session = openPort.openWithPassword(folder.path, password)
    val browseModel = VaultBrowseModel(session)
    browseModel.loadBlocks()
    val (syncModel, monitor) = makeVaultSync(folder, stateDir, vaultUuid)
    return BrowseSession(
        browse = VaultBrowseViewModel(browseModel),
        sync = VaultSyncViewModel(syncModel),
        monitor = monitor,
    )
}
```

- [ ] **Step 4: Run test to verify it passes** (emulator running)

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest --tests 'org.secretary.app.OpenBrowseWithSyncSmokeTest'
```
Expected: PASS (1 test) on `Medium_Phone_API_36.1`.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/OpenBrowseWithSyncSmokeTest.kt
git commit -m "feat(android): openBrowseWithSync assembles browse VM + sync VM + monitor (#TBD)"
```

---

### Task 3: `BrowseWithSyncScreen` composable + `AppRoot` rewiring

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt`
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`
- Modify: `android/app/build.gradle.kts` (add Compose UI-test deps for the instrumented render test)
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/BrowseWithSyncScreenUiTest.kt`

**Interfaces:**
- Consumes: `BrowseSession`, `openBrowseWithSync` (Task 2); `launchSyncAtUnlock` (Task 1); `org.secretary.sync.ui.SyncScreen`; `org.secretary.browse.ui.BrowseScreen` + `org.secretary.sync.ui.SYNC_BADGE_TAG`.
- Produces: `@Composable fun BrowseWithSyncScreen(browse: VaultBrowseViewModel, sync: VaultSyncViewModel)`

**Notes for the implementer:**
- `BrowseWithSyncScreen` is pure composition: `Column { SyncScreen(sync); HorizontalDivider(); BrowseScreen(browse) }`. The badge row (inside `SyncScreen`) sits above `BrowseScreen`'s swappable content, so it stays visible on both the block-list and record-list views.
- `AppRoot`: the `Browse` route carries a single `BrowseSession`. `unlockAndOpen` gains a `scope` parameter (the `rememberCoroutineScope()` already created in `AppRoot`), assembles via `openBrowseWithSync`, fires `launchSyncAtUnlock`, then zeroizes the original password in the existing `finally`. The `Browse` route's `DisposableEffect` both starts/stops the monitor (mirroring slice 6) AND locks the browse session on dispose (mirroring the current slice-7 behaviour).
- The Compose UI-test deps must be added to `:app` — its `androidTest` config currently lacks `ui-test-junit4` / `ui-test-manifest` (only `:sync-ui` has them).

- [ ] **Step 1: Add Compose UI-test dependencies to `:app`**

In `android/app/build.gradle.kts`, inside the `dependencies { ... }` block, under the `// --- Instrumented tests ...` section, add:

```kotlin
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
```

(The `composeBom` val is already declared earlier in the same `dependencies` block; reuse it.)

- [ ] **Step 2: Write the failing test** (instrumented render test over the real stack)

```kotlin
package org.secretary.app

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.uniffiVaultOpenPort
import org.secretary.sync.ui.SYNC_BADGE_TAG
import java.io.File

/**
 * Proves the UNIFICATION: the sync badge and the browse content render together on one screen, and
 * the badge survives navigating from the block list into a block's record list. Built over the real
 * `.so` session (reusing openBrowseWithSync) rather than fabricated fakes, so the test exercises the
 * production composition path.
 */
@RunWith(AndroidJUnit4::class)
class BrowseWithSyncScreenUiTest {
    @get:Rule val composeRule = createAndroidComposeRule<androidx.activity.ComponentActivity>()

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext
    private val goldenPassword = "correct horse battery staple"
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun badgeAndBlocksRenderTogether_badgeSurvivesBlockNavigation() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        toClean += stateBase
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                goldenPassword.toByteArray())
        }

        composeRule.setContent {
            BrowseWithSyncScreen(browse = session.browse, sync = session.sync)
        }

        // Badge + the "Blocks" header are visible together on the block-list view.
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).assertIsDisplayed()
        composeRule.onNodeWithText("Blocks").assertIsDisplayed()

        // Navigate into the first block; the badge must still be displayed on the record-list view.
        val firstBlockLabel = session.browse.blocks.value.first().let { blockLabelForTest(it.uuidHex) }
        // Tapping a block row selects it (BrowseScreen renders block labels as clickable rows).
        composeRule.onAllNodes(hasClickAction()).onFirst().performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).assertIsDisplayed()

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
```

> Implementer note: the navigation assertion only needs to prove the badge persists after the block list changes to a record list. If the `blockLabelForTest`/`hasClickAction` helpers prove awkward against the real block labels, drive selection directly on the view-model instead — call `session.browse.selectBlock(session.browse.blocks.value.first())` inside a `withContext(Dispatchers.Main)` block, `composeRule.waitForIdle()`, then assert the badge tag is still displayed. Prefer whichever is least brittle; the *invariant under test* is "badge visible on both views", not the tap mechanics. Remove the unused imports/helpers for whichever path you keep.

- [ ] **Step 3: Run test to verify it fails**

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest --tests 'org.secretary.app.BrowseWithSyncScreenUiTest'
```
Expected: FAIL — `BrowseWithSyncScreen` unresolved (compilation error).

- [ ] **Step 4: Write the composable**

Create `android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt`:

```kotlin
package org.secretary.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.secretary.browse.ui.BrowseScreen
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.sync.ui.SyncScreen
import org.secretary.sync.ui.VaultSyncViewModel

/**
 * The unified browse+sync screen: the sync badge (and its password/conflict sheets, all owned by
 * the reused [SyncScreen]) sit above the [BrowseScreen] content. Because the badge row is outside
 * BrowseScreen's swappable block-list/record-list content, it stays visible on both views.
 *
 * This composable holds NO state — it is pure composition of two independently-tested library
 * surfaces ([SyncScreen] from `:sync-ui`, [BrowseScreen] from `:browse-ui`). Mirrors iOS's unified
 * `VaultBrowseScreen`, which likewise composes both view-models at the app layer.
 */
@Composable
fun BrowseWithSyncScreen(browse: VaultBrowseViewModel, sync: VaultSyncViewModel) {
    Column(modifier = Modifier.fillMaxSize()) {
        SyncScreen(viewModel = sync)
        HorizontalDivider()
        BrowseScreen(viewModel = browse)
    }
}
```

- [ ] **Step 5: Rewire `AppRoot.kt`**

Replace the `Route` sealed interface, the `Browse` branch in the `when`, and `unlockAndOpen` as follows. (Imports: add `org.secretary.sync.ChangeDetectionMonitor` is reachable via `BrowseSession`; add `kotlinx.coroutines.CoroutineScope`. Remove now-unused imports — `VaultBrowseModel`, `uniffiVaultOpenPort` move into `openBrowseWithSync`/are still used; keep `FileDeviceUuidStore`, `File`. Let the compiler/clippy-equivalent guide the final import set.)

`Route`:

```kotlin
private sealed interface Route {
    data object Unlock : Route
    data class Browse(val session: BrowseSession) : Route
}
```

The `when (val r = route)` `Browse` branch:

```kotlin
        is Route.Browse -> {
            // The monitor runs only while Browse is composed: started on enter, stopped on dispose
            // (background → Unlock, or teardown). The browse session is also wiped on dispose so the
            // decrypted manifest/identity never outlives the on-screen session (re-entry re-opens
            // from the password). A failed monitor start leaves detection advisory-blind (the badge
            // falls back to manual "Sync now"); not fatal.
            DisposableEffect(r.session) {
                try {
                    r.session.monitor.start()
                } catch (e: Exception) {
                    Log.w(TAG, "folder-change monitor failed to start", e)
                }
                onDispose {
                    r.session.monitor.stop()
                    r.session.browse.lock()
                }
            }
            BrowseWithSyncScreen(browse = r.session.browse, sync = r.session.sync)
        }
```

The `Unlock` branch passes the scope to `unlockAndOpen`:

```kotlin
        is Route.Unlock -> UnlockScreen(onUnlock = { password ->
            scope.launch { route = unlockAndOpen(context, scope, password) }
        })
```

`unlockAndOpen`:

```kotlin
/**
 * Opens the vault for browsing, assembles the sync model+monitor, fires a background
 * sync-at-unlock, and returns the Browse route. Runs on the main `scope` (Argon2id hops to IO
 * inside the open port; makeVaultSync inside [openBrowseWithSync] requires main — satisfied here).
 *
 * Secret hygiene: the original password buffer is zeroized in a `finally` wrapping the whole body —
 * overwritten on every exit (success, open failure, early provisioning throw). The background
 * sync-at-unlock receives a COPY ([launchSyncAtUnlock]); zeroizing the original here cannot corrupt
 * that copy. Because [openBrowseWithSync] awaits the open, the zeroize cannot race the Argon2id that
 * consumes the original.
 *
 * Known accepted minor race (mirrors slices 6/7): if backgrounded while this suspends, the coroutine
 * may still set route = Browse afterward; the next ON_STOP disposes Browse (stops the monitor, wipes
 * the session) and the password is already zeroized — self-heals.
 */
private suspend fun unlockAndOpen(
    context: Context,
    scope: CoroutineScope,
    password: ByteArray,
): Route {
    try {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices"))
        val stateDir = syncStateDir(context.filesDir).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)
        val session = openBrowseWithSync(
            uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid, password)
        // Background silent sync-at-unlock with a password copy (browse renders immediately;
        // the second Argon2id never blocks the UI). A conflict on this path only raises the
        // review badge — the interactive path (badge tap) re-prompts for the password.
        launchSyncAtUnlock(scope, password, session.sync::syncAtUnlock)
        return Route.Browse(session)
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        return Route.Unlock
    } finally {
        password.fill(0) // zeroize the original on every exit; the background copy is independent
    }
}
```

- [ ] **Step 6: Run the render test to verify it passes** (emulator running)

Run:
```bash
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest --tests 'org.secretary.app.BrowseWithSyncScreenUiTest'
```
Expected: PASS (1 test).

- [ ] **Step 7: Run the full `:app` host + connected suites and the neighbour modules**

Run (host first, then connected):
```bash
cd android && ./gradlew :app:testDebugUnitTest :vault-access:test :browse-ui:test
cd android && PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest :browse-ui:connectedDebugAndroidTest :sync-ui:connectedDebugAndroidTest
```
Expected: all green — including the pre-existing `OpenBrowseSmokeTest` / `MakeVaultSyncSmokeTest` and the `:sync-ui` (15) / `:browse-ui` (8) suites, which must be unaffected.

- [ ] **Step 8: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt \
        android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
        android/app/build.gradle.kts \
        android/app/src/androidTest/kotlin/org/secretary/app/BrowseWithSyncScreenUiTest.kt
git commit -m "feat(android): unify sync badge + sync-at-unlock onto the browse screen (#TBD)"
```

---

### Task 4: Documentation — README + ROADMAP rows

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

**Notes:** Follow the existing terse Android-slice row style (see the slice-10 / write-action-debounce rows). State: sync badge + sync-at-unlock now on the browse screen via a reused `SyncScreen` stacked above `BrowseScreen`; background sync-at-unlock; Android-only, no core/ffi/format change; the known second-Argon2id cost.

- [ ] **Step 1: Update `README.md`**

In the Android (C.3) progress narrative, append a sentence to the running slice list, e.g.:

```
**Sync-on-browse (2026-06-18):** the sync badge + sync-at-unlock re-integrated onto the browse
screen — a new app-level `BrowseWithSyncScreen` stacks the (untouched) `SyncScreen` above
`BrowseScreen`, so an unlocked user sees a live sync badge and the interactive sync/conflict flow
on the same screen they browse/edit on; sync-at-unlock runs in the background off the render path.
Mirrors iOS's unified `VaultBrowseScreen`. Android-only; no `core` / `ffi` / on-disk-format change.
```

And update the "Sync orchestration" status row's Android tail to mention sync-on-browse ✅ 2026-06-18.

- [ ] **Step 2: Update `ROADMAP.md`**

Add a `**C.3 sync-on-browse (Android)** ✅ 2026-06-18` entry mirroring the prose of the other C.3 slice entries (the reused-SyncScreen approach, background sync-at-unlock, the known second-Argon2id cost, Android-only / no core-ffi-format change). Reference the spec + plan docs.

- [ ] **Step 3: Verify the guardrails**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-on-browse
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'   # expect: empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'  # expect: empty (no ios/)
```
Expected: both empty.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: sync badge + sync-at-unlock on the Android browse screen (#TBD)"
```

---

## Self-Review

**Spec coverage:**
- "Reuse SyncScreen stacked above BrowseScreen in a new app-level composable" → Task 3 (`BrowseWithSyncScreen`). ✅
- "Browse route carries browse VM + sync VM + monitor" → Task 2 (`BrowseSession`) + Task 3 (`Route.Browse`). ✅
- "Background sync-at-unlock with a cloned-then-zeroized password" → Task 1 (`launchSyncAtUnlock`) + Task 3 (call site). ✅
- "Monitor lifecycle (start on entry, stop on dispose, failed start non-fatal)" → Task 3 `DisposableEffect`. ✅
- "Host-test the clone/zeroize discipline" → Task 1 (3 host tests). ✅
- "Instrumented: badge + block list shown together; badge on both views" → Task 3 `BrowseWithSyncScreenUiTest`. ✅
- "Both VMs produced; failed open → Unlock + zeroize" → Task 2 (`openBrowseWithSync` smoke) + Task 3 (`unlockAndOpen` `finally`; failed open returns Unlock). The "failed open" path reuses the existing typed-error behaviour (`OpenBrowseSmokeTest.open_wrongPassword_throwsTypedError` already pins it). ✅
- "No `:vault-access`/`:browse-ui`/`:sync-ui` library edits; guardrails empty" → Task 4 Step 3. ✅
- Acceptance criteria 1–5 → covered across Tasks 2/3/4. ✅

**Placeholder scan:** No "TBD/TODO/handle edge cases" in step bodies. The commit-message `#TBD` issue placeholders are intentional — replace with the real issue number when the slice is filed/closed (note: there is no pre-existing issue for this slice; either file one or drop the `(#NNN)` suffix at commit time).

**Type consistency:**
- `launchSyncAtUnlock(scope, password, suspend (ByteArray)->Unit): Job` — defined Task 1, consumed identically Tasks 2/3 via `session.sync::syncAtUnlock` (`VaultSyncViewModel.syncAtUnlock(ByteArray)` is `suspend`). ✅
- `BrowseSession(browse, sync, monitor)` — defined Task 2, consumed Task 3 (`r.session.browse/.sync/.monitor`). ✅
- `openBrowseWithSync(openPort, folder, stateDir, vaultUuid, password): BrowseSession` — defined Task 2, called identically in Task 2's test and Task 3's `unlockAndOpen`. ✅
- `BrowseWithSyncScreen(browse, sync)` — defined Task 3, called in Task 3's test and `AppRoot`. ✅
- `SYNC_BADGE_TAG` — existing public const in `:sync-ui`, used in Task 3's test. ✅
