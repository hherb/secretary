# Android Device-Management Settings Surface — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-vault "Settings" surface to the Android app that shows this device's biometric-enrollment status and lets the user enroll (with a password re-prompt) or disenroll.

**Architecture:** A pure `DeviceSettingsViewModel` in `:vault-access` wraps the existing `DeviceUnlockCoordinator` (which already holds enroll/disenroll). A `DeviceSettingsScreen` Compose surface in `:app` renders from a plain state value. `AppRoot` reaches the screen as a sub-view of the unlocked `Browse` route (so a Settings excursion never locks the vault), bridging the VM's plain-`var` state into a Compose mirror.

**Tech Stack:** Kotlin, Jetpack Compose (Material3), JUnit5 (host, `:vault-access`), AndroidX Compose UI test + JUnit4 (instrumented, `:app`), kotlinx-coroutines-test.

## Global Constraints

- **Android-only.** `git diff main...HEAD --name-only` must show nothing under `core/`, `ffi/`, `crypto-design`, `vault-format`, or `ios/`. Only `android/`, `docs/`, `README.md`, `ROADMAP.md` may change.
- **Threat-model §13 anti-oracle:** wrong-password and corruption stay **conflated** in one user-facing message — never split them.
- **Secret hygiene:** any `ByteArray` derived from a typed password is zeroized (`fill(0)`) in a `finally` after use. `password` passed into the VM is caller-owned (forwarded to the coordinator, not zeroized in the VM) — same contract as `DeviceUnlockViewModel.enroll`.
- **Don't read a VM's plain-`var` `state` directly in a composable** — bridge it into a `mutableStateOf` mirror in `AppRoot`, or it won't recompose.
- **Files focused, < 500 lines; no magic numbers/strings** — shared testTags and user copy are named constants. TDD: failing test first, frequent commits.
- **Test command base:** host = `cd android && ./gradlew :vault-access:test`; instrumented = `cd android && ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=<FQN>` (connectedAndroidTest rejects `--tests`; two devices are attached, so `ANDROID_SERIAL` is mandatory).

### State-model refinement (vs. the design doc)

The design sketched a sealed `DeviceSettingsState` (Enrolled / Unenrolled / Working / Failed). During planning a gap surfaced: `Working` and `Failed` don't carry the enrolled bit, so after a failure the screen wouldn't know which button to show. This plan uses a **data class** carrying all three facts at once — strictly the same four concepts, expressed so status survives a failure:

```kotlin
data class DeviceSettingsState(
    val enrolled: Boolean,
    val working: Boolean = false,
    val error: String? = null,
)
```

---

### Task 1: `DeviceSettingsViewModel` (pure, host-tested)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceSettingsViewModel.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceSettingsViewModelTest.kt`

**Interfaces:**
- Consumes (existing): `DeviceUnlockCoordinator(slotPort, enclave, metadata)` with `val isEnrolled: Boolean`, `suspend fun enroll(folder, vaultId, password)`, `suspend fun disenroll(folder)`. Host fakes `FakeVaultDeviceSlotPort(addError=…)`, `FakeDeviceSecretEnclave(storeError=…)`, `FakeEnrollmentMetadataStore()`. Errors: `DeviceUnlockError.{BiometryNotEnrolled,BiometryUnavailable,Enclave}`, `VaultBrowseError.WrongPasswordOrCorrupt`.
- Produces (for Task 3): `class DeviceSettingsViewModel(coordinator: DeviceUnlockCoordinator)` with `var state: DeviceSettingsState` (private set), `fun refresh()`, `suspend fun enroll(folder: String, vaultId: String, password: ByteArray)`, `suspend fun disenroll(folder: String)`; `data class DeviceSettingsState(enrolled, working=false, error=null)`; internal consts `ENROLL_BIOMETRIC_UNAVAILABLE_MESSAGE`, `ENROLL_FAILED_MESSAGE`, `DISENROLL_FAILED_MESSAGE`.

- [ ] **Step 1: Write the failing test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/DeviceSettingsViewModelTest.kt`:

```kotlin
package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceSettingsViewModelTest {
    private val folder = "/tmp/vault"
    private val vaultId = "00112233445566778899aabbccddeeff"

    private fun coordinator(
        slotPort: VaultDeviceSlotPort = FakeVaultDeviceSlotPort(),
        enclave: DeviceSecretEnclave = FakeDeviceSecretEnclave(),
        metadata: DeviceEnrollmentMetadataStore = FakeEnrollmentMetadataStore(),
    ) = DeviceUnlockCoordinator(slotPort, enclave, metadata)

    @Test
    fun refresh_reportsUnenrolled_whenNothingStored() {
        val vm = DeviceSettingsViewModel(coordinator())
        vm.refresh()
        assertFalse(vm.state.enrolled)
        assertNull(vm.state.error)
    }

    @Test
    fun enroll_success_marksEnrolled_clearsError() = runTest {
        val vm = DeviceSettingsViewModel(coordinator())
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertTrue(vm.state.enrolled)
        assertFalse(vm.state.working)
        assertNull(vm.state.error)
    }

    @Test
    fun refresh_reportsEnrolled_afterEnroll() = runTest {
        val coord = coordinator()
        val vm = DeviceSettingsViewModel(coord)
        vm.enroll(folder, vaultId, "pw".toByteArray())
        vm.refresh()
        assertTrue(vm.state.enrolled)
    }

    @Test
    fun enroll_wrongPassword_keepsUnenrolled_setsConflatedError() = runTest {
        // addDeviceSlot fails the same way a wrong re-prompted password does.
        val slot = FakeVaultDeviceSlotPort(addError = VaultBrowseError.WrongPasswordOrCorrupt)
        val vm = DeviceSettingsViewModel(coordinator(slotPort = slot))
        vm.enroll(folder, vaultId, "wrong".toByteArray())
        assertFalse(vm.state.enrolled)
        assertEquals(ENROLL_FAILED_MESSAGE, vm.state.error)
    }

    @Test
    fun enroll_noBiometric_setsBiometricUnavailableError() = runTest {
        val enclave = FakeDeviceSecretEnclave(storeError = DeviceUnlockError.BiometryNotEnrolled)
        val vm = DeviceSettingsViewModel(coordinator(enclave = enclave))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertFalse(vm.state.enrolled)
        assertEquals(ENROLL_BIOMETRIC_UNAVAILABLE_MESSAGE, vm.state.error)
    }

    @Test
    fun disenroll_success_marksUnenrolled() = runTest {
        val coord = coordinator()
        val vm = DeviceSettingsViewModel(coord)
        vm.enroll(folder, vaultId, "pw".toByteArray())
        vm.disenroll(folder)
        assertFalse(vm.state.enrolled)
        assertNull(vm.state.error)
    }

    @Test
    fun disenroll_whenNotEnrolled_isIdempotentSuccess() = runTest {
        val vm = DeviceSettingsViewModel(coordinator())
        vm.disenroll(folder)
        assertFalse(vm.state.enrolled)
        assertNull(vm.state.error)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.DeviceSettingsViewModelTest'`
Expected: FAIL — compilation error, `DeviceSettingsViewModel` / `DeviceSettingsState` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/DeviceSettingsViewModel.kt`:

```kotlin
package org.secretary.browse

/** User-facing copy for the device-settings surface. Conflates wrong-password vs. corrupt per
 *  threat-model §13 — do NOT split [ENROLL_FAILED_MESSAGE] into distinct password/corruption text. */
internal const val ENROLL_BIOMETRIC_UNAVAILABLE_MESSAGE =
    "Couldn't enable biometric unlock — no biometric is set up on this device."
internal const val ENROLL_FAILED_MESSAGE =
    "Couldn't enable biometric unlock — wrong password, or biometrics unavailable."
internal const val DISENROLL_FAILED_MESSAGE =
    "Couldn't disable biometric unlock — please try again."

/**
 * Plain UI state for the device-management Settings surface. Carries [enrolled] (which button to
 * show), [working] (an op is in flight — disable buttons) and an optional user-safe [error] together,
 * so a failure never loses the enrolled/unenrolled status. Rendered by `DeviceSettingsScreen`.
 */
data class DeviceSettingsState(
    val enrolled: Boolean,
    val working: Boolean = false,
    val error: String? = null,
)

/**
 * Pure view-model for the Settings surface: a thin state wrapper over [DeviceUnlockCoordinator]
 * (which holds the real enroll/disenroll). Separate from `DeviceUnlockViewModel` (single
 * responsibility; that VM's states are unlock-flow-shaped). Host-tested over the in-memory fakes.
 *
 * Unlike the unlock-time enroll (whose password was already validated by the open), the Settings
 * enroll re-prompts an UNVERIFIED password — so [enroll] catches BOTH [DeviceUnlockError] AND
 * [VaultBrowseError] (a wrong password surfaces as [VaultBrowseError.WrongPasswordOrCorrupt] from
 * `addDeviceSlot`). [password] is caller-owned (forwarded to the coordinator, not zeroized here).
 */
class DeviceSettingsViewModel(private val coordinator: DeviceUnlockCoordinator) {
    var state: DeviceSettingsState = DeviceSettingsState(enrolled = false)
        private set

    /** Cheap, prompt-free recompute of enrolled-vs-not; clears any prior error. */
    fun refresh() {
        state = DeviceSettingsState(enrolled = coordinator.isEnrolled)
    }

    /** Enroll this device (triggers the one enroll-time biometric prompt inside the enclave). */
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray) {
        state = state.copy(working = true, error = null)
        state = try {
            coordinator.enroll(folder, vaultId, password)
            DeviceSettingsState(enrolled = true)
        } catch (e: DeviceUnlockError) {
            DeviceSettingsState(enrolled = coordinator.isEnrolled, error = enrollErrorMessage(e))
        } catch (e: VaultBrowseError) {
            DeviceSettingsState(enrolled = coordinator.isEnrolled, error = enrollErrorMessage(e))
        }
    }

    /** Revoke this device's enrollment (idempotent; needs no password). */
    suspend fun disenroll(folder: String) {
        state = state.copy(working = true, error = null)
        state = try {
            coordinator.disenroll(folder)
            DeviceSettingsState(enrolled = false)
        } catch (e: VaultBrowseError) {
            DeviceSettingsState(enrolled = coordinator.isEnrolled, error = DISENROLL_FAILED_MESSAGE)
        }
    }
}

/** Map an enroll failure to user-safe copy. Biometric-absent gets its own hint; everything else
 *  (incl. wrong password / corruption) folds to the conflated [ENROLL_FAILED_MESSAGE] (§13). */
internal fun enrollErrorMessage(e: Throwable): String = when (e) {
    is DeviceUnlockError.BiometryNotEnrolled,
    is DeviceUnlockError.BiometryUnavailable -> ENROLL_BIOMETRIC_UNAVAILABLE_MESSAGE
    else -> ENROLL_FAILED_MESSAGE
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.DeviceSettingsViewModelTest'`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-settings
git add android/vault-access/src/main/kotlin/org/secretary/browse/DeviceSettingsViewModel.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/DeviceSettingsViewModelTest.kt
git commit -m "feat(android): pure DeviceSettingsViewModel for enroll/disenroll status"
```

---

### Task 2: `DeviceSettingsScreen` (Compose surface + instrumented UI test)

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/DeviceSettingsScreen.kt`
- Test: `android/app/src/androidTest/kotlin/org/secretary/app/DeviceSettingsScreenUiTest.kt`

**Interfaces:**
- Consumes (Task 1): `DeviceSettingsState(enrolled, working, error)`.
- Produces (for Task 3): `@Composable fun DeviceSettingsScreen(state: DeviceSettingsState, onEnroll: (password: ByteArray) -> Unit, onDisenroll: () -> Unit, onBack: () -> Unit)`. testTags: `device-status`, `enroll-button`, `disenroll-button`, `device-error`, `settings-back`, `enroll-password-field`, `enroll-confirm`, `disenroll-confirm`.

- [ ] **Step 1: Write the failing test**

Create `android/app/src/androidTest/kotlin/org/secretary/app/DeviceSettingsScreenUiTest.kt`:

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.DeviceSettingsState

class DeviceSettingsScreenUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun unenrolled_showsEnableButton_notDisable() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("enroll-button").assertIsDisplayed()
        composeRule.onAllNodesWithTag("disenroll-button").assertCountEquals(0)
    }

    @Test
    fun enrolled_showsDisableButton_notEnable() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = true),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("disenroll-button").assertIsDisplayed()
        composeRule.onAllNodesWithTag("enroll-button").assertCountEquals(0)
    }

    @Test
    fun enable_opensPasswordDialog_confirmInvokesOnEnroll() {
        var enrolled = false
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false),
                onEnroll = { enrolled = true }, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("enroll-button").performClick()
        composeRule.onNodeWithTag("enroll-password-field").assertIsDisplayed().performTextInput("pw")
        composeRule.onNodeWithTag("enroll-confirm").performClick()
        assertTrue(enrolled)
    }

    @Test
    fun disable_opensConfirmDialog_confirmInvokesOnDisenroll() {
        var disenrolled = false
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = true),
                onEnroll = {}, onDisenroll = { disenrolled = true }, onBack = {},
            )
        }
        composeRule.onNodeWithTag("disenroll-button").performClick()
        composeRule.onNodeWithTag("disenroll-confirm").assertIsDisplayed().performClick()
        assertTrue(disenrolled)
    }

    @Test
    fun error_isDisplayed() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false, error = "boom"),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("device-error").assertIsDisplayed()
    }

    @Test
    fun working_disablesActionButton() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false, working = true),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("enroll-button").assertIsNotEnabled()
    }

    @Test
    fun back_invokesOnBack() {
        var backed = false
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false),
                onEnroll = {}, onDisenroll = {}, onBack = { backed = true },
            )
        }
        composeRule.onNodeWithTag("settings-back").performClick()
        assertTrue(backed)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.DeviceSettingsScreenUiTest`
Expected: FAIL — compilation error, `DeviceSettingsScreen` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/app/src/main/kotlin/org/secretary/app/DeviceSettingsScreen.kt`:

```kotlin
package org.secretary.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
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
import org.secretary.browse.DeviceSettingsState

/**
 * Device-management Settings surface. A pure function of [state] + callbacks (no view-model
 * reference), so it is driven directly in instrumented tests. [onEnroll] receives the password bytes
 * collected by the enroll dialog — AppRoot forwards them to the VM and zeroizes them after.
 *
 * Password hygiene: the dialog's `String`-backed field lingers until GC (same demo-skeleton tradeoff
 * as `UnlockScreen`); the derived `ByteArray` is owned (and zeroized) by AppRoot's [onEnroll] lambda.
 */
@Composable
fun DeviceSettingsScreen(
    state: DeviceSettingsState,
    onEnroll: (password: ByteArray) -> Unit,
    onDisenroll: () -> Unit,
    onBack: () -> Unit,
) {
    var showEnrollDialog by remember { mutableStateOf(false) }
    var showDisenrollDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Device settings")
        Text(
            text = if (state.enrolled) {
                "This device is enrolled for biometric unlock."
            } else {
                "This device is not enrolled for biometric unlock."
            },
            modifier = Modifier.testTag("device-status"),
        )

        if (state.error != null) {
            Text(text = state.error, modifier = Modifier.testTag("device-error"))
        }

        if (state.enrolled) {
            Button(
                onClick = { showDisenrollDialog = true },
                enabled = !state.working,
                modifier = Modifier.fillMaxWidth().testTag("disenroll-button"),
            ) { Text("Disable biometric unlock") }
        } else {
            Button(
                onClick = { showEnrollDialog = true },
                enabled = !state.working,
                modifier = Modifier.fillMaxWidth().testTag("enroll-button"),
            ) { Text("Enable biometric unlock") }
        }

        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth().testTag("settings-back"),
        ) { Text("Back") }
    }

    if (showEnrollDialog) {
        EnrollPasswordDialog(
            onConfirm = { password ->
                showEnrollDialog = false
                onEnroll(password.toByteArray(Charsets.UTF_8))
            },
            onDismiss = { showEnrollDialog = false },
        )
    }

    if (showDisenrollDialog) {
        AlertDialog(
            onDismissRequest = { showDisenrollDialog = false },
            title = { Text("Disable biometric unlock?") },
            text = { Text("You will need your password to open this vault next time.") },
            confirmButton = {
                TextButton(
                    onClick = { showDisenrollDialog = false; onDisenroll() },
                    modifier = Modifier.testTag("disenroll-confirm"),
                ) { Text("Disable") }
            },
            dismissButton = { TextButton(onClick = { showDisenrollDialog = false }) { Text("Cancel") } },
        )
    }
}

/** Password re-prompt for enroll-from-settings; confirm is disabled until a password is entered. */
@Composable
private fun EnrollPasswordDialog(onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Enable biometric unlock") },
        text = {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Vault password") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("enroll-password-field"),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(password) },
                enabled = password.isNotEmpty(),
                modifier = Modifier.testTag("enroll-confirm"),
            ) { Text("Enable") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd android && ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.DeviceSettingsScreenUiTest`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-settings
git add android/app/src/main/kotlin/org/secretary/app/DeviceSettingsScreen.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/DeviceSettingsScreenUiTest.kt
git commit -m "feat(android): DeviceSettingsScreen with enroll/disenroll dialogs"
```

---

### Task 3: Wire Settings into `AppRoot` + a Browse entry affordance

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`
- Modify: `android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt`
- Test: `android/app/src/androidTest/kotlin/org/secretary/app/BrowseWithSyncSettingsEntryUiTest.kt` (new)

**Interfaces:**
- Consumes: Task 1 `DeviceSettingsViewModel`/`DeviceSettingsState`; Task 2 `DeviceSettingsScreen`; existing `unlockAndOpen(...)`, `DeviceUnlockCoordinator`, `BrowseSession`.
- Produces: `BrowseWithSyncScreen(browse, sync, onOpenSettings: () -> Unit = {})` (new param, defaulted so the existing test compiles); testTag `open-settings`. `Route.Browse(session, folder, showSettings=false)`.

- [ ] **Step 1: Write the failing test (the Browse entry affordance)**

Create `android/app/src/androidTest/kotlin/org/secretary/app/BrowseWithSyncSettingsEntryUiTest.kt`:

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.UnlockCredential
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/** Proves the Browse screen exposes a settings entry that invokes its callback. Built over the real
 *  `.so` session (like BrowseWithSyncScreenUiTest) so it exercises the production composition path. */
@RunWith(AndroidJUnit4::class)
class BrowseWithSyncSettingsEntryUiTest {
    @get:Rule val composeRule = createAndroidComposeRule<androidx.activity.ComponentActivity>()

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun browse_showsSettingsEntry_andInvokesCallback() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        toClean += stateBase
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        val pw = "correct horse battery staple".toByteArray()
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                UnlockCredential.Password(pw))
        }
        pw.fill(0)

        var opened = false
        composeRule.setContent {
            BrowseWithSyncScreen(browse = session.browse, sync = session.sync,
                onOpenSettings = { opened = true })
        }
        composeRule.onNodeWithTag("open-settings").assertIsDisplayed().performClick()
        assertTrue(opened)

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd android && ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.BrowseWithSyncSettingsEntryUiTest`
Expected: FAIL — `onOpenSettings` is not a parameter / no `open-settings` node.

- [ ] **Step 3a: Add the entry affordance to `BrowseWithSyncScreen`**

Replace the body of `android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt` with:

```kotlin
package org.secretary.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import org.secretary.browse.ui.BrowseScreen
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.sync.ui.SyncScreen
import org.secretary.sync.ui.VaultSyncViewModel

/**
 * The unified browse+sync screen: the sync badge (and its password/conflict sheets, owned by the
 * reused [SyncScreen]) sit above the [BrowseScreen] content, with a "Device settings" entry that
 * invokes [onOpenSettings] (AppRoot routes to the Settings sub-view). Holds NO state.
 */
@Composable
fun BrowseWithSyncScreen(
    browse: VaultBrowseViewModel,
    sync: VaultSyncViewModel,
    onOpenSettings: () -> Unit = {},
) {
    Column(modifier = Modifier.fillMaxSize()) {
        SyncScreen(viewModel = sync)
        TextButton(
            onClick = onOpenSettings,
            modifier = Modifier.align(Alignment.End).testTag("open-settings"),
        ) { Text("Device settings") }
        HorizontalDivider()
        BrowseScreen(viewModel = browse)
    }
}
```

- [ ] **Step 3b: Extend the route and wire the Settings VM in `AppRoot`**

In `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`:

1. Add imports near the other `org.secretary.browse` imports:

```kotlin
import org.secretary.browse.DeviceSettingsState
import org.secretary.browse.DeviceSettingsViewModel
```

2. Replace the `Route.Browse` declaration:

```kotlin
private sealed interface Route {
    data object Unlock : Route
    data class Browse(
        val session: BrowseSession,
        val folder: File,
        val showSettings: Boolean = false,
    ) : Route
}
```

3. After the existing `deviceVm` / `deviceState` block (around line 70-76), add the settings VM + mirror:

```kotlin
    val settingsVm = remember(coordinator) { DeviceSettingsViewModel(coordinator) }
    var settingsState by remember { mutableStateOf(DeviceSettingsState(enrolled = false)) }
```

4. Replace the whole `is Route.Browse -> { … }` branch with:

```kotlin
        is Route.Browse -> {
            // Monitor + session lifecycle keyed on the SESSION instance only — flipping showSettings
            // keeps the same instance, so a Settings excursion never disposes/locks the vault. Only
            // ON_STOP (→ Route.Unlock) tears it down.
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
            // Refresh enrolled-vs-not (prompt-free) whenever the Settings sub-view is entered.
            LaunchedEffect(r.showSettings) {
                if (r.showSettings) {
                    settingsVm.refresh()
                    settingsState = settingsVm.state
                }
            }
            if (r.showSettings) {
                DeviceSettingsScreen(
                    state = settingsState,
                    onEnroll = { password ->
                        scope.launch {
                            try {
                                settingsVm.enroll(r.folder.path, vaultId, password)
                            } finally {
                                password.fill(0) // zeroize the re-prompted password on every exit
                            }
                            settingsState = settingsVm.state
                        }
                    },
                    onDisenroll = {
                        scope.launch {
                            settingsVm.disenroll(r.folder.path)
                            settingsState = settingsVm.state
                        }
                    },
                    onBack = { route = r.copy(showSettings = false) },
                )
            } else {
                BrowseWithSyncScreen(
                    browse = r.session.browse,
                    sync = r.session.sync,
                    onOpenSettings = { route = r.copy(showSettings = true) },
                )
            }
        }
```

5. Update `unlockAndOpen` to capture and return the folder. Change its return statements and signature so the `Route.Browse` it returns carries `folder`:

   - In the success path, replace `return Route.Browse(session)` with `return Route.Browse(session, folder)`.

   (`folder` is already a local `val folder = AppVaultProvisioning.stageGoldenVault(context)` in that function — no new plumbing needed.)

- [ ] **Step 4: Run the new entry test + full host suite + regression smokes**

```bash
cd android && ./gradlew :vault-access:test :kit:test :app:testDebugUnitTest :browse-ui:test
cd android && ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.BrowseWithSyncSettingsEntryUiTest
cd android && ANDROID_SERIAL=emulator-5554 PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.OpenWithDeviceSecretSmokeTest
```
Expected: host BUILD SUCCESSFUL; new entry test 1/1; device-secret regression smoke 1/1. (The existing `BrowseWithSyncScreenUiTest` still compiles — `onOpenSettings` is defaulted.)

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-settings
git add android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
        android/app/src/main/kotlin/org/secretary/app/BrowseWithSyncScreen.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/BrowseWithSyncSettingsEntryUiTest.kt
git commit -m "feat(android): reach DeviceSettingsScreen from Browse; thread vault folder"
```

---

### Task 4: Docs (README + ROADMAP)

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Locate the C.3 Android rows**

Run: `grep -n "device" README.md ROADMAP.md | grep -iE "biometric|device-open|slice|enroll"`
Expected: shows the slice-1/slice-2 device-open lines to append a sibling row beside.

- [ ] **Step 2: Add a device-settings line to README.md**

Add a brief dot-point under the Android status section (keep it terse per the README style — no test-count walls), e.g.:

```markdown
- Device-management Settings: view biometric-enrollment status, enroll (with password re-prompt) or disenroll this device.
```

- [ ] **Step 3: Add a ROADMAP.md row**

Add a row beside the C.3 Android device-open entries marking the enrollment/settings UI shipped (✅, 2026-06-19), matching the existing row format in that section.

- [ ] **Step 4: Verify guardrails (Android-only)**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-settings
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format' || echo "OK: no core/ffi/format"
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md)' || echo "OK: android/docs only"
```
Expected: both print their `OK:` line (empty matches).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/c3-android-device-settings
git add README.md ROADMAP.md
git commit -m "docs: note Android device-management Settings surface"
```

---

## Manual on-device proof (after Task 3, before PR)

On the NX809J (Android 16): install the app, password-unlock, open **Device settings** → **Enable biometric unlock** → enter the vault password → complete the enroll-time biometric prompt → status flips to "enrolled". Background + reopen → "Unlock with biometrics" works. Return to **Device settings** → **Disable biometric unlock** → confirm → status flips to "not enrolled"; the next open falls back to password-only.

## Final whole-branch review + handoff

After Task 4: request a whole-branch code review (security-critical secret-hygiene focus on the re-prompt password path + the conflated error messaging), fix all findings in-task, then author the handoff per `/nextsession` (symlink-retarget model) and open the PR.
