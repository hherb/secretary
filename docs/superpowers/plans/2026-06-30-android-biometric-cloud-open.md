# Android biometric cloud-vault OPEN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an enrolled device open a cloud (SAF) vault by biometric, mirroring the demo biometric-open path.

**Architecture:** Purely additive Android UI orchestration in `AppRoot.kt` plus one new pure helper. The credential pipeline (`openCloudTarget → openCloudBrowse → openBrowseWithSync → openWithCredential → openWithDeviceSecret`) and the biometric coordinator (`cloudDeviceUnlockCoordinator` / `DeviceUnlockViewModel.unlockWithBiometrics`) already exist from #333; this wires them together at the unlock screen. **No `CloudVaultOpen.kt` / `UnlockScreen.kt` / `:kit` / `:vault-access` / `core` / FFI / on-disk-format / spec / conformance change.**

**Tech Stack:** Kotlin, Jetpack Compose, JUnit 5 (host unit tests under `:app/src/test`), Compose UI test + AndroidJUnit (instrumented under `:app/src/androidTest`).

## Global Constraints

- **Module boundary:** changes live in `android/app` only (Kotlin/Compose). Do **not** touch `:kit`, `:vault-access`, `core`, `ffi`, or any on-disk format / spec / conformance / conflict-KAT.
- **Pure helpers:** new decision logic is a free function with no Compose/Android types in its body (`unlockBiometricEnrolled`), host-tested.
- **Secret hygiene:** the device-secret credential bytes are zeroized by the existing `finally` blocks in `openCloudTarget`/`openCloudBrowse` — do not add a new zeroize site and do not stash the credential.
- **Biometric vaultId guard:** the cloud biometric unlock passes `vaultId = cdu.metadataVaultId ?: ""` to `unlockWithBiometrics` — `DeviceUnlockCoordinator.unlock` guards `enrollment.vaultId == vaultId` before prompting (else `VaultSlotMismatch`). The location's `vaultUuidHex` may be empty/stale; the enrolled id is correct.
- **In-flight flag:** the cloud `onBiometricUnlock` branch sets `isUnlocking = true` synchronously and resets it in a `finally` (mirrors the demo path; prevents a double-tap launching two prompts).
- **Cancel keeps the button:** after `unlockWithBiometrics` returns, recompute `cloudEnrolled = cdu.coordinator.isEnrolled` so a cancelled/failed prompt does not strand the user on the password-only screen (`LaunchedEffect(route)` will not re-fire).
- **Host gate (must stay green):** `./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`.
- **Acceptance bar:** host gate + emulator-5554 instrumented; on-device RedMagic run deferred to a manual follow-up.
- **Commands run from the worktree:** `cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android`. The Gradle wrapper is `./gradlew` there. The emulator/adb need absolute paths (`~/Library/Android/sdk/platform-tools/adb`).

---

### Task 1: Pure `unlockBiometricEnrolled` helper + host test

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/CloudBiometric.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/UnlockBiometricEnrolledTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces: `fun unlockBiometricEnrolled(isCloudTarget: Boolean, demoEnrolled: Boolean, cloudEnrolled: Boolean): Boolean` — returns `cloudEnrolled` when `isCloudTarget`, else `demoEnrolled`. Consumed by Task 2 (`AppRoot.kt`).

- [ ] **Step 1: Write the failing test**

Create `android/app/src/test/kotlin/org/secretary/app/UnlockBiometricEnrolledTest.kt`:

```kotlin
package org.secretary.app

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class UnlockBiometricEnrolledTest {
    @Test fun cloudTarget_enrolled_isTrue() {
        assertTrue(unlockBiometricEnrolled(isCloudTarget = true, demoEnrolled = false, cloudEnrolled = true))
    }

    @Test fun cloudTarget_unenrolled_isFalse() {
        assertFalse(unlockBiometricEnrolled(isCloudTarget = true, demoEnrolled = true, cloudEnrolled = false))
    }

    @Test fun demoTarget_followsDemoEnrolled_true() {
        assertTrue(unlockBiometricEnrolled(isCloudTarget = false, demoEnrolled = true, cloudEnrolled = false))
    }

    @Test fun demoTarget_followsDemoEnrolled_false() {
        assertFalse(unlockBiometricEnrolled(isCloudTarget = false, demoEnrolled = false, cloudEnrolled = true))
    }

    @Test fun cloudBranch_ignoresDemoEnrolled() {
        // cloud target: demoEnrolled must not leak in
        assertFalse(unlockBiometricEnrolled(isCloudTarget = true, demoEnrolled = true, cloudEnrolled = false))
    }

    @Test fun demoBranch_ignoresCloudEnrolled() {
        // demo target: cloudEnrolled must not leak in
        assertFalse(unlockBiometricEnrolled(isCloudTarget = false, demoEnrolled = false, cloudEnrolled = true))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.UnlockBiometricEnrolledTest"`
Expected: FAIL — compile error, `unlockBiometricEnrolled` is unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/app/src/main/kotlin/org/secretary/app/CloudBiometric.kt`:

```kotlin
package org.secretary.app

/**
 * Whether the unlock screen should offer biometric unlock for the current target.
 *
 * The unlock screen serves both the demo/local vault and a cloud (SAF) vault. The biometric
 * affordance is enrollment-scoped per target: a cloud target uses its own per-cloud-vault enclave
 * ([cloudEnrolled]), the demo target uses the demo enclave ([demoEnrolled]). This is the single
 * decision that replaces the old demo-only inline check (`cloudTarget == null && state is Enrolled`)
 * now that cloud open supports biometrics too.
 *
 * Pure and total: a cloud target follows [cloudEnrolled] and never [demoEnrolled], a demo target
 * follows [demoEnrolled] and never [cloudEnrolled] — no cross-talk between the two namespaces.
 */
fun unlockBiometricEnrolled(
    isCloudTarget: Boolean,
    demoEnrolled: Boolean,
    cloudEnrolled: Boolean,
): Boolean = if (isCloudTarget) cloudEnrolled else demoEnrolled
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.UnlockBiometricEnrolledTest"`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337
git add android/app/src/main/kotlin/org/secretary/app/CloudBiometric.kt \
        android/app/src/test/kotlin/org/secretary/app/UnlockBiometricEnrolledTest.kt
git commit -m "feat(android): pure unlockBiometricEnrolled helper for cloud biometric open (#337)"
```

---

### Task 2: Wire cloud biometric open into `AppRoot.kt`

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`

**Interfaces:**
- Consumes: `unlockBiometricEnrolled(...)` (Task 1); existing `cloudDeviceUnlockCoordinator(activity, noBackupBase, cloudKey)` → `CloudDeviceUnlock` (with `.coordinator`, `.metadataVaultId`, `.coordinator.isEnrolled`); existing `cloudVaultKey(treeUri)`; existing `DeviceUnlockViewModel(coordinator).unlockWithBiometrics(vaultId, reason, onCredential)`; existing `openCloudTarget(context, activity, target, credential, enrollThisDevice, locationStore, selectionVm): Route`.
- Produces: no new public symbols (internal wiring only).

> **Context for the implementer:** `AppRoot.kt` is a single large `@Composable`. You are adding (a) one new Compose state var, (b) a clause inside the existing `LaunchedEffect(route)`, (c) a changed `isEnrolled` argument on the `UnlockScreen` call, and (d) a cloud branch inside the existing `onBiometricUnlock` lambda. The demo branch is unchanged. This task has no host unit test (it is Compose/Android glue over real Keystore/SAF/FFI); it is verified by `:app:compileDebugKotlin` here and the Task 3 instrumented test. Commit it as one unit.

- [ ] **Step 1: Add the `cloudEnrolled` state var**

In `AppRoot()`, immediately after the existing line:

```kotlin
    var deviceState by remember { mutableStateOf<DeviceUnlockState>(DeviceUnlockState.Unenrolled) }
```

add:

```kotlin
    // Per-cloud-vault biometric enrollment, computed prompt-free on entering a cloud Unlock screen
    // (see LaunchedEffect(route)). Drives whether the biometric button shows for a cloud target.
    var cloudEnrolled by remember { mutableStateOf(false) }
```

- [ ] **Step 2: Compute `cloudEnrolled` on entering a cloud Unlock screen**

Replace the existing `LaunchedEffect(route)` block:

```kotlin
    LaunchedEffect(route) {
        if (route is Route.Unlock) {
            deviceVm.refresh()
            deviceState = deviceVm.state
        }
        if (route is Route.Selection) {
            selectionVm.loadPersisted()
            selectionState = selectionVm.state
        }
    }
```

with:

```kotlin
    LaunchedEffect(route) {
        val current = route
        if (current is Route.Unlock) {
            deviceVm.refresh()
            deviceState = deviceVm.state
            // For a cloud target, read its per-cloud-vault enrollment (enclave blob AND metadata),
            // keyed by the cloud treeUri. Cheap and prompt-free (constructs the Keystore wrapper but
            // never releases). Demo targets leave cloudEnrolled false (the demo path drives the button).
            val cloudTarget = current.cloudTarget
            cloudEnrolled = if (cloudTarget != null) {
                cloudDeviceUnlockCoordinator(
                    activity,
                    context.noBackupFilesDir,
                    cloudVaultKey(cloudTarget.location.treeUri),
                ).coordinator.isEnrolled
            } else {
                false
            }
        }
        if (current is Route.Selection) {
            selectionVm.loadPersisted()
            selectionState = selectionVm.state
        }
    }
```

- [ ] **Step 3: Drive `UnlockScreen.isEnrolled` through the pure helper**

In the `is Route.Unlock ->` branch, replace the existing `isEnrolled` argument and its comment:

```kotlin
            // The biometric-OPEN button is demo-only (cloud open stays password-based this session), so hide it
            // for a cloud target. The "Remember this device" checkbox (shown when !isEnrolled) IS live for cloud:
            // ticking it enrolls a device secret for write-reauth after the password open (see openCloudTarget).
            isEnrolled = r.cloudTarget == null && deviceState is DeviceUnlockState.Enrolled,
```

with:

```kotlin
            // Biometric-OPEN is now available for a cloud target too (#337): a cloud target follows its
            // per-cloud-vault enrollment (cloudEnrolled), the demo target follows the demo enclave. The
            // "Remember this device" checkbox (shown when !isEnrolled) stays live for enrolling a new device.
            isEnrolled = unlockBiometricEnrolled(
                isCloudTarget = r.cloudTarget != null,
                demoEnrolled = deviceState is DeviceUnlockState.Enrolled,
                cloudEnrolled = cloudEnrolled,
            ),
```

- [ ] **Step 4: Add the cloud branch to `onBiometricUnlock`**

Replace the entire existing `onBiometricUnlock = { ... }` lambda:

```kotlin
            onBiometricUnlock = {
                // Publish the in-flight flag synchronously (see onUnlock) so a double-tap can't launch
                // two concurrent biometric prompts before the button disables.
                isUnlocking = true
                scope.launch {
                    try {
                        deviceVm.unlockWithBiometrics(
                            vaultId = vaultId,
                            reason = "Unlock your vault",
                        ) { credential -> route = unlockAndOpen(context, scope, credential, enrollAfter = false, coordinator, vaultId) }
                        // On success we've already routed to Browse. On a failed/cancelled prompt the VM
                        // leaves state=Failed; recompute enrolled-vs-unenrolled from the blob (prompt-free)
                        // so the "Unlock with biometrics" button persists — a cancel must not strand the
                        // user on the password-only screen (LaunchedEffect(route) won't re-fire here).
                        deviceVm.refresh()
                        deviceState = deviceVm.state
                    } finally {
                        isUnlocking = false
                    }
                }
            },
```

with:

```kotlin
            onBiometricUnlock = {
                // Publish the in-flight flag synchronously (see onUnlock) so a double-tap can't launch
                // two concurrent biometric prompts before the button disables.
                isUnlocking = true
                scope.launch {
                    try {
                        val cloudTarget = r.cloudTarget
                        if (cloudTarget != null) {
                            // Cloud biometric open: build the per-cloud-vault coordinator, release the
                            // secret behind the prompt, then route the DeviceSecret credential through the
                            // SAME openCloudTarget pipeline the password path uses (enrollThisDevice=false:
                            // a biometric unlock means the device is already enrolled). The vaultId guard
                            // is the ENROLLED id (metadataVaultId): the location's UUID may be empty/stale,
                            // and DeviceUnlockCoordinator.unlock checks enrollment.vaultId == vaultId before
                            // prompting. The open itself uses the deviceUuid carried in the credential.
                            val cdu = cloudDeviceUnlockCoordinator(
                                activity,
                                context.noBackupFilesDir,
                                cloudVaultKey(cloudTarget.location.treeUri),
                            )
                            DeviceUnlockViewModel(cdu.coordinator).unlockWithBiometrics(
                                vaultId = cdu.metadataVaultId ?: "",
                                reason = "Unlock your vault",
                            ) { credential ->
                                route = openCloudTarget(
                                    context, activity, cloudTarget, credential,
                                    enrollThisDevice = false, locationStore, selectionVm,
                                ).also { result ->
                                    selectionState = selectionVm.state
                                    if (result is Route.Unlock) {
                                        Toast.makeText(
                                            context,
                                            "Couldn't open the cloud vault — check the folder is reachable, then try again.",
                                            Toast.LENGTH_LONG,
                                        ).show()
                                    }
                                }
                            }
                            // Recompute prompt-free so a cancel/failed prompt keeps the button (the screen
                            // stays on Unlock; LaunchedEffect(route) won't re-fire).
                            cloudEnrolled = cdu.coordinator.isEnrolled
                        } else {
                            deviceVm.unlockWithBiometrics(
                                vaultId = vaultId,
                                reason = "Unlock your vault",
                            ) { credential -> route = unlockAndOpen(context, scope, credential, enrollAfter = false, coordinator, vaultId) }
                            // On success we've already routed to Browse. On a failed/cancelled prompt the VM
                            // leaves state=Failed; recompute enrolled-vs-unenrolled from the blob (prompt-free)
                            // so the "Unlock with biometrics" button persists — a cancel must not strand the
                            // user on the password-only screen (LaunchedEffect(route) won't re-fire here).
                            deviceVm.refresh()
                            deviceState = deviceVm.state
                        }
                    } finally {
                        isUnlocking = false
                    }
                }
            },
```

- [ ] **Step 5: Verify it compiles (both main + androidTest source sets)**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android && ./gradlew :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`
Expected: BUILD SUCCESSFUL. (No new warnings; `r.cloudTarget` smart-casts to non-null inside the `if`.)

- [ ] **Step 6: Run the host gate to confirm nothing regressed**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android && ./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test`
Expected: BUILD SUCCESSFUL (all existing tests + Task 1's pass).

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337
git add android/app/src/main/kotlin/org/secretary/app/AppRoot.kt
git commit -m "feat(android): wire biometric open for cloud vaults in AppRoot (#337)"
```

---

### Task 3: Instrumented UI test — biometric button on the cloud-titled unlock screen

**Files:**
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/CloudBiometricUnlockUiTest.kt`

**Interfaces:**
- Consumes: the existing `UnlockScreen(title, isEnrolled, rememberDevice, isUnlocking, onUnlock, onEnrollChoice, onBiometricUnlock)` composable and its `biometric-unlock` testTag.
- Produces: nothing.

> **Context for the implementer:** `UnlockScreen` is unchanged by this feature; it already renders the biometric button for any `isEnrolled == true`. This test pins that the affordance is present on a **cloud-titled** unlock screen (asserting the #332 per-target title and the #337 biometric button coexist) and absent when unenrolled. Mirror the structure of `UnlockScreenDeviceUiTest.kt` exactly (same imports, same `createComposeRule`).

- [ ] **Step 1: Write the test**

Create `android/app/src/androidTest/kotlin/org/secretary/app/CloudBiometricUnlockUiTest.kt`:

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The biometric-unlock affordance must be available on a CLOUD-titled unlock screen (#337), not just
 * the demo vault. UnlockScreen is credential-agnostic, so this pins the integration contract: a
 * cloud title + an enrolled state render the biometric button, and an unenrolled cloud screen hides it.
 */
class CloudBiometricUnlockUiTest {
    @get:Rule val composeRule = createComposeRule()

    private val cloudTitle = "Secretary — My Cloud Vault"

    @Test
    fun cloudEnrolled_showsBiometricUnlockButton_andInvokesCallback() {
        var biometricTapped = false
        composeRule.setContent {
            UnlockScreen(
                title = cloudTitle,
                isEnrolled = true,
                rememberDevice = false,
                isUnlocking = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = { biometricTapped = true },
            )
        }
        composeRule.onNodeWithTag("biometric-unlock").assertIsDisplayed().assertIsEnabled().performClick()
        assertTrue(biometricTapped)
    }

    @Test
    fun cloudUnenrolled_hidesBiometricButton() {
        composeRule.setContent {
            UnlockScreen(
                title = cloudTitle,
                isEnrolled = false,
                rememberDevice = false,
                isUnlocking = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = {},
            )
        }
        composeRule.onNodeWithTag("biometric-unlock").assertDoesNotExist()
    }
}
```

- [ ] **Step 2: Confirm the emulator is online**

Run: `~/Library/Android/sdk/platform-tools/adb devices`
Expected: `emulator-5554   device` is listed. (If absent, boot `Medium_Phone_API_36.1` first — see the closing inventory.)

- [ ] **Step 3: Run the instrumented test**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android && ./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.CloudBiometricUnlockUiTest`
Expected: BUILD SUCCESSFUL, 2/2 passed. (Per the Android instrumented-test gotcha note: use `-Pandroid.testInstrumentationRunnerArguments.class=`, NOT `--tests`.)

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337
git add android/app/src/androidTest/kotlin/org/secretary/app/CloudBiometricUnlockUiTest.kt
git commit -m "test(android): instrumented cloud-titled biometric-unlock button (#337)"
```

---

### Task 4: Full host gate + docs (README / ROADMAP)

**Files:**
- Modify: `README.md` (Android status row, if present)
- Modify: `ROADMAP.md` (C.3 / cloud-biometric clause)

**Interfaces:** none.

- [ ] **Step 1: Run the full host gate**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337/android && ./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 2: Update README.md and ROADMAP.md**

Read the current Android status text in both files. Update the cloud-vault biometric line to reflect that cloud **open** (not just write-reauth) is now biometric. Keep it brief per the README style (dot points, no test-count walls). Example edit to the cloud biometric line: "cloud-vault device enrollment + biometric write-reauth **and open**".

If neither file references Android cloud biometric specifically, add one concise dot point under the existing Android section. Do not invent a status that overstates scope (open is emulator-verified; on-device deferred).

- [ ] **Step 3: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-biometric-cloud-open-337
git add README.md ROADMAP.md
git commit -m "docs: README + ROADMAP — Android cloud biometric open (#337)"
```

---

## Self-Review

**Spec coverage:**
- Query per-cloud enrollment at screen entry → Task 2 Step 2. ✓
- Show biometric button for an enrolled cloud target → Task 2 Step 3 (`unlockBiometricEnrolled`, Task 1). ✓
- Route `DeviceSecret` through `openCloudTarget(enrollThisDevice=false)` → Task 2 Step 4. ✓
- Existing Toast on biometric-open failure (no silent return) → Task 2 Step 4 (`if (result is Route.Unlock)` Toast). ✓
- `vaultId = metadataVaultId` guard → Task 2 Step 4 + Global Constraints. ✓
- Host unit test (totality) → Task 1. ✓
- Instrumented UI test (cloud-titled button shown/absent) → Task 3. ✓
- Host gate green + README/ROADMAP → Task 4. ✓
- Out of scope (settings toggle, cloud error re-plumbing, recovery-cloud) → not in any task. ✓

**Placeholder scan:** none — every step shows full code or an exact command.

**Type consistency:** `unlockBiometricEnrolled(isCloudTarget, demoEnrolled, cloudEnrolled)` defined in Task 1, called with the same parameter names in Task 2 Step 3. `cloudDeviceUnlockCoordinator(activity, noBackupBase, cloudKey)` and `.coordinator`/`.metadataVaultId`/`.coordinator.isEnrolled` match `CloudDeviceUnlock` in `CloudDeviceUnlock.kt`. `openCloudTarget(context, activity, target, credential, enrollThisDevice, locationStore, selectionVm)` matches `CloudVaultOpen.kt:198`. `cloudVaultKey(treeUri)` matches `ProvisioningRouting.kt:29`. `DeviceUnlockViewModel(coordinator).unlockWithBiometrics(vaultId, reason, onCredential)` matches `DeviceUnlockViewModel.kt:44`. ✓
