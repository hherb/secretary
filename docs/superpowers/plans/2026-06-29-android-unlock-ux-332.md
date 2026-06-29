# Android UnlockScreen UX Polish (#332) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Android walking-skeleton unlock flow a progress affordance during the multi-second Argon2id open, a typed error message on a failed demo/password unlock, and a target-specific screen title.

**Architecture:** Two pure host-tested helpers in `:app` derive the title and the failure message; `UnlockScreen` gains `title` + `isUnlocking` parameters to render a spinner and disable controls; `AppRoot` owns the `isUnlocking` flag (set around all three open entry points) and shows the typed Toast from `unlockAndOpen`'s existing `catch`.

**Tech Stack:** Kotlin, Jetbrains Compose (Material 3), JUnit 5 (jupiter) for `:app` host tests, AndroidX Compose UI test for instrumented tests, Gradle.

## Global Constraints

- **Module scope:** `android/app` only. No change to `:vault-access`, `:kit`, core Rust, on-disk format, FFI surface, spec, conformance, or conflict KATs.
- **No magic numbers / strings:** all user-facing copy and the title prefix are `private const val` declarations.
- **Pure functions in reusable modules:** the title and message derivations are free functions with no side effects and no Android/Compose types in their bodies (beyond the `CloudVaultTarget?` / `Throwable` inputs).
- **TDD:** failing host test first for the pure helpers; instrumented assertions for the composable behavior.
- **Files under ~500 lines:** the new helper file is small; `UnlockScreen.kt` and `AppRoot.kt` stay well under.
- **Working dir:** all paths are inside the worktree `.worktrees/android-unlock-ux-332/`. Run Gradle from `.worktrees/android-unlock-ux-332/android`. Android SDK tools need absolute paths (`~/Library/Android/sdk/platform-tools/adb`).
- **`:app` host-test framework is JUnit 5** — use `org.junit.jupiter.api.Test` and `org.junit.jupiter.api.Assertions.*` (mirror `VaultUuidParsingTest`).
- **Commit trailer:** end every commit message with
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

---

### Task 1: Pure helpers — `unlockScreenTitle` + `unlockFailureMessage`

**Files:**
- Create: `android/app/src/main/kotlin/org/secretary/app/UnlockMessages.kt`
- Test: `android/app/src/test/kotlin/org/secretary/app/UnlockMessagesTest.kt`

**Interfaces:**
- Consumes: `CloudVaultTarget` (already defined in `org.secretary.app.CloudVaultOpen`, fields `location: VaultLocation`, `workingDir: File`, `isCreate: Boolean`); `org.secretary.browse.VaultBrowseError` (sealed; arms used here: `WrongPasswordOrCorrupt`, `WrongRecoveryOrCorrupt`, `InvalidRecoveryPhrase(val detail: String)`); `org.secretary.browse.VaultLocation(displayName, treeUri, vaultUuidHex = "")`.
- Produces:
  - `fun unlockScreenTitle(cloudTarget: CloudVaultTarget?): String`
  - `fun unlockFailureMessage(error: Throwable): String`

- [ ] **Step 1: Write the failing test**

Create `android/app/src/test/kotlin/org/secretary/app/UnlockMessagesTest.kt`:

```kotlin
package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultLocation
import java.io.File

class UnlockMessagesTest {

    private fun cloudTarget(displayName: String): CloudVaultTarget =
        CloudVaultTarget(
            location = VaultLocation(displayName = displayName, treeUri = "content://tree/x"),
            workingDir = File("/tmp/working"),
            isCreate = false,
        )

    @Test
    fun titleForDemoTargetIsTheDemoVaultTitle() {
        assertEquals("Secretary — demo vault", unlockScreenTitle(null))
    }

    @Test
    fun titleForCloudTargetUsesItsDisplayName() {
        assertEquals("Secretary — Family Drive", unlockScreenTitle(cloudTarget("Family Drive")))
    }

    @Test
    fun wrongPasswordMapsToTheWrongPasswordMessage() {
        assertEquals(
            "Wrong password, or the vault is damaged.",
            unlockFailureMessage(VaultBrowseError.WrongPasswordOrCorrupt),
        )
    }

    @Test
    fun wrongRecoveryMapsToTheWrongRecoveryMessage() {
        assertEquals(
            "Wrong recovery phrase, or the vault is damaged.",
            unlockFailureMessage(VaultBrowseError.WrongRecoveryOrCorrupt),
        )
    }

    @Test
    fun invalidRecoveryPhraseInterpolatesItsDetail() {
        assertEquals(
            "Invalid recovery phrase: word 3 is not in the wordlist",
            unlockFailureMessage(VaultBrowseError.InvalidRecoveryPhrase("word 3 is not in the wordlist")),
        )
    }

    @Test
    fun unknownThrowableMapsToTheGenericMessage() {
        assertEquals(
            "Couldn't open the vault. Please try again.",
            unlockFailureMessage(RuntimeException("boom")),
        )
    }

    @Test
    fun otherVaultBrowseErrorArmMapsToTheGenericMessage() {
        assertEquals(
            "Couldn't open the vault. Please try again.",
            unlockFailureMessage(VaultBrowseError.FolderInvalid("nope")),
        )
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/android-unlock-ux-332/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.UnlockMessagesTest"`
Expected: FAIL — compilation error, `unlockScreenTitle` / `unlockFailureMessage` unresolved.

- [ ] **Step 3: Write minimal implementation**

Create `android/app/src/main/kotlin/org/secretary/app/UnlockMessages.kt`:

```kotlin
package org.secretary.app

import org.secretary.browse.VaultBrowseError

/**
 * Pure derivations for the Unlock screen's chrome — kept free of Compose/Android types so they are
 * host-testable in `:app/src/test`. [UnlockScreen] and [AppRoot] consume these; nothing here has side
 * effects.
 */

/** Title prefix shared by every unlock target. */
private const val TITLE_PREFIX = "Secretary — "

/** Suffix for the demo (golden) vault — the [CloudVaultTarget]-less path. */
private const val DEMO_VAULT_SUFFIX = "demo vault"

private const val MSG_WRONG_PASSWORD = "Wrong password, or the vault is damaged."
private const val MSG_WRONG_RECOVERY = "Wrong recovery phrase, or the vault is damaged."
private const val MSG_INVALID_PHRASE_PREFIX = "Invalid recovery phrase: "
private const val MSG_GENERIC = "Couldn't open the vault. Please try again."

/**
 * The Unlock screen title for [cloudTarget]: the demo-vault title when null (the golden-vault path),
 * otherwise the cloud folder's display name. Lets the user tell which vault they are unlocking (#332).
 */
fun unlockScreenTitle(cloudTarget: CloudVaultTarget?): String =
    TITLE_PREFIX + (cloudTarget?.location?.displayName ?: DEMO_VAULT_SUFFIX)

/**
 * A user-facing message for a failed demo/password open. Maps the typed [VaultBrowseError] arms the
 * open port can raise (wrong password/recovery — conflated with corruption per the threat model §13;
 * malformed recovery phrase — safe to surface verbatim) and folds everything else (IO/SAF/unknown)
 * to a generic message. Total over [Throwable] (#332).
 */
fun unlockFailureMessage(error: Throwable): String = when (error) {
    is VaultBrowseError.WrongPasswordOrCorrupt -> MSG_WRONG_PASSWORD
    is VaultBrowseError.WrongRecoveryOrCorrupt -> MSG_WRONG_RECOVERY
    is VaultBrowseError.InvalidRecoveryPhrase -> MSG_INVALID_PHRASE_PREFIX + error.detail
    else -> MSG_GENERIC
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd .worktrees/android-unlock-ux-332/android && ./gradlew :app:testDebugUnitTest --tests "org.secretary.app.UnlockMessagesTest"`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/UnlockMessages.kt \
        android/app/src/test/kotlin/org/secretary/app/UnlockMessagesTest.kt
git commit -m "feat(android): pure unlock title + typed failure-message helpers (#332)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `UnlockScreen` — `title` + `isUnlocking` (spinner + disabled controls)

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`
- Modify: `android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenRecoveryUiTest.kt` (new required params)
- Modify: `android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenDeviceUiTest.kt` (new required params)
- Test: `android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenProgressUiTest.kt` (create)

**Interfaces:**
- Consumes: `unlockScreenTitle` (Task 1) is used by the caller (Task 3), not here; this task only adds the parameters.
- Produces: updated signature
  ```kotlin
  fun UnlockScreen(
      title: String,
      isEnrolled: Boolean,
      rememberDevice: Boolean,
      isUnlocking: Boolean,
      onUnlock: (UnlockCredential) -> Unit,
      onEnrollChoice: (Boolean) -> Unit,
      onBiometricUnlock: () -> Unit,
  )
  ```
  New testTag: `unlock-progress` (the in-flight `CircularProgressIndicator`). Existing tags unchanged.

- [ ] **Step 1: Write the failing instrumented test**

Create `android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenProgressUiTest.kt`:

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertDoesNotExist
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import org.junit.Rule
import org.junit.Test

class UnlockScreenProgressUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun whenUnlocking_showsSpinnerAndDisablesControls() {
        composeRule.setContent {
            UnlockScreen(
                title = "Secretary — Family Drive",
                isEnrolled = false,
                rememberDevice = false,
                isUnlocking = true,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = {},
            )
        }

        composeRule.onNodeWithText("Secretary — Family Drive").assertIsDisplayed()
        composeRule.onNodeWithTag("unlock-progress").assertIsDisplayed()
        composeRule.onNodeWithTag("unlock-button").assertIsNotEnabled()
        composeRule.onNodeWithTag("password-field").assertIsNotEnabled()
        composeRule.onNodeWithTag("mode-password").assertIsNotEnabled()
    }

    @Test
    fun whenNotUnlocking_titleRendersAndNoSpinner() {
        composeRule.setContent {
            UnlockScreen(
                title = "Secretary — demo vault",
                isEnrolled = false,
                rememberDevice = false,
                isUnlocking = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = {},
            )
        }

        composeRule.onNodeWithText("Secretary — demo vault").assertIsDisplayed()
        composeRule.onNodeWithTag("unlock-progress").assertDoesNotExist()
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/android-unlock-ux-332/android && ./gradlew :app:compileDebugAndroidTestKotlin`
Expected: FAIL — `UnlockScreen` has no `title` / `isUnlocking` parameters (compile error). (We verify at compile time; the on-emulator run happens in Step 6.)

- [ ] **Step 3: Implement the composable change**

Edit `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt`.

3a. Add imports near the existing Material 3 imports:

```kotlin
import androidx.compose.material3.CircularProgressIndicator
```

3b. Change the signature and the title line. Replace:

```kotlin
fun UnlockScreen(
    isEnrolled: Boolean,
    rememberDevice: Boolean,
    onUnlock: (UnlockCredential) -> Unit,
    onEnrollChoice: (Boolean) -> Unit,
    onBiometricUnlock: () -> Unit,
) {
```

with:

```kotlin
fun UnlockScreen(
    title: String,
    isEnrolled: Boolean,
    rememberDevice: Boolean,
    isUnlocking: Boolean,
    onUnlock: (UnlockCredential) -> Unit,
    onEnrollChoice: (Boolean) -> Unit,
    onBiometricUnlock: () -> Unit,
) {
```

3c. Replace the hardcoded title:

```kotlin
        Text("Secretary — demo vault")
```

with:

```kotlin
        Text(title)
```

3d. Disable the biometric button while unlocking. Replace:

```kotlin
            Button(
                onClick = onBiometricUnlock,
                modifier = Modifier.fillMaxWidth().testTag("biometric-unlock"),
            ) { Text("Unlock with biometrics") }
```

with:

```kotlin
            Button(
                onClick = onBiometricUnlock,
                enabled = !isUnlocking,
                modifier = Modifier.fillMaxWidth().testTag("biometric-unlock"),
            ) { Text("Unlock with biometrics") }
```

3e. Disable both segmented buttons. Add `enabled = !isUnlocking,` to each `SegmentedButton(...)` (after the `onClick = ...` line, before `shape = ...`). The block becomes:

```kotlin
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = mode == UnlockMode.Password,
                onClick = { mode = UnlockMode.Password },
                enabled = !isUnlocking,
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                modifier = Modifier.testTag("mode-password"),
            ) { Text("Password") }
            SegmentedButton(
                selected = mode == UnlockMode.Recovery,
                onClick = { mode = UnlockMode.Recovery },
                enabled = !isUnlocking,
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                modifier = Modifier.testTag("mode-recovery"),
            ) { Text("Recovery phrase") }
        }
```

3f. Disable the text fields and the remember-device checkbox. In the `when (mode)` block add `enabled = !isUnlocking,` to the password `OutlinedTextField`, the recovery `OutlinedTextField`, and the `Checkbox`:

```kotlin
        when (mode) {
            UnlockMode.Password -> Column {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Vault password") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    enabled = !isUnlocking,
                    modifier = Modifier.fillMaxWidth().testTag("password-field"),
                )
                if (!isEnrolled) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = rememberDevice,
                            onCheckedChange = onEnrollChoice,
                            enabled = !isUnlocking,
                            modifier = Modifier.testTag("remember-device"),
                        )
                        Text("Remember this device with biometrics")
                    }
                }
            }
            UnlockMode.Recovery -> OutlinedTextField(
                value = phrase,
                onValueChange = { phrase = it },
                label = { Text("24-word recovery phrase") },
                singleLine = false,
                minLines = 3,
                enabled = !isUnlocking,
                modifier = Modifier.fillMaxWidth().testTag("recovery-field"),
            )
        }
```

3g. The unlock button: AND the enable with `!isUnlocking`, and swap the label for a spinner while in flight. Replace the whole final `Button(...)` block:

```kotlin
        Button(
            onClick = {
                val credential = when (mode) {
                    UnlockMode.Password ->
                        UnlockCredential.Password(password.toByteArray(Charsets.UTF_8))
                    UnlockMode.Recovery ->
                        UnlockCredential.Recovery(
                            RecoveryPhrase.normalize(phrase).toByteArray(Charsets.UTF_8))
                }
                onUnlock(credential)
            },
            enabled = when (mode) {
                UnlockMode.Password -> password.isNotEmpty()
                UnlockMode.Recovery -> phrase.isNotBlank()
            },
            modifier = Modifier.fillMaxWidth().testTag("unlock-button"),
        ) {
            Text(if (mode == UnlockMode.Password) "Unlock & Sync" else "Unlock")
        }
```

with:

```kotlin
        Button(
            onClick = {
                val credential = when (mode) {
                    UnlockMode.Password ->
                        UnlockCredential.Password(password.toByteArray(Charsets.UTF_8))
                    UnlockMode.Recovery ->
                        UnlockCredential.Recovery(
                            RecoveryPhrase.normalize(phrase).toByteArray(Charsets.UTF_8))
                }
                onUnlock(credential)
            },
            enabled = !isUnlocking && when (mode) {
                UnlockMode.Password -> password.isNotEmpty()
                UnlockMode.Recovery -> phrase.isNotBlank()
            },
            modifier = Modifier.fillMaxWidth().testTag("unlock-button"),
        ) {
            if (isUnlocking) {
                CircularProgressIndicator(modifier = Modifier.testTag("unlock-progress"))
            } else {
                Text(if (mode == UnlockMode.Password) "Unlock & Sync" else "Unlock")
            }
        }
```

3h. Update the KDoc above `UnlockScreen` to document the two new params (one sentence each): `[title]` renders the screen heading (demo vs cloud target); `[isUnlocking]` disables every control and swaps the button label for a spinner during the multi-second open.

- [ ] **Step 4: Update the existing instrumented tests for the new required params**

In `UnlockScreenRecoveryUiTest.kt`, both `UnlockScreen(...)` call sites: add `title = "Secretary — demo vault",` as the first argument and `isUnlocking = false,` after `rememberDevice = false,`. Example for the first:

```kotlin
            UnlockScreen(
                title = "Secretary — demo vault",
                isEnrolled = false,
                rememberDevice = false,
                isUnlocking = false,
                onUnlock = { captured = it },
                onEnrollChoice = {},
                onBiometricUnlock = {},
            )
```

Do the same for every `UnlockScreen(...)` call in `UnlockScreenDeviceUiTest.kt` (add `title = "Secretary — demo vault",` first and `isUnlocking = false,` after `rememberDevice`).

- [ ] **Step 5: Compile the test sources**

Run: `cd .worktrees/android-unlock-ux-332/android && ./gradlew :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Run the instrumented tests on the emulator**

Boot/confirm `emulator-5554` is online (`~/Library/Android/sdk/platform-tools/adb devices`), then:

Run:
```bash
cd .worktrees/android-unlock-ux-332/android && \
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnlockScreenProgressUiTest
```
Expected: 2 tests pass on `emulator-5554`. (Per prior batons, `:app` instrumented tests are not the merge gate — if the emulator is unavailable or shows the known "No compose hierarchies found", record that and rely on Step 5's compile + the Task 1 host gate. Do NOT silently skip — note the outcome.)

- [ ] **Step 7: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenProgressUiTest.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenRecoveryUiTest.kt \
        android/app/src/androidTest/kotlin/org/secretary/app/UnlockScreenDeviceUiTest.kt
git commit -m "feat(android): UnlockScreen progress spinner + per-target title (#332)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `AppRoot` wiring — in-flight flag, title, typed demo Toast

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt`

**Interfaces:**
- Consumes: `unlockScreenTitle` / `unlockFailureMessage` (Task 1); the new `UnlockScreen(title, isUnlocking, …)` signature (Task 2).
- Produces: no new public symbols (internal Compose wiring).

- [ ] **Step 1: Add the in-flight state**

In `AppRoot()`, alongside the other `remember` state near the top (e.g. just after `var rememberDevice by remember { mutableStateOf(false) }` at line ~93), add:

```kotlin
    var isUnlocking by remember { mutableStateOf(false) }
```

- [ ] **Step 2: Pass `title` and `isUnlocking` into `UnlockScreen`, and gate the in-flight flag around the button open paths**

Replace the `is Route.Unlock -> UnlockScreen(` call (lines ~281–325) so it (a) passes the two new params and (b) wraps the `onUnlock` body in `isUnlocking = true` / `finally { isUnlocking = false }`:

```kotlin
        is Route.Unlock -> UnlockScreen(
            title = unlockScreenTitle(r.cloudTarget),
            // The biometric-OPEN button is demo-only (cloud open stays password-based this session), so hide it
            // for a cloud target. The "Remember this device" checkbox (shown when !isEnrolled) IS live for cloud:
            // ticking it enrolls a device secret for write-reauth after the password open (see openCloudTarget).
            isEnrolled = r.cloudTarget == null && deviceState is DeviceUnlockState.Enrolled,
            rememberDevice = rememberDevice,
            isUnlocking = isUnlocking,
            onUnlock = { credential ->
                scope.launch {
                    isUnlocking = true
                    try {
                        val target = r.cloudTarget
                        route = if (target != null) {
                            openCloudTarget(context, activity, target, credential, enrollThisDevice = rememberDevice, locationStore, selectionVm).also { result ->
                                selectionState = selectionVm.state
                                // openCloudTarget returns Route.Unlock (same target) on any open/create
                                // failure — surface it instead of silently re-showing the Unlock screen
                                // (a SAF provider hiccup, e.g. eventually-consistent cloud, or a wrong
                                // password otherwise looks like a dead button).
                                if (result is Route.Unlock) {
                                    Toast.makeText(
                                        context,
                                        "Couldn't open the cloud vault — check the folder is reachable and the password is correct, then try again.",
                                        Toast.LENGTH_LONG,
                                    ).show()
                                }
                            }
                        } else {
                            unlockAndOpen(context, scope, credential, enrollAfter = rememberDevice, coordinator, vaultId)
                        }
                    } finally {
                        isUnlocking = false
                    }
                }
            },
            onEnrollChoice = { rememberDevice = it },
            onBiometricUnlock = {
                scope.launch {
                    isUnlocking = true
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
        )
```

- [ ] **Step 3: Surface the typed Toast on the demo-path failure**

In `unlockAndOpen`'s `catch` (lines ~445–447), add the Toast before returning. Replace:

```kotlin
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        return Route.Unlock()
    } finally {
```

with:

```kotlin
    } catch (e: Exception) {
        Log.w(TAG, "unlock/open failed; returning to unlock screen", e)
        Toast.makeText(context, unlockFailureMessage(e), Toast.LENGTH_LONG).show()
        return Route.Unlock()
    } finally {
```

- [ ] **Step 4: Compile**

Run: `cd .worktrees/android-unlock-ux-332/android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Full host gate + test-source compile**

Run:
```bash
cd .worktrees/android-unlock-ux-332/android && \
./gradlew :app:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin
```
Expected: BUILD SUCCESSFUL; `UnlockMessagesTest` green within `:app:testDebugUnitTest`.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/kotlin/org/secretary/app/AppRoot.kt
git commit -m "feat(android): wire unlock in-flight spinner + typed demo Toast + per-target title (#332)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (after all tasks)

- [ ] Full host gate from the worktree:
  ```bash
  cd .worktrees/android-unlock-ux-332/android && \
  ./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:testDebugUnitTest \
    :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin
  ```
  Expected: BUILD SUCCESSFUL. (`:kit`/`:vault-access` included as a sanity check that the `:app`-only change didn't perturb the sealed-`when` consumers — none expected, since no sealed type changed.)
- [ ] README / ROADMAP: check whether the root README status row or `android/README.md` needs a note (likely a one-line mention that the unlock flow now shows progress + typed errors; ROADMAP D-phase Android walking-skeleton wording). Update if so.
- [ ] Handoff doc + retargeted `NEXT_SESSION.md` symlink committed on the branch.

## Spec coverage check

| Spec requirement | Task |
|---|---|
| Loading indicator + disabled controls during open | Task 2 (composable) + Task 3 (flag wiring around all 3 entry points) |
| Typed error message on failed demo/password unlock | Task 1 (`unlockFailureMessage`) + Task 3 (Toast in `unlockAndOpen` catch) |
| Title by target (demo vs cloud) | Task 1 (`unlockScreenTitle`) + Task 2 (`title` param) + Task 3 (`title =` wiring) |
| Pure host-tested helpers | Task 1 |
| No `:vault-access`/`:kit`/crypto change | All tasks `:app`-only |
| Cloud path error message unchanged (out of scope) | Task 3 keeps the existing cloud Toast |
