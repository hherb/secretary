# Unsynced-Create Warning Banner (#329) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface `PendingFlushNotPersisted` (an offline-created cloud vault that could neither sync nor be marked for retry) as a persistent warning banner on the Unlock screen, instead of only a logcat line.

**Architecture:** The signal already exists — `cloudOpenFailureRoute` returns `CloudOpenFailure(target, createdButNotSynced)`, host-tested. Today `openCloudTarget` drops `createdButNotSynced` when building `Route.Unlock`. We thread it onto `Route.Unlock` via a pure projection helper, then render a `Text` banner in `UnlockScreen` when the flag is set. Pure routing decision is host-tested; the banner rendering is instrumented-tested on emulator-5554.

**Tech Stack:** Kotlin, Jetpack Compose (Material3), JUnit5 (host unit), Compose UI test (instrumented).

## Global Constraints

- Scope: `android/app` Kotlin/Compose **only**. No `:vault-access` / `:kit`, no `core` / `ffi`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change.
- The integrity protection (materialize no-clobber guard + `isCreate`-preserved push-before-pull retry) is untouched. This adds **only** a user-facing warning.
- New `UnlockScreen` param and new `Route.Unlock` field are both **defaulted** so existing construction/call sites compile unchanged.
- Banner text (verbatim): `Vault created but not yet synced — keep this device online and reopen to finish the upload. The vault currently exists only on this device.`
- Banner `testTag`: `unsynced-create-warning`.
- Work in the worktree: `/Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329`, branch `feature/android-unsynced-create-banner-329`. Use absolute paths; the Bash cwd does not persist between calls.
- Host gate (run from `<worktree>/android`): `./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`.

---

### Task 1: Thread `createdButNotSynced` onto `Route.Unlock`

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt:64` (add `Route.Unlock.unsyncedCreateWarning` field)
- Modify: `android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt` (add `unsyncedCreateRoute` pure helper near `cloudOpenFailureRoute` ~line 44; use it in `openCloudTarget` failure branch ~line 262)
- Test: `android/app/src/test/kotlin/org/secretary/app/CloudCreateErrorRoutingTest.kt`

**Interfaces:**
- Consumes: `CloudOpenFailure(val target: CloudVaultTarget, val createdButNotSynced: Boolean)` and `cloudOpenFailureRoute(error, target): CloudOpenFailure` (both exist, `internal`).
- Produces: `Route.Unlock(val cloudTarget: CloudVaultTarget? = null, val unsyncedCreateWarning: Boolean = false)` and `internal fun unsyncedCreateRoute(failure: CloudOpenFailure): Route.Unlock`.

- [ ] **Step 1: Add the field to `Route.Unlock`**

In `AppRoot.kt`, change the `Unlock` route (currently line 64):

```kotlin
    data class Unlock(
        val cloudTarget: CloudVaultTarget? = null,
        val unsyncedCreateWarning: Boolean = false,
    ) : Route
```

Keep the existing KDoc comment above it.

- [ ] **Step 2: Write the failing host test**

Append to `CloudCreateErrorRoutingTest.kt` (it already imports `PendingFlushNotPersisted`, `VaultMirrorException`, `VaultLocation`, `File`, and the JUnit5 assertions). Add `import org.junit.jupiter.api.Assertions.assertSame`:

```kotlin
    @Test
    fun `unsyncedCreateRoute carries the warning flag for an unsynced create`() {
        val t = target()
        val route = unsyncedCreateRoute(CloudOpenFailure(t, createdButNotSynced = true))
        assertSame(t, route.cloudTarget, "must stay on the same target so reopen retries push-before-pull")
        assertTrue(route.unsyncedCreateWarning, "the un-synced-create warning must ride the route")
    }

    @Test
    fun `unsyncedCreateRoute does not warn for an ordinary failure`() {
        val t = target()
        val route = unsyncedCreateRoute(CloudOpenFailure(t, createdButNotSynced = false))
        assertSame(t, route.cloudTarget)
        assertEquals(false, route.unsyncedCreateWarning)
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329/android && ./gradlew :app:testDebugUnitTest --tests org.secretary.app.CloudCreateErrorRoutingTest`
Expected: compile FAIL — `unsyncedCreateRoute` unresolved.

- [ ] **Step 4: Add the pure helper**

In `CloudVaultOpen.kt`, directly below the existing `cloudOpenFailureRoute` (line 44-45), add:

```kotlin
/**
 * Project a [CloudOpenFailure] to the Unlock route, carrying [CloudOpenFailure.createdButNotSynced]
 * through as [Route.Unlock.unsyncedCreateWarning] so the screen can show the persistent
 * "created but not yet synced" banner (#329). Pure: host-testable without a Context.
 */
internal fun unsyncedCreateRoute(failure: CloudOpenFailure): Route.Unlock =
    Route.Unlock(cloudTarget = failure.target, unsyncedCreateWarning = failure.createdButNotSynced)
```

- [ ] **Step 5: Use the helper in `openCloudTarget`**

In `CloudVaultOpen.kt`, in the `catch (e: Exception)` block of `openCloudTarget` (~line 256-262), replace the final `Route.Unlock(cloudTarget = failure.target)` line with `unsyncedCreateRoute(failure)`. Keep both `Log.w` branches exactly as-is:

```kotlin
    } catch (e: Exception) {
        val failure = cloudOpenFailureRoute(e, target)
        if (failure.createdButNotSynced) {
            Log.w(TAG, "cloud vault CREATED but not synced and not marked for retry — user must not lose it", e)
        } else {
            Log.w(TAG, "cloud open/create failed; returning to unlock with same target", e)
        }
        unsyncedCreateRoute(failure)
    } finally {
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329/android && ./gradlew :app:testDebugUnitTest --tests org.secretary.app.CloudCreateErrorRoutingTest`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329
git add android/app/src/main/kotlin/org/secretary/app/AppRoot.kt \
        android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt \
        android/app/src/test/kotlin/org/secretary/app/CloudCreateErrorRoutingTest.kt
git commit -m "feat(android): thread unsynced-create flag onto Route.Unlock (#329)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Render the banner in `UnlockScreen` + wire `AppRoot`

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt` (new param + banner `Text`)
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt:299-308` (pass-through)

**Interfaces:**
- Consumes: `Route.Unlock.unsyncedCreateWarning` (from Task 1).
- Produces: `UnlockScreen(..., unsyncedCreateWarning: Boolean = false)` rendering a `Text` with `testTag("unsynced-create-warning")` when the flag is set.

- [ ] **Step 1: Add the `MaterialTheme` import to `UnlockScreen.kt`**

Add alongside the existing `androidx.compose.material3.*` imports:

```kotlin
import androidx.compose.material3.MaterialTheme
```

- [ ] **Step 2: Add the param to the `UnlockScreen` signature**

Add `unsyncedCreateWarning` as the last parameter (defaulted), after `onBiometricUnlock`:

```kotlin
fun UnlockScreen(
    title: String,
    isEnrolled: Boolean,
    rememberDevice: Boolean,
    isUnlocking: Boolean,
    onUnlock: (UnlockCredential) -> Unit,
    onEnrollChoice: (Boolean) -> Unit,
    onBiometricUnlock: () -> Unit,
    unsyncedCreateWarning: Boolean = false,
) {
```

Also extend the KDoc with one line: `@param unsyncedCreateWarning When true, shows a persistent "created but not yet synced" banner above the title (#329).`

- [ ] **Step 3: Render the banner at the top of the `Column`**

Inside the outer `Column { ... }`, immediately BEFORE `Text(title)`:

```kotlin
        if (unsyncedCreateWarning) {
            Text(
                "Vault created but not yet synced — keep this device online and reopen to " +
                    "finish the upload. The vault currently exists only on this device.",
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.fillMaxWidth().testTag("unsynced-create-warning"),
            )
        }
```

- [ ] **Step 4: Pass the flag from `AppRoot`**

In `AppRoot.kt`, in the `is Route.Unlock -> UnlockScreen(` call (line 299), add as the matching argument:

```kotlin
            unsyncedCreateWarning = r.unsyncedCreateWarning,
```

- [ ] **Step 5: Verify the host gate compiles + existing tests pass**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329/android && ./gradlew :app:compileDebugKotlin :app:testDebugUnitTest`
Expected: BUILD SUCCESSFUL; all `:app` unit tests pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329
git add android/app/src/main/kotlin/org/secretary/app/UnlockScreen.kt \
        android/app/src/main/kotlin/org/secretary/app/AppRoot.kt
git commit -m "feat(android): unsynced-create warning banner on UnlockScreen (#329)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Instrumented UI test (emulator-5554)

**Files:**
- Create: `android/app/src/androidTest/kotlin/org/secretary/app/UnsyncedCreateWarningUiTest.kt`

**Interfaces:**
- Consumes: `UnlockScreen(..., unsyncedCreateWarning: Boolean)` (Task 2); `testTag("unsynced-create-warning")`.

- [ ] **Step 1: Write the instrumented test**

Mirror the existing `CloudBiometricUnlockUiTest.kt` structure exactly:

```kotlin
package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertDoesNotExist
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Rule
import org.junit.Test

/**
 * The un-synced-create warning banner (#329) must render on the Unlock screen exactly when the
 * route carries the flag. UnlockScreen is credential-agnostic, so this pins the UI contract:
 * unsyncedCreateWarning = true renders the banner; false hides it.
 */
class UnsyncedCreateWarningUiTest {
    @get:Rule val composeRule = createComposeRule()

    private val cloudTitle = "Secretary — My Cloud Vault"

    @Test
    fun warningTrue_showsBanner() {
        composeRule.setContent {
            UnlockScreen(
                title = cloudTitle,
                isEnrolled = false,
                rememberDevice = false,
                isUnlocking = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = {},
                unsyncedCreateWarning = true,
            )
        }
        composeRule.onNodeWithTag("unsynced-create-warning").assertIsDisplayed()
    }

    @Test
    fun warningFalse_hidesBanner() {
        composeRule.setContent {
            UnlockScreen(
                title = cloudTitle,
                isEnrolled = false,
                rememberDevice = false,
                isUnlocking = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = {},
                unsyncedCreateWarning = false,
            )
        }
        composeRule.onNodeWithTag("unsynced-create-warning").assertDoesNotExist()
    }
}
```

- [ ] **Step 2: Verify the androidTest sources compile**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329/android && ./gradlew :app:compileDebugAndroidTestKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Confirm emulator-5554 is online, then run the instrumented test**

Run:
```bash
~/Library/Android/sdk/platform-tools/adb devices    # expect emulator-5554  device
cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329/android && \
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnsyncedCreateWarningUiTest
```
Expected: 2/2 passing. (Use the class-arg form — `connectedAndroidTest` rejects `--tests`.)

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329
git add android/app/src/androidTest/kotlin/org/secretary/app/UnsyncedCreateWarningUiTest.kt
git commit -m "test(android): instrumented UnsyncedCreateWarningUiTest (#329)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Locate the Android cloud-vault status lines**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329 && grep -n "offline-create\|not yet synced\|PendingFlush\|cloud" README.md ROADMAP.md`
Read the surrounding context before editing.

- [ ] **Step 2: Add a brief status note**

In the Android cloud section of each file, add one concise dot point (per the README brevity rule — no test-count walls): the offline-created-but-unsynced cloud vault now shows a persistent Unlock-screen warning banner (#329), so the user knows their only copy is still local until the next successful sync.

- [ ] **Step 3: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329
git add README.md ROADMAP.md
git commit -m "docs: note unsynced-create warning banner (#329)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- §1 (thread flag onto route) → Task 1. ✅
- §2 (UnlockScreen banner + AppRoot pass-through) → Task 2. ✅
- §3 (persistence/clearing semantics) → no code; emergent from the flag riding the route (each `openCloudTarget` recomputes it). Documented in design; no task needed. ✅
- §4 (no new failure modes) → nothing to implement. ✅
- §5 host test → Task 1 Step 2; instrumented test → Task 3. ✅
- Files table → Tasks 1-4 cover all six. ✅

**Placeholder scan:** none — every step has exact code/commands.

**Type consistency:** `unsyncedCreateWarning: Boolean` field on `Route.Unlock`, param on `UnlockScreen`, and `unsyncedCreateRoute(failure: CloudOpenFailure): Route.Unlock` are named identically across Tasks 1-3. `testTag("unsynced-create-warning")` matches between Task 2 (render) and Task 3 (assert). Banner text identical between design, Task 2, and the Global Constraints block.
