# Settings/Trash Render Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct + host-test the mobile Settings error banner (#421), add an Android instrumented render test for the Trash/Settings banners (#417), and close the already-fixed #413.

**Architecture:** Extract the inline error→message mapping into a pure, host-tested function in the shared module on each platform (Android `:vault-access`, iOS `SecretaryVaultAccessUI`), neutralizing only the shared load/save fallback arm. Add an Android instrumented Compose test that renders the real screens against small purpose-built port doubles and asserts the `testTag` nodes. iOS keeps host-logic coverage; the literal SwiftUI render assertion is deferred.

**Tech Stack:** Kotlin / Jetpack Compose (`:vault-access` JUnit5 host tests, `:browse-ui` androidTest instrumented), Swift / SwiftUI (`SecretaryVaultAccess` XCTest host tests).

## Global Constraints

- No `core` / crypto / on-disk-format / `manifest_version` change. No new `FfiVaultError` / `VaultBrowseError` / `VaultAccessError` variant. `#![forbid(unsafe_code)]` intact.
- Android + iOS only. No `.rs` / desktop change.
- Do NOT modify the reviewed security models (`SettingsModel` / `SettingsViewModel`), the retarget-after-save ordering, or the field-preservation re-read. This work is view/formatter-layer only.
- Exact copy strings (verbatim, note the iOS curly apostrophe `’`):
  - Android fallback: `"Couldn't update settings: "` + `error::class.simpleName`. Android reauth arm unchanged: `"Couldn't authorize the change: "` + `error.detail`.
  - iOS fallback: `"Couldn’t update settings. Please try again."` iOS `.reauthFailed` / `.invalidArgument` arms unchanged.
- Exact test-tag / a11y-id names (unchanged): Android `trash-notice`, `settings-notice`, `settings-error`; iOS `settings-notice`, `settings-error`, `purge-notice`.
- Android instrumented tests: filter with `-Pandroid.testInstrumentationRunnerArguments.class=…` (NOT `--tests`); `adb`/`emulator` are not on the bare PATH — use absolute paths, confirm `adb devices` first.
- iOS host tests run via `swift test` in `ios/SecretaryVaultAccess/` (the FFI-free layer; no xcframework).
- One PR for #421 + #417; #413 closed separately (comment + close, no code).

---

### Task 1: #421 Android — extract + neutralize the Settings error message

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/browse/SettingsErrorMessage.kt`
- Create: `android/vault-access/src/test/kotlin/org/secretary/browse/SettingsErrorMessageTest.kt`
- Modify: `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/SettingsScreen.kt:127-139` (the `SettingsErrorBanner` composable) + add the import

**Interfaces:**
- Consumes: `VaultBrowseError` (sealed class in `org.secretary.browse`; arms used: `ReauthFailed(val detail: String)`, `CorruptVault(val detail: String)`).
- Produces: `fun settingsErrorMessage(error: VaultBrowseError): String` in package `org.secretary.browse`.

- [ ] **Step 1: Write the failing host test**

Create `android/vault-access/src/test/kotlin/org/secretary/browse/SettingsErrorMessageTest.kt`:

```kotlin
package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SettingsErrorMessageTest {
    @Test
    fun reauthFailed_usesAuthorizeCopyWithDetail() {
        assertEquals(
            "Couldn't authorize the change: no match",
            settingsErrorMessage(VaultBrowseError.ReauthFailed("no match")),
        )
    }

    @Test
    fun genericLoadOrSaveError_usesNeutralUpdateCopy_notSave() {
        // A hard read error surfaced from load() must NOT read "save" (the #421 bug).
        val msg = settingsErrorMessage(VaultBrowseError.CorruptVault("boom"))
        assertEquals("Couldn't update settings: CorruptVault", msg)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.SettingsErrorMessageTest' )`
Expected: FAIL — compilation error, `settingsErrorMessage` unresolved.

- [ ] **Step 3: Write the minimal implementation**

Create `android/vault-access/src/main/kotlin/org/secretary/browse/SettingsErrorMessage.kt`:

```kotlin
package org.secretary.browse

/**
 * User-facing text for a Settings-screen [error]. Pure + host-tested (extracted from the
 * `SettingsErrorBanner` composable so the wording is verifiable without an instrumented render, #421).
 *
 * The [error] state is populated by BOTH `SettingsModel.load()` and `SettingsModel.save()`; only
 * [VaultBrowseError.ReauthFailed] is save-specific (re-auth gates writes, never reads), so the
 * fallback stays operation-neutral ("update", not "save") — a hard read error from `load()` would
 * otherwise be mislabelled as a save failure. Mirror of iOS `settingsErrorMessage`.
 */
fun settingsErrorMessage(error: VaultBrowseError): String = when (error) {
    is VaultBrowseError.ReauthFailed -> "Couldn't authorize the change: ${error.detail}"
    else -> "Couldn't update settings: ${error::class.simpleName}"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd android && ./gradlew :vault-access:test --tests 'org.secretary.browse.SettingsErrorMessageTest' )`
Expected: PASS (2 tests).

- [ ] **Step 5: Wire the composable to the extracted function**

In `android/browse-ui/src/main/kotlin/org/secretary/browse/ui/SettingsScreen.kt`, add the import near the existing `import org.secretary.browse.VaultBrowseError` (line 28):

```kotlin
import org.secretary.browse.settingsErrorMessage
```

Replace the `SettingsErrorBanner` body (lines 127-139) so it delegates to the extracted function:

```kotlin
@Composable
private fun SettingsErrorBanner(error: VaultBrowseError) {
    Text(
        text = settingsErrorMessage(error),
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.fillMaxWidth().testTag("settings-error"),
    )
}
```

- [ ] **Step 6: Verify the module still compiles + host tests pass**

Run: `( cd android && ./gradlew :vault-access:test :browse-ui:compileDebugKotlin )`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 7: Commit**

```bash
git add android/vault-access/src/main/kotlin/org/secretary/browse/SettingsErrorMessage.kt \
        android/vault-access/src/test/kotlin/org/secretary/browse/SettingsErrorMessageTest.kt \
        android/browse-ui/src/main/kotlin/org/secretary/browse/ui/SettingsScreen.kt
git commit -m "fix(android): host-test Settings error copy; neutral load/save fallback (#421)"
```

---

### Task 2: #421 iOS — extract + neutralize the Settings error message

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift`
- Create: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift`
- Modify: `ios/SecretaryApp/Sources/SettingsScreen.swift:89-102` (delete the `private func`; the call site on line 32 resolves to the new public function)

**Interfaces:**
- Consumes: `VaultAccessError` (`public enum` in `SecretaryVaultAccess`; arms used: `.reauthFailed(String)`, `.invalidArgument(String)`, `.corruptVault(String)`).
- Produces: `public func settingsErrorMessage(_ e: VaultAccessError) -> String` in `SecretaryVaultAccessUI`.

- [ ] **Step 1: Write the failing host test**

Create `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift`:

```swift
import XCTest
@testable import SecretaryVaultAccessUI
import SecretaryVaultAccess

final class SettingsErrorMessageTests: XCTestCase {
    func testReauthFailedUsesSaveWordedCopy() {
        XCTAssertEqual(
            settingsErrorMessage(.reauthFailed("x")),
            "Re-authentication didn’t complete — settings were not saved.")
    }

    func testInvalidArgumentUsesRangeCopy() {
        XCTAssertEqual(
            settingsErrorMessage(.invalidArgument("x")),
            "That value is out of range — settings were not saved.")
    }

    func testGenericLoadOrSaveErrorUsesNeutralUpdateCopyNotSave() {
        // A hard read error surfaced from load() must NOT read "save" (#421).
        XCTAssertEqual(
            settingsErrorMessage(.corruptVault("boom")),
            "Couldn’t update settings. Please try again.")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter SettingsErrorMessageTests )`
Expected: FAIL — `settingsErrorMessage` not found in `SecretaryVaultAccessUI`.

- [ ] **Step 3: Write the minimal implementation**

Create `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift`:

```swift
import SecretaryVaultAccess

/// Short user-facing message for a Settings-screen error. Pure + host-tested (extracted from the
/// `SettingsScreen` view so the wording is verifiable without an instrumented render, #421).
///
/// The `error` state is populated by BOTH `SettingsViewModel.load()` and `.save()`; only
/// `.reauthFailed` / `.invalidArgument` are save-specific (re-auth and range-validation never occur
/// on a read), so the fallback stays operation-neutral ("update", not "save") — a hard read error
/// from `load()` would otherwise be mislabelled as a save failure. The anti-oracle "…OrCorrupt"
/// cases are folded upstream. Mirror of Android `settingsErrorMessage`.
public func settingsErrorMessage(_ e: VaultAccessError) -> String {
    switch e {
    case .reauthFailed:
        return "Re-authentication didn’t complete — settings were not saved."
    case .invalidArgument:
        return "That value is out of range — settings were not saved."
    default:
        return "Couldn’t update settings. Please try again."
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter SettingsErrorMessageTests )`
Expected: PASS (3 tests).

- [ ] **Step 5: Delete the now-duplicated private function in the app target**

In `ios/SecretaryApp/Sources/SettingsScreen.swift`, delete the entire `private func settingsErrorMessage(_:)` (lines 89-102, including its doc comment). The call site `Text(settingsErrorMessage(error))` (line 32) now resolves to the public function from the already-imported `SecretaryVaultAccessUI` (line 3). Do not change any other line.

- [ ] **Step 6: Re-run the host suite (guards the extraction did not break the UI target's dependency)**

Run: `( cd ios/SecretaryVaultAccess && swift test --filter SettingsErrorMessageTests )`
Expected: PASS (3 tests). (The app-target compile is verified in Task 4 via the full iOS runner.)

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/SettingsErrorMessage.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/SettingsErrorMessageTests.swift \
        ios/SecretaryApp/Sources/SettingsScreen.swift
git commit -m "fix(ios): host-test Settings error copy; neutral load/save fallback (#421)"
```

---

### Task 3: #417 Android — instrumented render tests for the Trash + Settings banners

Two instrumented Compose tests under `:browse-ui` androidTest, rendering the real screens against small purpose-built port doubles (androidTest cannot see the host `src/test` fakes). One emulator run covers both. These are render-binding regression guards over existing behaviour (the `testTag`s and bindings already exist); the Settings-error test additionally locks in Task 1's neutral copy, so **it must run after Task 1**.

**Files:**
- Create: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/TrashNoticeRenderTest.kt`
- Create: `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/SettingsBannerRenderTest.kt`

**Interfaces:**
- Consumes (Trash): `TrashPort` (7 methods), `EmptyTrashReportInfo(purgedCount, sharedCount, ownerOnlyCount, unknownCount, filesRemoved, filesFailed: Int)`, `PurgeResultInfo`, `RetentionReportInfo`, `TrashedBlockInfo`, `ExpiredEntryInfo`, `TrashBrowseModel(port, gate = NoopReauthGate, settingsPort = null)`, `TrashBrowseViewModel(model)`, `TrashScreen(viewModel, onBack)`.
- Consumes (Settings): `SettingsPort` (`readSettings(): VaultSettings`, `suspend writeSettings(VaultSettings)`, `settingsBounds(): SettingsBounds`), `SettingsBounds`, `RetargetableReauthGate`, `NoopReauthGate`, `WriteReauthGate`, `VaultBrowseError.CorruptVault`, `SettingsModel(port, gate, makeGraceGate, nowMs)`, `SettingsBrowseViewModel(model)`, `SettingsScreen(viewModel, onBack)`.

- [ ] **Step 1: Write the Trash-notice render test**

Create `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/TrashNoticeRenderTest.kt`:

```kotlin
package org.secretary.browse.ui

import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.EmptyTrashReportInfo
import org.secretary.browse.ExpiredEntryInfo
import org.secretary.browse.PurgeResultInfo
import org.secretary.browse.RetentionReportInfo
import org.secretary.browse.TrashBrowseModel
import org.secretary.browse.TrashPort
import org.secretary.browse.TrashedBlockInfo

/**
 * Instrumented render guard for the Trash purge-notice banner (#417): proves `testTag("trash-notice")`
 * renders the view-model's `notice` — both the success text and the `filesFailed > 0` warning variant.
 * The banner FORMATTER is host-tested (`TrashFormattingTest`); this asserts the render BINDING.
 */
class TrashNoticeRenderTest {
    @get:Rule val composeRule = createComposeRule()

    /** Minimal androidTest TrashPort: only `emptyTrash()` is exercised; other ops must not be called. */
    private class FakeTrashPort(private val purged: Int, private val failed: Int) : TrashPort {
        override fun listTrashedBlocks(): List<TrashedBlockInfo> = emptyList()
        override fun expiredTrashEntries(windowMs: Long): List<ExpiredEntryInfo> = emptyList()
        override fun defaultRetentionWindowMs(): Long = 0L
        override suspend fun restoreBlock(uuid: ByteArray) = error("unused in render test")
        override suspend fun purgeBlock(uuid: ByteArray): PurgeResultInfo = error("unused in render test")
        override suspend fun emptyTrash(): EmptyTrashReportInfo =
            EmptyTrashReportInfo(purged, 0, purged, 0, 0, failed)
        override suspend fun autoPurgeExpired(windowMs: Long): RetentionReportInfo = error("unused in render test")
    }

    private fun render(purged: Int, failed: Int) {
        val vm = TrashBrowseViewModel(TrashBrowseModel(FakeTrashPort(purged, failed)))
        composeRule.setContent { TrashScreen(viewModel = vm, onBack = {}) }
        composeRule.runOnIdle { vm.emptyTrash() }
        composeRule.waitForIdle()
    }

    @Test
    fun emptyTrashSuccess_rendersPurgedCount() {
        render(purged = 2, failed = 0)
        composeRule.onNodeWithTag("trash-notice").assertTextEquals("Purged 2 items")
    }

    @Test
    fun emptyTrashPartialFailure_rendersWarningVariant() {
        render(purged = 2, failed = 1)
        composeRule.onNodeWithTag("trash-notice")
            .assertTextEquals("Purged 2 items · 1 file could not be removed")
    }
}
```

- [ ] **Step 2: Write the Settings-error render test**

Create `android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/SettingsBannerRenderTest.kt`:

```kotlin
package org.secretary.browse.ui

import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.NoopReauthGate
import org.secretary.browse.RetargetableReauthGate
import org.secretary.browse.SettingsBounds
import org.secretary.browse.SettingsModel
import org.secretary.browse.SettingsPort
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultSettings

/**
 * Instrumented render guard for the Settings error banner (#417): a hard `readSettings()` failure on
 * the synchronous `load()` renders `testTag("settings-error")` with the neutral #421 copy (NOT the old
 * "save" wording). The message MAPPING is host-tested (`SettingsErrorMessageTest`); this asserts the
 * render BINDING + that load errors reach the banner.
 */
class SettingsBannerRenderTest {
    @get:Rule val composeRule = createComposeRule()

    private companion object {
        const val DAY_MS = 86_400_000L
        const val MIN_MS = 60_000L
    }

    /** SettingsPort whose read throws; bounds are valid so the model constructs. Write is never reached. */
    private class ThrowingReadSettingsPort : SettingsPort {
        override fun readSettings(): VaultSettings = throw VaultBrowseError.CorruptVault("render-test")
        override suspend fun writeSettings(settings: VaultSettings) = error("unused in render test")
        override fun settingsBounds(): SettingsBounds = SettingsBounds(
            retentionDefaultMs = 90 * DAY_MS, retentionMinMs = DAY_MS, retentionMaxMs = 3650 * DAY_MS,
            reauthGraceDefaultMs = 2 * MIN_MS, reauthGraceMinMs = 0L, reauthGraceMaxMs = 60 * MIN_MS,
        )
    }

    @Test
    fun loadFailure_rendersNeutralUpdateCopy_notSave() {
        val model = SettingsModel(
            port = ThrowingReadSettingsPort(),
            gate = RetargetableReauthGate(),                       // unused: load() does not gate
            makeGraceGate = { NoopReauthGate },                    // unused: no save in this test
            nowMs = { 0L },
        )
        val vm = SettingsBrowseViewModel(model)
        composeRule.setContent { SettingsScreen(viewModel = vm, onBack = {}) }
        composeRule.waitForIdle()                                  // SettingsScreen's LaunchedEffect runs load()
        composeRule.onNodeWithTag("settings-error")
            .assertTextEquals("Couldn't update settings: CorruptVault")
    }
}
```

- [ ] **Step 3: Boot an emulator (if none attached) and confirm it is ready**

```bash
"$HOME/Library/Android/sdk/platform-tools/adb" devices          # list attached devices/emulators
# If none: launch one (adjust AVD name to an installed one from `emulator -list-avds`), then wait:
# "$HOME/Library/Android/sdk/emulator/emulator" -avd <AVD> -no-window -no-snapshot &
# "$HOME/Library/Android/sdk/platform-tools/adb" wait-for-device
```
Expected: at least one `device` line.

- [ ] **Step 4: Run both instrumented render tests**

Run (backgrounded with log-poll if the `:kit` daemon is cold — a first configure can trigger a multi-minute native build):
```bash
( cd android && ./gradlew :browse-ui:connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.browse.ui.TrashNoticeRenderTest,org.secretary.browse.ui.SettingsBannerRenderTest )
```
Expected: BUILD SUCCESSFUL, 3 instrumented tests passed.

- [ ] **Step 5: Commit**

```bash
git add android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/TrashNoticeRenderTest.kt \
        android/browse-ui/src/androidTest/kotlin/org/secretary/browse/ui/SettingsBannerRenderTest.kt
git commit -m "test(android): instrumented render guards for Trash + Settings banners (#417)"
```

---

### Task 4: Whole-branch verification + issue bookkeeping + docs + PR

**Files:**
- Assess: `README.md`, `ROADMAP.md` (likely no change — no user-facing feature)
- Docs: new handoff under `docs/handoffs/` + retarget `NEXT_SESSION.md` symlink

- [ ] **Step 1: Full Android gate**

Run:
```bash
( cd android && ./gradlew :vault-access:test :browse-ui:compileDebugKotlin :app:assembleDebug )
```
Expected: BUILD SUCCESSFUL (host tests green; the extraction + composable wiring assemble).

- [ ] **Step 2: Full iOS runner (verifies the app-target `SettingsScreen.swift` compiles against the moved function)**

Run the repo iOS runner backgrounded with log-poll (the Rust xcframework build is multi-minute + silent — trips a 600s foreground watchdog; warm once, poll the log):
```bash
( cd ios && ./run-ios-tests.sh ) &            # then poll its log until it prints the host + build result
```
Expected: host suites pass (incl. `SettingsErrorMessageTests`); the SecretaryApp target builds. If the runner is unavailable in this environment, record that the app-target build was not run and flag it in the handoff (host tests + the trivial call-site resolution are the evidence).

- [ ] **Step 3: Close #413 (verify-then-close)**

Confirm the current tree still carries the fix before closing:
```bash
grep -n "timeZone: TimeZone, locale: Locale" ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/TrashFormatting.swift
grep -n "formatTrashedWhen(block.tombstonedAtMs, timeZone: .current, locale: .current)" ios/SecretaryApp/Sources/TrashScreen.swift
```
Expected: both match. Then:
```bash
gh issue close 413 --comment "Already fixed by the #415 housekeeping sweep (commit 4de849e2): \`formatTrashedWhen\` now takes an injected \`timeZone\`/\`locale\`, renders a \`.medium\` locale-aware date, the call site in TrashScreen.swift passes \`.current\`/\`.current\`, and TrashFormattingTests asserts the zone changes output (utcDay vs laDay). No further work needed."
```

- [ ] **Step 4: Re-scope #417 (Android done; iOS literal render deferred)**

```bash
gh issue comment 417 --body "Addressed on this branch: (1) Android instrumented Compose render guards for \`trash-notice\` (success + partial-failure warning) and \`settings-error\`; (2) iOS render-feeding logic is host-covered (TrashViewModelTests purgeNotice + the new SettingsErrorMessageTests). Remaining open sliver: the iOS literal SwiftUI \`accessibilityIdentifier\` render assertion — deferred (no ViewInspector/XCUITest target; disproportionate infra for a low-risk thin binding), to pair with a future ViewInspector/XCUITest decision and the #414 instrumented follow-on."
```

- [ ] **Step 5: Assess README / ROADMAP**

No user-facing feature shipped (copy fix + render tests). Confirm no status row needs changing; touch only if a render-test row is warranted — a single dot-point, no test-count walls (README style). If unchanged, note "no doc change" in the handoff.

- [ ] **Step 6: Write the handoff + retarget the symlink, then open the PR**

Author `docs/handoffs/2026-07-12-settings-trash-render-consolidation-shipped.md` (commit SHAs, what's next, open risks, resume commands), then:
```bash
ln -snf docs/handoffs/2026-07-12-settings-trash-render-consolidation-shipped.md NEXT_SESSION.md
git add docs/handoffs/2026-07-12-settings-trash-render-consolidation-shipped.md NEXT_SESSION.md
git commit -m "docs: handoff — settings/trash render consolidation shipped"
git push -u origin feature/settings-trash-render-consolidation
gh pr create --title "Consolidate settings/trash render loose ends (#421 + #417)" --body "…"
```

---

## Notes for the implementer

- **Deferred (documented, not gaps):** iOS literal SwiftUI render assertion (#417 re-scoped); Android `settings-notice` success-banner render (needs a gated-save drive — redundant with the host `SettingsModel` save tests; the notice binding is structurally identical to the error binding this test already exercises).
- **If the emulator is unavailable in the session:** Tasks 1, 2, and 4-host still ship fully (host-only). Commit the Task 3 test files, mark the instrumented run as "written, not executed here" in the handoff, and leave the emulator run as the resume step. Do NOT claim the instrumented tests passed without a green `connectedDebugAndroidTest`.
