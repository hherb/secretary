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
