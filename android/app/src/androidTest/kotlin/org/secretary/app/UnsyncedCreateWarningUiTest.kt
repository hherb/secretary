package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
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
