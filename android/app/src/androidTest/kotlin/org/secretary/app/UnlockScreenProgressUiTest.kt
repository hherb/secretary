package org.secretary.app

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
        composeRule.onNodeWithTag("mode-recovery").assertIsNotEnabled()
        composeRule.onNodeWithTag("remember-device").assertIsNotEnabled()
        // recovery-field and biometric-unlock render only in other states (recovery mode / enrolled)
        // and are not asserted here.
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
