package org.secretary.app

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.UnlockCredential

class UnlockScreenDeviceUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun enrolled_showsBiometricUnlockButton_andInvokesCallback() {
        var biometricTapped = false
        composeRule.setContent {
            UnlockScreen(
                isEnrolled = true,
                rememberDevice = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = { biometricTapped = true },
            )
        }
        composeRule.onNodeWithTag("biometric-unlock").assertIsDisplayed().performClick()
        assertTrue(biometricTapped)
    }

    @Test
    fun notEnrolled_passwordMode_showsRememberCheckbox_andReportsChoice() {
        var lastChoice: Boolean? = null
        composeRule.setContent {
            UnlockScreen(
                isEnrolled = false,
                rememberDevice = false,
                onUnlock = {},
                onEnrollChoice = { lastChoice = it },
                onBiometricUnlock = {},
            )
        }
        composeRule.onNodeWithTag("remember-device").assertIsDisplayed().performClick()
        assertTrue(lastChoice == true)
    }

    @Test
    fun enrolled_hidesRememberCheckbox() {
        composeRule.setContent {
            UnlockScreen(
                isEnrolled = true,
                rememberDevice = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = {},
            )
        }
        // assertDoesNotExist not available in compose-bom 2025.05.00; assertCountEquals(0) is equivalent
        composeRule.onAllNodesWithTag("remember-device").assertCountEquals(0)
    }

    @Test
    fun notEnrolled_hidesBiometricButton() {
        composeRule.setContent {
            UnlockScreen(
                isEnrolled = false,
                rememberDevice = false,
                onUnlock = {},
                onEnrollChoice = {},
                onBiometricUnlock = {},
            )
        }
        // assertDoesNotExist not available in compose-bom 2025.05.00; assertCountEquals(0) is equivalent
        composeRule.onAllNodesWithTag("biometric-unlock").assertCountEquals(0)
    }
}
