package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
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
                onUnlock = {},
                onEnrollChoice = { lastChoice = it },
                onBiometricUnlock = {},
            )
        }
        composeRule.onNodeWithTag("remember-device").assertIsDisplayed().performClick()
        assertTrue(lastChoice == true)
    }
}
