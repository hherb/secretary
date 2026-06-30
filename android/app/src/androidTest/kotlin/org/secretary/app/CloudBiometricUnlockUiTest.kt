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
