package org.secretary.app

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.UnlockCredential

class UnlockScreenRecoveryUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun recoveryMode_submitsANormalizedRecoveryCredential() {
        var captured: UnlockCredential? = null
        composeRule.setContent { UnlockScreen(onUnlock = { captured = it }) }

        // Switch to recovery mode, type a noisy phrase, submit.
        composeRule.onNodeWithTag("mode-recovery").performClick()
        composeRule.onNodeWithTag("recovery-field").performTextInput("  Alpha   BRAVO  ")
        composeRule.onNodeWithTag("unlock-button").performClick()

        val cred = captured
        assertTrue("expected a Recovery credential", cred is UnlockCredential.Recovery)
        // Normalized: lowercased, single-spaced, trimmed, UTF-8.
        assertArrayEquals("alpha bravo".toByteArray(Charsets.UTF_8), cred!!.secret)
    }

    @Test
    fun passwordMode_submitsAPasswordCredential() {
        var captured: UnlockCredential? = null
        composeRule.setContent { UnlockScreen(onUnlock = { captured = it }) }

        composeRule.onNodeWithTag("password-field").performTextInput("hunter2")
        composeRule.onNodeWithTag("unlock-button").performClick()

        val cred = captured
        assertTrue("expected a Password credential", cred is UnlockCredential.Password)
        assertArrayEquals("hunter2".toByteArray(Charsets.UTF_8), cred!!.secret)
    }
}
