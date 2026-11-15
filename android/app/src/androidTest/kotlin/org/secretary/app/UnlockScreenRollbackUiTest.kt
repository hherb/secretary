package org.secretary.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.UnlockCredential

/**
 * The rollback reset dialog (#746): the first password open is refused as a rollback, AppRoot sets
 * `showRollbackReset`, and the dialog must reuse the password still in the field. Drives the real
 * [UnlockScreen]; the open itself is AppRoot's, faked here by flipping the flag after submit.
 */
class UnlockScreenRollbackUiTest {
    @get:Rule val composeRule = createComposeRule()

    private val submitted = mutableListOf<UnlockCredential>()
    private var cancels = 0

    /** Types [password], submits, then plays AppRoot's answer to a rollback refusal. */
    private fun submitAndRefuse(password: String) {
        var showReset by mutableStateOf(false)
        composeRule.setContent {
            UnlockScreen(
                title = "Secretary — demo vault",
                isEnrolled = false,
                rememberDevice = false,
                isUnlocking = false,
                onUnlock = { submitted += it; showReset = true },
                onEnrollChoice = {},
                onBiometricUnlock = {},
                showRollbackReset = showReset,
                onRollbackCancel = { cancels++; showReset = false },
            )
        }
        composeRule.onNodeWithTag("password-field").performTextInput(password)
        composeRule.onNodeWithTag("unlock-button").performClick()
        composeRule.onNodeWithTag("rollback-reset-dialog").assertIsDisplayed()
    }

    @Test
    fun theDialogShowsTheSharedCopy() {
        submitAndRefuse("hunter2")
        composeRule.onNodeWithText(ROLLBACK_DIALOG_TITLE).assertIsDisplayed()
        composeRule.onNodeWithText(ROLLBACK_DIALOG_BODY).assertIsDisplayed()
        composeRule.onNodeWithText(ROLLBACK_DIALOG_CONFIRM).assertIsDisplayed()
        composeRule.onNodeWithText(ROLLBACK_DIALOG_CANCEL).assertIsDisplayed()
    }

    @Test
    fun confirmResubmitsTheEnteredPasswordAsAReset() {
        submitAndRefuse("hunter2")
        composeRule.onNodeWithTag("rollback-reset-confirm").performClick()

        assertEquals(2, submitted.size)
        val first = submitted[0] as UnlockCredential.Password
        val reset = submitted[1] as UnlockCredential.Password
        assertTrue("the first open must not reset", !first.resetSyncState)
        assertTrue("confirm must ask for the reset", reset.resetSyncState)
        assertArrayEquals("hunter2".toByteArray(Charsets.UTF_8), reset.secret)
        assertEquals(0, cancels)
    }

    @Test
    fun cancelDismissesWithoutResetting() {
        submitAndRefuse("hunter2")
        composeRule.onNodeWithTag("rollback-reset-cancel").performClick()

        assertEquals(1, cancels)
        assertEquals("only the original open, no reset", 1, submitted.size)
        composeRule.onNodeWithTag("rollback-reset-dialog").assertDoesNotExist()
    }
}
