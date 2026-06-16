package org.secretary.sync.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.VaultSyncError

@RunWith(AndroidJUnit4::class)
class SyncPasswordSheetUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun typingAndSubmitting_forwardsPasswordBytes() {
        var captured: ByteArray? = null
        composeRule.setContent {
            PasswordSheetContent(error = null, onSubmit = { captured = it }, onDismiss = {})
        }
        composeRule.onNodeWithTag(PASSWORD_FIELD_TAG).performTextInput("hunter2")
        composeRule.onNodeWithText("Sync").performClick()
        assertNotNull(captured)
        assertTrue(captured!!.contentEquals("hunter2".toByteArray()))
    }

    @Test
    fun error_isShownInline() {
        composeRule.setContent {
            PasswordSheetContent(error = VaultSyncError.WrongPasswordOrCorrupt, onSubmit = {}, onDismiss = {})
        }
        composeRule.onNodeWithTag(PASSWORD_ERROR_TAG).assertIsDisplayed()
    }
}
