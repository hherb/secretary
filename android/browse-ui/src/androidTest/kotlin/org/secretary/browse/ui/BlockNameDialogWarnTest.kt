package org.secretary.browse.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.VaultBrowseModel

/** #269: create/rename block-name dialog warns (but still allows) on a name that collides
 *  case-insensitively with an existing block. Duplicate names stay writable. */
class BlockNameDialogWarnTest {
    @get:Rule val composeRule = createComposeRule()

    private val personal = BlockSummaryView(ByteArray(16) { 0x1A }, "Personal", 0u, 0u)
    private val work = BlockSummaryView(ByteArray(16) { 0x2B }, "Work", 1u, 0u)

    private fun openBrowse(): VaultBrowseViewModel {
        val session = FakeVaultSession(
            vaultUuidHex = "aabbccdd",
            blocks = listOf(personal, work),
            recordsByBlockHex = emptyMap(),
        )
        val vm = VaultBrowseViewModel(VaultBrowseModel(session))
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.waitForIdle()
        return vm
    }

    private fun openCreateDialog() {
        composeRule.onNodeWithTag("new-block").performClick()
        composeRule.waitForIdle()
    }

    @Test
    fun collidingName_showsWarning_andRelabelsConfirm() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("Work")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-warning").assertIsDisplayed()
        composeRule.onNodeWithText("Save anyway").assertIsDisplayed()
    }

    @Test
    fun caseOnlyDifference_showsWarning() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("work")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-warning").assertIsDisplayed()
    }

    @Test
    fun uniqueName_noWarning_andPlainConfirm() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("Finance")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-warning").assertDoesNotExist()
        composeRule.onNodeWithText("Save").assertIsDisplayed()
    }

    @Test
    fun saveAnyway_stillCreates_dialogDismisses() {
        openBrowse()
        openCreateDialog()
        composeRule.onNodeWithTag("block-name-field").performTextInput("Work")
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-confirm").performClick()
        composeRule.waitForIdle()
        // Allow verified: the dialog closed AND a second block named "Work" now exists —
        // duplicate names stay writable (warn-but-allow, not warn-and-block). Two rows read
        // "Work": the seeded block plus the just-created duplicate.
        composeRule.onNodeWithTag("block-name-field").assertDoesNotExist()
        composeRule.onAllNodesWithText("Work").assertCountEquals(2)
    }

    @Test
    fun renameSeededWithOwnName_noWarning() {
        openBrowse()
        composeRule.onNodeWithTag("rename-${personal.uuidHex}").performClick()
        composeRule.waitForIdle()
        // Field pre-filled with "Personal"; self is excluded by UUID → no collision.
        composeRule.onNodeWithTag("block-name-warning").assertDoesNotExist()
    }
}
