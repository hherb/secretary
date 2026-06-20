package org.secretary.browse.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

class BlockCrudUiTest {
    @get:Rule val composeRule = createComposeRule()

    private val blockA = BlockSummaryView(ByteArray(16) { 0x1A }, "Personal", 0u, 0u)
    private val blockB = BlockSummaryView(ByteArray(16) { 0x2B }, "Work", 1u, 0u)
    private val recordInA = RecordSummaryView(
        uuidHex = "cc00000000000000000000000000cc01",
        type = "login",
        tags = emptyList(),
        createdAtMs = 0u,
        lastModMs = 0u,
        tombstone = false,
        fields = listOf(textField("username", "alice")),
    )

    private fun vm(): VaultBrowseViewModel {
        val session = FakeVaultSession(
            vaultUuidHex = "aabbccdd",
            blocks = listOf(blockA, blockB),
            recordsByBlockHex = mapOf(blockA.uuidHex to listOf(recordInA)),
        )
        return VaultBrowseViewModel(VaultBrowseModel(session))
    }

    // --- Test 1: New block ---
    @Test
    fun newBlock_tapConfirm_appearsInBlockList() {
        val vm = vm()
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }

        composeRule.onNodeWithTag("new-block").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("block-name-field").performTextInput("Finance")
        composeRule.onNodeWithTag("block-name-confirm").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithText("Finance").assertIsDisplayed()
    }

    // --- Test 2: Move record ---
    @Test
    fun moveRecord_tapTarget_recordLeavesSourceList() {
        val vm = vm()
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }

        // Navigate into blockA
        composeRule.onNodeWithText("Personal").performClick()
        composeRule.waitForIdle()

        // Tap the "Move" button for the record
        composeRule.onNodeWithTag("move-${recordInA.uuidHex}").performClick()
        composeRule.waitForIdle()

        // The picker should show blockB as a target (blockA is the source, filtered out)
        composeRule.onNodeWithTag("move-target-${blockB.uuidHex}").assertIsDisplayed().performClick()
        composeRule.waitForIdle()

        // Record is tombstoned in blockA → should be gone from the live list
        composeRule.onNodeWithText("alice").assertDoesNotExist()
    }

    // --- Test 3: Rename block ---
    @Test
    fun renameBlock_tapConfirm_newNameInBlockList() {
        val vm = vm()
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }

        // The block list is visible; tap Rename for blockA
        composeRule.onNodeWithTag("rename-${blockA.uuidHex}").assertIsDisplayed().performClick()
        composeRule.waitForIdle()

        // Dialog opens pre-filled with "Personal"
        composeRule.onNodeWithTag("block-name-field").assertIsDisplayed()

        // Replace the pre-filled text with the new name
        composeRule.onNodeWithTag("block-name-field").performTextReplacement("Renamed")
        composeRule.onNodeWithTag("block-name-confirm").performClick()
        composeRule.waitForIdle()

        // New name appears in the block list
        composeRule.onNodeWithText("Renamed").assertIsDisplayed()
    }
}
