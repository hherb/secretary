package org.secretary.browse.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

class BrowseScreenRevealTest {
    @get:Rule val composeRule = createComposeRule()

    private val recUuid = "33445566778899aabbccddeeff001122"
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val rec = RecordSummaryView(
        recUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("password", "hunter2")),
    )

    private fun viewModel(): VaultBrowseViewModel {
        val session = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(rec)))
        return VaultBrowseViewModel(VaultBrowseModel(session))
    }

    private fun openBlock(vm: VaultBrowseViewModel, autoHideMillis: Long) {
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = autoHideMillis) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()       // select the block
        composeRule.waitForIdle()
    }

    @Test
    fun tapReveal_showsValue_thenTapHide_removesIt() {
        val vm = viewModel()
        openBlock(vm, autoHideMillis = 60_000L)                   // long timer: won't auto-fire
        composeRule.onNodeWithTag("reveal-$recUuid-password").performClick()
        composeRule.onNodeWithTag("value-$recUuid-password").assertIsDisplayed()
        composeRule.onNodeWithTag("reveal-$recUuid-password").performClick()  // now "Hide"
        // assertDoesNotExist not available in compose-bom 2025.05.00; assertCountEquals(0) is equivalent
        composeRule.onAllNodesWithTag("value-$recUuid-password").assertCountEquals(0)
    }

    @Test
    fun revealedValue_autoHidesAfterTheInterval() {
        val vm = viewModel()
        openBlock(vm, autoHideMillis = 300L)                      // short timer
        composeRule.onNodeWithTag("reveal-$recUuid-password").performClick()
        composeRule.onNodeWithTag("value-$recUuid-password").assertIsDisplayed()
        // The auto-hide LaunchedEffect fires after 300ms; waitUntil polls until the node is gone.
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag("value-$recUuid-password").fetchSemanticsNodes().isEmpty()
        }
        composeRule.onAllNodesWithTag("value-$recUuid-password").assertCountEquals(0)
    }
}
