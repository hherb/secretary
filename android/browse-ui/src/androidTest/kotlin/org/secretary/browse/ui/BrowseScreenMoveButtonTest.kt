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

/** #429: the per-record Move affordance is hidden when the open vault has no other block to move
 *  into, and shown once a second block exists. Only Move is gated — Edit/Delete stay. */
class BrowseScreenMoveButtonTest {
    @get:Rule val composeRule = createComposeRule()

    private val liveUuid = "33445566778899aabbccddeeff001122"
    private val logins = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val cards = BlockSummaryView(ByteArray(16) { 0x4d }, "Cards", 1u, 2u)
    private val live = RecordSummaryView(
        liveUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("username", "u")),
    )

    private fun open(blocks: List<BlockSummaryView>): VaultBrowseViewModel {
        val session = FakeVaultSession("abcd", blocks, mapOf(logins.uuidHex to listOf(live)))
        val vm = VaultBrowseViewModel(VaultBrowseModel(session))
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()
        composeRule.waitForIdle()
        return vm
    }

    @Test
    fun singleBlockVault_hidesMoveButton_butKeepsEditAndDelete() {
        open(listOf(logins))
        composeRule.onAllNodesWithTag("move-$liveUuid").assertCountEquals(0)
        composeRule.onNodeWithTag("edit-$liveUuid").assertIsDisplayed()
        composeRule.onNodeWithTag("delete-$liveUuid").assertIsDisplayed()
    }

    @Test
    fun multiBlockVault_showsMoveButton() {
        open(listOf(logins, cards))
        composeRule.onNodeWithTag("move-$liveUuid").assertIsDisplayed()
    }
}
