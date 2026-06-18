package org.secretary.browse.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import kotlinx.coroutines.CompletableDeferred
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

class BrowseScreenSoftDeleteTest {
    @get:Rule val composeRule = createComposeRule()

    private val liveUuid = "33445566778899aabbccddeeff001122"
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val live = RecordSummaryView(
        liveUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("username", "u")),
    )

    private fun vm(): VaultBrowseViewModel {
        val session = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(live)))
        return VaultBrowseViewModel(VaultBrowseModel(session))
    }

    private fun openBlock(vm: VaultBrowseViewModel) {
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()
        composeRule.waitForIdle()
    }

    @Test
    fun delete_removesRecordFromLiveView() {
        val vm = vm()
        openBlock(vm)
        composeRule.onNodeWithTag("delete-$liveUuid").assertIsDisplayed().performClick()
        composeRule.waitForIdle()
        composeRule.onAllNodesWithTag("delete-$liveUuid").assertCountEquals(0)   // gone from live view
    }

    @Test
    fun deleteDisabledWhileWriteInFlight() {
        val gate = CompletableDeferred<Unit>()
        val session = FakeVaultSession(
            "abcd", listOf(block), mapOf(block.uuidHex to listOf(live)),
            writeGate = gate,
        )
        val vm = VaultBrowseViewModel(VaultBrowseModel(session))
        openBlock(vm)
        // Click Delete — the write coroutine parks on the gate, leaving main thread idle.
        composeRule.onNodeWithTag("delete-$liveUuid").performClick()
        composeRule.waitForIdle()
        // The writing flag is true while the gate is open → Delete must be disabled.
        composeRule.onNodeWithTag("delete-$liveUuid").assertIsNotEnabled()
        // Let the write finish so the coroutine tears down cleanly.
        gate.complete(Unit)
    }

    @Test
    fun showDeleted_revealsDeletedRecord_andRestoreBringsItBack() {
        val vm = vm()
        openBlock(vm)
        composeRule.onNodeWithTag("delete-$liveUuid").performClick()             // tombstone
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("toggle-show-deleted").performClick()          // show deleted
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("restore-$liveUuid").assertIsDisplayed().performClick()
        composeRule.waitForIdle()
        // After restore, with show-deleted still on, the row is live again → Delete button returns.
        composeRule.onNodeWithTag("delete-$liveUuid").assertIsDisplayed()
    }
}
