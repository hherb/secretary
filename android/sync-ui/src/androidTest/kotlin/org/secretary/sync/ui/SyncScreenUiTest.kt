package org.secretary.sync.ui

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.SyncCollision
import org.secretary.sync.SyncCoordinator
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncVeto
import org.secretary.sync.VaultSyncModel

@RunWith(AndroidJUnit4::class)
class SyncScreenUiTest {
    @get:Rule val composeRule = createComposeRule()

    private fun model(): VaultSyncModel {
        val veto = SyncVeto(
            recordUuidHex = "aabb",
            recordType = "login",
            tags = listOf("work"),
            fieldNames = listOf("password"),
            localLastModMs = 1uL,
            peerTombstonedAtMs = 2uL,
            peerDeviceHex = "deadbeefcafef00d",
        )
        val conflict = SyncOutcome.ConflictsPending(
            vetoes = listOf(veto),
            collisions = listOf(SyncCollision(recordUuidHex = "ccdd", fieldNames = listOf("url"))),
            manifestHash = byteArrayOf(1, 2, 3),
        )
        // First interactive pass surfaces a conflict; the resolve commit comes back clean.
        val port = ScriptedSyncPort(syncOutcome = conflict, commitOutcome = SyncOutcome.MergedClean)
        val coordinator = SyncCoordinator(port, stateDir = "s", vaultFolder = "f")
        return VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null)
    }

    /**
     * End-to-end flow: badge tap → password entry → conflict sheet appears → Apply resolves clean
     * → conflict sheet closes. Exercises the full badge→password→conflict→resolve→sheet-closed
     * path through a real [VaultSyncViewModel] backed by scripted fakes.
     *
     * The password sheet stays open only while [VaultSyncViewModel.passwordSheetVisible] is true.
     * In this flow the interactive pass returns [SyncOutcome.ConflictsPending] (not an error), so
     * `lastError` is null and the VM closes the password sheet before surfacing the conflict sheet.
     *
     * [ModalBottomSheet] has show/hide animations; extra [androidx.compose.ui.test.ComposeContentTestRule.waitForIdle]
     * calls are inserted at each animation boundary so the test does not race the transition.
     */
    @Test
    fun badgeTap_password_conflict_resolve_endToEnd() {
        composeRule.setContent { SyncScreen(viewModel = VaultSyncViewModel(model())) }

        // Badge starts at "Never synced"; tap opens the password sheet.
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).performClick()
        composeRule.waitForIdle()

        // Type a password and submit. The sheet is a ModalBottomSheet so wait for idle twice —
        // once for the coroutine to fire, once for the animation to settle.
        composeRule.onNodeWithTag(PASSWORD_FIELD_TAG).performTextInput("pw")
        composeRule.onNodeWithText("Sync").performClick()
        composeRule.waitForIdle()
        composeRule.waitForIdle()

        // Conflict sheet appears; Apply resolves clean → sheet closes.
        composeRule.onNodeWithTag(CONFLICT_APPLY_TAG).performClick()
        composeRule.waitForIdle()
        composeRule.waitForIdle()

        // Conflict sheet is gone — assertCountEquals(0) is the BOM-1.8.1-compatible equivalent
        // of assertDoesNotExist(), which does not exist in this Compose version.
        composeRule.onAllNodesWithTag(CONFLICT_APPLY_TAG).assertCountEquals(0)
    }
}
