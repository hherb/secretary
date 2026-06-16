package org.secretary.sync.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.PendingConflict
import org.secretary.sync.SyncCollision
import org.secretary.sync.SyncVeto
import org.secretary.sync.SyncVetoDecision

@RunWith(AndroidJUnit4::class)
class ConflictResolutionSheetUiTest {
    @get:Rule val composeRule = createComposeRule()

    private val veto = SyncVeto(
        recordUuidHex = "aabb",
        recordType = "login",
        tags = listOf("work"),
        fieldNames = listOf("password"),
        localLastModMs = 100uL,
        peerTombstonedAtMs = 200uL,
        peerDeviceHex = "deadbeefcafef00d",
    )
    private val conflict = PendingConflict(
        vetoes = listOf(veto),
        collisions = listOf(SyncCollision(recordUuidHex = "ccdd", fieldNames = listOf("url"))),
    )

    @Test
    fun showsRecordMetadata_andDefaultsToKeepMine() {
        var decisions: List<SyncVetoDecision>? = null
        composeRule.setContent {
            ConflictSheetContent(conflict = conflict, error = null, onResolve = { decisions = it }, onCancel = {})
        }
        composeRule.onNodeWithText("login").assertIsDisplayed()
        composeRule.onNodeWithText("Apply").performClick()
        // No toggle touched → default keepLocal = true for the single veto.
        assertEquals(listOf(SyncVetoDecision("aabb", true)), decisions)
    }

    @Test
    fun acceptDelete_flipsDecisionToKeepLocalFalse() {
        var decisions: List<SyncVetoDecision>? = null
        composeRule.setContent {
            ConflictSheetContent(conflict = conflict, error = null, onResolve = { decisions = it }, onCancel = {})
        }
        composeRule.onNodeWithText("Accept delete").performClick()
        composeRule.onNodeWithText("Apply").performClick()
        assertEquals(listOf(SyncVetoDecision("aabb", false)), decisions)
    }

    @Test
    fun cancel_invokesOnCancel() {
        var cancelled = false
        composeRule.setContent {
            ConflictSheetContent(conflict = conflict, error = null, onResolve = {}, onCancel = { cancelled = true })
        }
        composeRule.onNodeWithText("Cancel").performClick()
        assertTrue("Cancel must invoke onCancel", cancelled)
    }

    @Test
    fun error_isShownInline() {
        composeRule.setContent {
            ConflictSheetContent(conflict = conflict, error = org.secretary.sync.VaultSyncError.EvidenceStale, onResolve = {}, onCancel = {})
        }
        composeRule.onNodeWithTag(CONFLICT_ERROR_TAG).assertIsDisplayed()
    }

    @Test
    fun collisionSummary_isShown() {
        composeRule.setContent {
            ConflictSheetContent(conflict = conflict, error = null, onResolve = {}, onCancel = {})
        }
        composeRule.onNodeWithText("1 field(s) auto-merged — no action needed").assertIsDisplayed()
    }

    @Test
    fun multipleVetoes_toggleIndependently() {
        val veto2 = SyncVeto(
            recordUuidHex = "ccdd", recordType = "note", tags = emptyList(),
            fieldNames = listOf("body"), localLastModMs = 1uL, peerTombstonedAtMs = 2uL,
            peerDeviceHex = "00112233445566778899",
        )
        val twoVetoConflict = PendingConflict(vetoes = listOf(veto, veto2), collisions = emptyList())
        var decisions: List<SyncVetoDecision>? = null
        composeRule.setContent {
            ConflictSheetContent(conflict = twoVetoConflict, error = null, onResolve = { decisions = it }, onCancel = {})
        }
        // Flip only the SECOND veto to Accept delete; the first stays default Keep mine.
        composeRule.onAllNodesWithText("Accept delete")[1].performClick()
        composeRule.onNodeWithText("Apply").performClick()
        assertEquals(
            listOf(SyncVetoDecision("aabb", true), SyncVetoDecision("ccdd", false)),
            decisions,
        )
    }
}
