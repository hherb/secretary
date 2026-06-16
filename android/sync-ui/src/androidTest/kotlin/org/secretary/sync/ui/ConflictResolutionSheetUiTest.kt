package org.secretary.sync.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
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
}
