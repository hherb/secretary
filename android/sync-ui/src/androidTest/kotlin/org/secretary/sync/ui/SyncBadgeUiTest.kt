package org.secretary.sync.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.SyncBadgeState

@RunWith(AndroidJUnit4::class)
class SyncBadgeUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun reviewNeeded_showsLabel() {
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.ReviewNeeded, nowMs = 0uL, onTap = {})
        }
        composeRule.onNodeWithText("Review needed").assertIsDisplayed()
    }

    @Test
    fun syncing_showsSpinner_andTapIsDisabled() {
        var tapped = false
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.Syncing, nowMs = 0uL, onTap = { tapped = true })
        }
        composeRule.onNodeWithTag(SYNC_BADGE_SPINNER_TAG).assertIsDisplayed()
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).performClick()
        assertTrue("tap must be ignored while syncing", !tapped)
    }

    @Test
    fun synced_tap_invokesCallback() {
        var tapped = false
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.Synced(sinceMs = 0uL), nowMs = 0uL, onTap = { tapped = true })
        }
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).performClick()
        assertTrue(tapped)
    }

    @Test
    fun neverSynced_showsLabel() {
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.NeverSynced, nowMs = 0uL, onTap = {})
        }
        composeRule.onNodeWithText("Never synced").assertIsDisplayed()
    }

    @Test
    fun synced_showsRelativeLabel() {
        // nowMs == sinceMs → "just now"
        composeRule.setContent {
            SyncBadge(state = SyncBadgeState.Synced(sinceMs = 1_000uL), nowMs = 1_000uL, onTap = {})
        }
        composeRule.onNodeWithText("Synced just now").assertIsDisplayed()
    }
}
