package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.VaultSelectionState

class VaultSelectionScreenUiTest {
    @get:Rule val rule = createComposeRule()

    @Test
    fun empty_state_offers_create_and_demo() {
        var created = false
        rule.setContent {
            VaultSelectionScreen(
                state = VaultSelectionState.Empty,
                onCreate = { created = true }, onOpen = {}, onChooseDifferent = {},
                onPickFolder = {}, onDemo = {},
            )
        }
        rule.onNodeWithTag("create-vault").assertIsDisplayed().performClick()
        rule.onNodeWithTag("open-demo").assertIsDisplayed()
        assertTrue(created)
    }

    @Test
    fun located_state_offers_open() {
        var opened = false
        rule.setContent {
            VaultSelectionScreen(
                state = VaultSelectionState.Located("My Vault"),
                onCreate = {}, onOpen = { opened = true }, onChooseDifferent = {},
                onPickFolder = {}, onDemo = {},
            )
        }
        rule.onNodeWithTag("open-vault").assertIsDisplayed().performClick()
        rule.onNodeWithTag("choose-different").assertIsDisplayed()
        assertTrue(opened)
    }

    @Test
    fun unavailable_state_shows_reason_and_repick() {
        rule.setContent {
            VaultSelectionScreen(
                state = VaultSelectionState.Unavailable("offline"),
                onCreate = {}, onOpen = {}, onChooseDifferent = {},
                onPickFolder = {}, onDemo = {},
            )
        }
        rule.onNodeWithTag("selection-reason").assertIsDisplayed()
        rule.onNodeWithTag("pick-folder").assertIsDisplayed()
    }
}
