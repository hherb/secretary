package org.secretary.app

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.DeviceSettingsState

class DeviceSettingsScreenUiTest {
    @get:Rule val composeRule = createComposeRule()

    @Test
    fun unenrolled_showsEnableButton_notDisable() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("enroll-button").assertIsDisplayed()
        composeRule.onAllNodesWithTag("disenroll-button").assertCountEquals(0)
    }

    @Test
    fun enrolled_showsDisableButton_notEnable() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = true),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("disenroll-button").assertIsDisplayed()
        composeRule.onAllNodesWithTag("enroll-button").assertCountEquals(0)
    }

    @Test
    fun enable_opensPasswordDialog_confirmInvokesOnEnroll() {
        var enrolled = false
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false),
                onEnroll = { enrolled = true }, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("enroll-button").performClick()
        composeRule.onNodeWithTag("enroll-password-field").assertIsDisplayed().performTextInput("pw")
        composeRule.onNodeWithTag("enroll-confirm").performClick()
        assertTrue(enrolled)
    }

    @Test
    fun disable_opensConfirmDialog_confirmInvokesOnDisenroll() {
        var disenrolled = false
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = true),
                onEnroll = {}, onDisenroll = { disenrolled = true }, onBack = {},
            )
        }
        composeRule.onNodeWithTag("disenroll-button").performClick()
        composeRule.onNodeWithTag("disenroll-confirm").assertIsDisplayed().performClick()
        assertTrue(disenrolled)
    }

    @Test
    fun error_isDisplayed() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false, error = "boom"),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("device-error").assertIsDisplayed()
    }

    @Test
    fun working_disablesActionButton() {
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false, working = true),
                onEnroll = {}, onDisenroll = {}, onBack = {},
            )
        }
        composeRule.onNodeWithTag("enroll-button").assertIsNotEnabled()
    }

    @Test
    fun back_invokesOnBack() {
        var backed = false
        composeRule.setContent {
            DeviceSettingsScreen(
                state = DeviceSettingsState(enrolled = false),
                onEnroll = {}, onDisenroll = {}, onBack = { backed = true },
            )
        }
        composeRule.onNodeWithTag("settings-back").performClick()
        assertTrue(backed)
    }
}
