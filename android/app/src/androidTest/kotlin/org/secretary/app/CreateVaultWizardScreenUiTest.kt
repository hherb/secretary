package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.MnemonicWord
import org.secretary.browse.VaultNameError
import org.secretary.browse.VaultProvisioningStep

class CreateVaultWizardScreenUiTest {
    @get:Rule val rule = createComposeRule()

    @Test
    fun folder_step_reports_name_and_pick() {
        var chosenName: String? = null
        rule.setContent {
            CreateVaultWizardScreen(
                step = VaultProvisioningStep.Folder, nameError = null, error = null,
                isCreating = false, mnemonicRows = null,
                onPickParent = {}, pickedFolderLabel = "Vaults",
                onChooseFolder = { chosenName = it }, onCreate = { _, _ -> },
                onAcknowledge = {}, onCancel = {},
            )
        }
        rule.onNodeWithTag("wizard-name").performTextInput("My Vault")
        rule.onNodeWithTag("wizard-next").performClick()
        assertEquals("My Vault", chosenName)
    }

    @Test
    fun folder_step_shows_name_error() {
        rule.setContent {
            CreateVaultWizardScreen(
                step = VaultProvisioningStep.Folder, nameError = VaultNameError.Blank, error = null,
                isCreating = false, mnemonicRows = null,
                onPickParent = {}, pickedFolderLabel = null,
                onChooseFolder = {}, onCreate = { _, _ -> }, onAcknowledge = {}, onCancel = {},
            )
        }
        rule.onNodeWithTag("wizard-name-error").assertIsDisplayed()
    }

    @Test
    fun mnemonic_step_shows_grid_and_acknowledges() {
        var acked = false
        rule.setContent {
            CreateVaultWizardScreen(
                step = VaultProvisioningStep.Mnemonic, nameError = null, error = null,
                isCreating = false,
                mnemonicRows = listOf(MnemonicWord(1, "alpha"), MnemonicWord(2, "bravo")),
                onPickParent = {}, pickedFolderLabel = null,
                onChooseFolder = {}, onCreate = { _, _ -> },
                onAcknowledge = { acked = true }, onCancel = {},
            )
        }
        rule.onNodeWithTag("mnemonic-grid").assertIsDisplayed()
        rule.onNodeWithTag("wizard-ack").performClick()
        assertTrue(acked)
    }
}
