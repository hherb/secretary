package org.secretary.browse.ui

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import org.junit.Rule
import org.junit.Test
import org.secretary.browse.BlockSummaryView
import org.secretary.browse.FakeVaultSession
import org.secretary.browse.RecordSummaryView
import org.secretary.browse.VaultBrowseModel
import org.secretary.browse.textField

class RecordEditFormTest {
    @get:Rule val composeRule = createComposeRule()

    private val recUuid = "33445566778899aabbccddeeff001122"
    private val block = BlockSummaryView(ByteArray(16) { 0x4c }, "Logins", 1u, 2u)
    private val existing = RecordSummaryView(
        recUuid, "login", emptyList(), 1u, 2u, false, listOf(textField("user", "alice")),
    )

    private fun fakeAndVm(): Pair<FakeVaultSession, VaultBrowseViewModel> {
        val session = FakeVaultSession("abcd", listOf(block), mapOf(block.uuidHex to listOf(existing)))
        return session to VaultBrowseViewModel(VaultBrowseModel(session))
    }

    private fun openBlock(vm: VaultBrowseViewModel) {
        composeRule.setContent { BrowseScreen(viewModel = vm, autoHideMillis = 60_000L) }
        composeRule.runOnIdle { vm.loadBlocks() }
        composeRule.onNodeWithText("Logins").performClick()
        composeRule.waitForIdle()
    }

    @Test
    fun add_newRecord_appearsInList() {
        val (fake, vm) = fakeAndVm()
        openBlock(vm)
        composeRule.onNodeWithTag("add-record").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("record-type-input").performTextInput("note")
        composeRule.onNodeWithTag("add-field").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("field-name-0").performTextInput("body")
        composeRule.onNodeWithTag("field-value-0").performTextInput("hello")
        composeRule.onNodeWithTag("save-record").performClick()
        composeRule.waitForIdle()
        // Form dismissed + new record present.
        assert(fake.appended.size == 1)
        composeRule.onNodeWithText("note").assertIsDisplayed()
    }

    @Test
    fun edit_existingRecord_recordsTheEdit() {
        val (fake, vm) = fakeAndVm()
        openBlock(vm)
        composeRule.onNodeWithTag("edit-$recUuid").performClick()
        composeRule.waitForIdle()
        // Field 0 prefilled with the revealed plaintext; change it.
        composeRule.onNodeWithTag("field-value-0").performTextInput("bob")
        composeRule.onNodeWithTag("save-record").performClick()
        composeRule.waitForIdle()
        assert(fake.edited.size == 1)
        assert(fake.edited.first().second == recUuid)
    }
}
