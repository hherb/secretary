package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.UnlockCredential
import org.secretary.browse.ui.BrowseScreen
import org.secretary.browse.ui.VaultBrowseViewModel
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * On-device round-trip acceptance test for block CRUD:
 *
 * 1. Open the real golden vault via [BrowseScreen] + [VaultBrowseViewModel].
 * 2. Create a new block through the UI ("new-block" → type name → "block-name-confirm").
 * 3. Navigate into the source block ("Personal logins"), pick its first record, tap "Move",
 *    select the newly-created block as the target.
 * 4. Navigate into the new block and assert the record is displayed there (read-back).
 * 5. Navigate back to the source block, toggle "toggle-show-deleted", and assert a
 *    tombstoned row appears (the moved record is tombstoned in the source).
 *
 * Models on [BrowseWithSyncScreenUiTest]: same vault staging, same uniffi open port wiring,
 * same [createAndroidComposeRule] + [waitUntil] pattern.
 */
@RunWith(AndroidJUnit4::class)
class BlockCrudRoundTripUiTest {
    @get:Rule val composeRule = createAndroidComposeRule<androidx.activity.ComponentActivity>()

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun createBlock_moveRecord_readBack_tombstoneInSource() = runBlocking {
        // ── Setup: stage the golden vault + open a real uniffi session ───────────────────────
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(
            File(context.noBackupFilesDir, "devices-${System.nanoTime()}")
        )
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        toClean += stateBase

        val password = AppVaultProvisioning.goldenPassword(context).toByteArray()
        val session: VaultBrowseViewModel = withContext(Dispatchers.Main) {
            val s = openBrowseWithSync(
                uniffiVaultOpenPort(deviceUuids),
                folder,
                syncStateDir(stateBase).apply { mkdirs() },
                AppVaultProvisioning.goldenVaultUuid(context),
                UnlockCredential.Password(password),
            )
            password.fill(0)
            s.browse
        }

        composeRule.setContent {
            BrowseScreen(viewModel = session, autoHideMillis = 60_000L)
        }

        // ── Step 1: Wait for block list; create a new block ──────────────────────────────────
        // Wait for "Personal logins" to confirm the block list is rendered.
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            composeRule.onAllNodesWithTag("new-block").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithText("Personal logins").assertIsDisplayed()

        val newBlockName = "Moved-${System.nanoTime()}"
        composeRule.onNodeWithTag("new-block").performClick()
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag("block-name-field").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag("block-name-field").performTextInput(newBlockName)
        composeRule.onNodeWithTag("block-name-confirm").performClick()

        // Wait for the new block to appear in the list (check via viewModel state, then assert
        // the composable renders it by name).
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            session.blocks.value.any { it.name == newBlockName }
        }
        composeRule.onNodeWithText(newBlockName).assertIsDisplayed()

        // Resolve the new block's uuidHex from the view model so we can target the move picker row.
        val newBlockHex = withContext(Dispatchers.Main) {
            session.blocks.value
                .firstOrNull { it.name == newBlockName }
                ?.uuidHex
        }
        assertTrue("new block not found in viewModel.blocks after create", newBlockHex != null)
        checkNotNull(newBlockHex)

        // ── Step 2: Navigate into "Personal logins", start moving its first record ────────────
        composeRule.onNodeWithText("Personal logins").performClick()
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            composeRule.onAllNodesWithTag("toggle-show-deleted").fetchSemanticsNodes().isNotEmpty()
        }

        // Resolve the first (live) record's uuidHex from the view model.
        val sourceRecordHex = withContext(Dispatchers.Main) {
            session.selectedRecords.value
                ?.firstOrNull { !it.tombstone }
                ?.uuidHex
        }
        assertTrue("no live record found in source block", sourceRecordHex != null)
        checkNotNull(sourceRecordHex)

        // Tap the Move button for the record.
        composeRule.onNodeWithTag("move-$sourceRecordHex").performClick()
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag("move-target-$newBlockHex").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag("move-target-$newBlockHex").performClick()

        // After the move the picker closes and the source block is re-read; the record is
        // withheld (tombstoned, showDeleted=false) so the live list now shows no live rows.
        // StateFlow.value is thread-safe to read from the test thread (no coroutine needed).
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            session.selectedRecords.value?.none { !it.tombstone } == true
        }

        // ── Step 3: Navigate Back → enter the new block → assert read-back ──────────────────
        composeRule.onNodeWithText("Back").performClick()
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag("new-block").fetchSemanticsNodes().isNotEmpty()
        }

        composeRule.onNodeWithText(newBlockName).performClick()
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            composeRule.onAllNodesWithTag("toggle-show-deleted").fetchSemanticsNodes().isNotEmpty()
        }

        // The moved record should be present in the new block.
        val movedRecordHex = withContext(Dispatchers.Main) {
            session.selectedRecords.value
                ?.firstOrNull { !it.tombstone }
                ?.uuidHex
        }
        assertTrue("moved record not found in new block", movedRecordHex != null)
        checkNotNull(movedRecordHex)

        // Reveal the "username" field to confirm the value materializes.
        val usernameRevealTag = "reveal-$movedRecordHex-username"
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag(usernameRevealTag).fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag(usernameRevealTag).performClick()
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag("value-$movedRecordHex-username").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag("value-$movedRecordHex-username").assertIsDisplayed()

        // ── Step 4: Back → source block → toggle-show-deleted → tombstoned row appears ───────
        composeRule.onNodeWithText("Back").performClick()
        composeRule.waitUntil(timeoutMillis = 5_000L) {
            composeRule.onAllNodesWithTag("new-block").fetchSemanticsNodes().isNotEmpty()
        }

        composeRule.onNodeWithText("Personal logins").performClick()
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            composeRule.onAllNodesWithTag("toggle-show-deleted").fetchSemanticsNodes().isNotEmpty()
        }

        // Enable show-deleted so the tombstoned record becomes visible.
        composeRule.onNodeWithTag("toggle-show-deleted").performClick()
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            session.selectedRecords.value?.any { it.tombstone } == true
        }

        // Confirm a tombstoned row is rendered (the "Restore" button marks the tombstone row).
        assertTrue(
            "no tombstoned record visible after toggle-show-deleted",
            composeRule.onAllNodesWithTag("restore-$sourceRecordHex").fetchSemanticsNodes().isNotEmpty(),
        )

        withContext(Dispatchers.Main) { session.lock() }
    }
}
