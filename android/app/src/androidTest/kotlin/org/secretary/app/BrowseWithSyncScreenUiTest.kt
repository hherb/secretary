package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.UnlockCredential
import org.secretary.browse.uniffiVaultOpenPort
import org.secretary.sync.ui.SYNC_BADGE_TAG
import java.io.File

/**
 * Proves the UNIFICATION: the sync badge and the browse content render together on one screen, and
 * the badge survives navigating from the block list into a block's record list. Built over the real
 * `.so` session (reusing openBrowseWithSync) rather than fabricated fakes, so the test exercises the
 * production composition path.
 */
@RunWith(AndroidJUnit4::class)
class BrowseWithSyncScreenUiTest {
    @get:Rule val composeRule = createAndroidComposeRule<androidx.activity.ComponentActivity>()

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext
    private val goldenPassword = "correct horse battery staple"
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun badgeAndBlocksRenderTogether_badgeSurvivesBlockNavigation() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        toClean += stateBase
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        val pw = goldenPassword.toByteArray()
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(
                uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                UnlockCredential.Password(pw))
        }
        pw.fill(0)

        composeRule.setContent {
            BrowseWithSyncScreen(browse = session.browse, sync = session.sync)
        }

        // Badge + the "Blocks" header are visible together on the block-list view.
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).assertIsDisplayed()
        composeRule.onNodeWithText("Blocks").assertIsDisplayed()

        // Navigate into the first block by driving the view-model directly (avoids brittle
        // label matching against real block UUIDs). The invariant is "badge visible on both
        // the block-list view AND the record-list view".
        withContext(Dispatchers.Main) {
            session.browse.selectBlock(session.browse.blocks.value.first())
        }
        // selectBlock launches a viewModelScope coroutine that decrypts the block; waitUntil
        // polls until the record-list view renders (the "toggle-show-deleted" Switch is only
        // present on the record-list, never on the block-list view) — so the subsequent badge
        // assertion genuinely proves "badge visible on the record-list view".
        composeRule.waitUntil(timeoutMillis = 10_000L) {
            composeRule.onAllNodesWithTag("toggle-show-deleted").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag(SYNC_BADGE_TAG).assertIsDisplayed()

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
