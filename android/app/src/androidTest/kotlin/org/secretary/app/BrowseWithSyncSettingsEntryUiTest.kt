package org.secretary.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
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
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/** Proves the Browse screen exposes a settings entry that invokes its callback. Built over the real
 *  `.so` session (like BrowseWithSyncScreenUiTest) so it exercises the production composition path. */
@RunWith(AndroidJUnit4::class)
class BrowseWithSyncSettingsEntryUiTest {
    @get:Rule val composeRule = createAndroidComposeRule<androidx.activity.ComponentActivity>()

    private val context get() = androidx.test.platform.app.InstrumentationRegistry
        .getInstrumentation().targetContext
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun browse_showsSettingsEntry_andInvokesCallback() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        toClean += stateBase
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        val pw = "correct horse battery staple".toByteArray()
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                UnlockCredential.Password(pw))
        }
        pw.fill(0)

        var opened = false
        composeRule.setContent {
            BrowseWithSyncScreen(browse = session.browse, sync = session.sync,
                onOpenSettings = { opened = true })
        }
        composeRule.onNodeWithTag("open-settings").assertIsDisplayed().performClick()
        assertTrue(opened)

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
