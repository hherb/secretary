package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * On-device proof that the unlock orchestration assembles a coherent browse+sync session over the
 * REAL libsecretary_ffi_uniffi.so: a browse VM with blocks loaded, a sync VM, and a monitor — then
 * a background sync-at-unlock settles cleanly on the single-device golden vault (an
 * AppliedAutomatically fast-forward against a fresh state dir).
 */
@RunWith(AndroidJUnit4::class)
class OpenBrowseWithSyncSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val goldenPassword = "correct horse battery staple"
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun assemblesBrowseAndSync_thenSyncAtUnlockSettlesClean() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        toClean += stateBase
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        // Assemble on the main thread (makeVaultSync is Looper-gated).
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                goldenPassword.toByteArray())
        }

        assertTrue("browse VM loaded blocks", session.browse.blocks.value.isNotEmpty())

        // Background sync-at-unlock with a password copy; join the job (test-only) and assert clean.
        val job = withContext(Dispatchers.Main) {
            launchSyncAtUnlock(this, goldenPassword.toByteArray(), session.sync::syncAtUnlock)
        }
        job.join()
        assertNull("clean silent pass surfaces no error", session.sync.lastError.value)
        assertTrue("review not raised on a clean single-device pass", !session.sync.reviewNeeded.value)

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
