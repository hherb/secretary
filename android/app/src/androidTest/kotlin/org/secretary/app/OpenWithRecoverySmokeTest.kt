package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.FileDeviceUuidStore
import org.secretary.browse.RecoveryPhrase
import org.secretary.browse.UnlockCredential
import org.secretary.browse.uniffiVaultOpenPort
import java.io.File

/**
 * On-device proof that the recovery-phrase open path works over the REAL
 * libsecretary_ffi_uniffi.so: open golden_vault_001 with its bundled 24-word recovery phrase and
 * reach the block list (mirrors OpenBrowseWithSyncSmokeTest, but via the recovery credential).
 */
@RunWith(AndroidJUnit4::class)
class OpenWithRecoverySmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val toClean = mutableListOf<File>()

    @After fun cleanup() {
        toClean.forEach { it.deleteRecursively() }
        File(context.filesDir, "golden_vault_001").deleteRecursively()
    }

    @Test
    fun opensGoldenVaultViaRecoveryPhrase_reachesBlockList() = runBlocking {
        val folder = AppVaultProvisioning.stageGoldenVault(context)
        val deviceUuids = FileDeviceUuidStore(File(context.noBackupFilesDir, "devices-${System.nanoTime()}"))
        val stateBase = File(context.cacheDir, "run-${System.nanoTime()}")
        val stateDir = syncStateDir(stateBase).apply { mkdirs() }
        toClean += stateBase
        val uuid = AppVaultProvisioning.goldenVaultUuid(context)

        val phraseBytes = RecoveryPhrase.normalize(AppVaultProvisioning.goldenRecoveryPhrase(context))
            .toByteArray(Charsets.UTF_8)
        val session = withContext(Dispatchers.Main) {
            openBrowseWithSync(
                uniffiVaultOpenPort(deviceUuids), folder, stateDir, uuid,
                UnlockCredential.Recovery(phraseBytes))
        }
        phraseBytes.fill(0)

        assertTrue("recovery open reached the block list", session.browse.blocks.value.isNotEmpty())

        withContext(Dispatchers.Main) { session.browse.lock() }
    }
}
