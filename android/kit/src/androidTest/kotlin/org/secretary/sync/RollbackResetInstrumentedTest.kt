package org.secretary.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.UniffiVaultOpenPort
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultSession
import org.secretary.browse.setPlatformSyncStateDir
import java.io.File

/**
 * #746 on device: after [setPlatformSyncStateDir], the open-time rollback check reads THAT dir — the
 * one this app's sync writes — and the reset clears it.
 *
 * Before #746 the check read `dirs::data_dir()/secretary/sync`, which Android never writes, so the
 * refused open below succeeded. A baseline is created the way the app creates one: a write, then a
 * sync pass into the state dir. An older copy of the same vault (same UUID, a clock the baseline
 * strictly dominates) then stands in for a provider serving a stale vault.
 *
 * The override is once per process, so every test in this APK that sets it must use [STATE_DIRNAME].
 * The golden vault's baseline is deleted after the test: any later open of a golden copy in this
 * process reads the same dir.
 */
@RunWith(AndroidJUnit4::class)
class RollbackResetInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val stateDir get() = File(context.filesDir, STATE_DIRNAME)
    private val toClean = mutableListOf<File>()
    private val sessions = mutableListOf<VaultSession>()

    @After fun cleanup() {
        sessions.forEach { it.wipe() }
        toClean.forEach { it.deleteRecursively() }
        stateDir.listFiles()?.forEach { it.deleteRecursively() }
    }

    @Test
    fun aDominatingBaselineInTheOverriddenDirRefusesTheOpenAndTheResetClearsIt() = runBlocking {
        stateDir.mkdirs()
        setPlatformSyncStateDir(stateDir)
        val uuid = GoldenVaultStaging.goldenVaultUuid(context)

        val current = GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }
        val older = File(current.parentFile!!, "older").also { current.copyRecursively(it) }

        // Advance the current copy past the older one, then record that clock as this device's baseline.
        GoldenVaultStaging.openSession(current).also { sessions += it }.let { session ->
            session.createBlock("advance the clock")
            UniffiVaultSyncPort(session).sync(stateDir.path, MERGE_CLOCK_MS)
        }
        val syncPort = UniffiVaultSyncPort(GoldenVaultStaging.openSession(current).also { sessions += it })
        assertTrue("the sync pass must persist a baseline", syncPort.status(stateDir.path, uuid).hasState)

        val thrown = runCatching {
            UniffiVaultOpenPort().openWithPassword(older.path, GoldenVaultStaging.PASSWORD)
        }.exceptionOrNull()
        assertEquals("the open must read the overridden dir's baseline", VaultBrowseError.RollbackDetected, thrown)

        val reset = UniffiVaultOpenPort(syncStateDir = stateDir)
            .resetSyncStateAndOpenWithPassword(older.path, GoldenVaultStaging.PASSWORD)
            .also { sessions += it }
        assertEquals(hex(uuid), reset.vaultUuidHex())
        assertFalse("the reset must delete the baseline", syncPort.status(stateDir.path, uuid).hasState)

        // Nothing left to refuse: an ordinary open of the older copy now succeeds.
        UniffiVaultOpenPort().openWithPassword(older.path, GoldenVaultStaging.PASSWORD).also { sessions += it }
        Unit
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private companion object {
        /** The one dir this process's opens may read their baseline from (the override is once per process). */
        const val STATE_DIRNAME = "rollback-test-sync-state"

        /** Stamps merge timestamps only; pinned to the golden vault's clock domain (see SyncRoundTrip). */
        val MERGE_CLOCK_MS = 2_000_000_000_000uL
    }
}
