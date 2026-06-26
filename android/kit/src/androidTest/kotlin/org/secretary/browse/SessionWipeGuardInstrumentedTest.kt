package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.GoldenVaultStaging
import java.io.File

/**
 * #252: a [UniffiVaultSession]'s read-only methods must stay safe after [wipe]. The vault
 * UUID is immutable, so [vaultUuidHex] snapshots it at construction and keeps returning it
 * post-wipe — pre-fix it re-read the zeroized manifest handle and got the bridge's all-zero
 * default (`00…00`), a silently-wrong UUID. [blockSummaries] exposes no blocks after wipe;
 * the bridge already returns an empty slice for a wiped handle, so this pins the session-layer
 * `wiped` guard that makes the contract explicit (matching the already-guarded `readBlock`/write
 * paths). Real native FFI: host tests cannot exercise the uniffi handle cascade. Mirror of iOS
 * `SessionWipeGuardIntegrationTests`.
 */
@RunWith(AndroidJUnit4::class)
class SessionWipeGuardInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val goldenPassword = "correct horse battery staple".toByteArray()
    private val toClean = mutableListOf<File>()

    @After fun cleanup() = toClean.forEach { it.deleteRecursively() }

    private fun stageVault(): File =
        GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }

    @Test
    fun vaultUuidHexSurvivesWipe() = runBlocking {
        val vault = stageVault()
        val session = uniffiVaultOpenPort().openWithPassword(vault.path, goldenPassword)
        val hexBefore = session.vaultUuidHex()
        // The snapshot must equal the pinned vault UUID (a real value, not the all-zero default).
        assertEquals(
            "vaultUuidHex must be the pinned golden vault UUID",
            hexOfBytes(GoldenVaultStaging.goldenVaultUuid(context)), hexBefore,
        )
        assertNotEquals("sanity: the golden vault's UUID is not all-zero", "0".repeat(32), hexBefore)
        session.wipe()
        assertEquals(
            "vaultUuidHex must survive wipe (immutable, snapshotted at construction)",
            hexBefore, session.vaultUuidHex(),
        )
    }

    @Test
    fun blockSummariesAfterWipeIsEmpty() = runBlocking {
        val vault = stageVault()
        val session = uniffiVaultOpenPort().openWithPassword(vault.path, goldenPassword)
        assertTrue("sanity: the golden vault has ≥1 block", session.blockSummaries().isNotEmpty())
        session.wipe()
        assertTrue("a wiped session must expose no blocks", session.blockSummaries().isEmpty())
    }
}
