package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.sync.GoldenVaultStaging
import java.io.File

/**
 * #251 (Android parity): navigating to another block must evict the prior block's decrypted
 * plaintext — a stale reveal closure must stop yielding plaintext. Reads the single golden
 * block twice (eviction + re-selection dedup in one). Real native FFI: host tests cannot
 * exercise the uniffi handle cascade.
 */
@RunWith(AndroidJUnit4::class)
class RevealResidencyInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val goldenPassword = "correct horse battery staple".toByteArray()
    private val toClean = mutableListOf<File>()

    @After fun cleanup() = toClean.forEach { it.deleteRecursively() }

    private fun stageVault(): File =
        GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }

    @Test
    fun navigatingAwayEvictsPriorBlockPlaintext() = runBlocking {
        val vault = stageVault()
        val session = uniffiVaultOpenPort().openWithPassword(vault.path, goldenPassword)
        try {
            val blockUuid = session.blockSummaries().first().uuid

            // First read: capture a reveal closure from this block's first field.
            val firstRecords = session.readBlock(blockUuid, false)
            val staleField = firstRecords.flatMap { it.fields }.first()
            staleField.reveal()  // sanity: reveals before navigating away

            // Navigate (re-read the only block). The fix wipes the prior BlockReadOutput,
            // cascading to the captured FieldHandle.
            session.readBlock(blockUuid, false)

            // Pre-fix: prior block still in openBlocks → still reveals. Post-fix: throws.
            assertThrows(VaultBrowseError.CorruptVault::class.java) { staleField.reveal() }
            Unit
        } finally {
            session.wipe()
        }
    }
}
