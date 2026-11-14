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
import org.secretary.browse.UniffiVaultSession
import java.io.File

/**
 * The first on-device exercise of the native sync surface: a real libsecretary_ffi_uniffi.so
 * load + uniffi marshalling + SyncOutcome/SyncStatus mapping, round-tripped against a writable
 * copy of golden_vault_001 on the arm64 emulator. Host tests (with fakes) cannot touch any of this.
 *
 * The class also exercises the SyncCoordinator wrapper over the real port — the slice-1 + slice-2a
 * assembled stack — not just the raw port.
 *
 * Scope: this proves the native surface works end-to-end (load → marshal → outcome arm → state
 * persistence), asserting the SyncOutcome and hasState only. Record-level content fidelity through
 * a merge is not asserted here — a single-device golden vault can only fast-forward, never merge
 * or veto; content round-trip + the ConflictsPending/commitDecisions path need a seeded concurrent
 * state and are future coverage.
 */
@RunWith(AndroidJUnit4::class)
class SyncRoundTripInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    // nowMs only stamps merge timestamps (`last_mod_ms`) in the commit/write path
    // (core/src/sync/commit/write.rs). Pinned to the golden vault's clock domain for determinism.
    private val mergeClockMs = 2_000_000_000_000uL

    private val toClean = mutableListOf<File>()
    private val sessions = mutableListOf<UniffiVaultSession>()

    @After fun cleanup() {
        sessions.forEach { it.wipe() }
        toClean.forEach { it.deleteRecursively() }
    }

    private fun stageVault(): File =
        GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }

    private fun stateDir(): File =
        GoldenVaultStaging.freshStateDir(context).also { toClean += it }

    private fun session(folder: File): UniffiVaultSession =
        GoldenVaultStaging.openSession(folder).also { sessions += it }

    @Test
    fun rawPort_statusThenSync_roundTripsThroughNativeFfi() = runBlocking {
        val vault = stageVault()
        val state = stateDir()
        val uuid = GoldenVaultStaging.goldenVaultUuid(context)
        val port = UniffiVaultSyncPort(session(vault))

        val before = port.status(state.path, uuid)
        assertFalse("fresh state dir reports no sync state", before.hasState)

        // The headline proof: native load + uniffi call + DTO→domain mapping. The first sync
        // against a fresh state dir has no prior persisted clock, so the vault's current state is
        // applied as the initial baseline: an ADVANCING arm.
        val outcome = port.sync(state.path, mergeClockMs)
        assertEquals(SyncOutcome.AppliedAutomatically, outcome)

        // AppliedAutomatically advances the clock, so the first sync persists sync state.
        val after = port.status(state.path, uuid)
        assertTrue("AppliedAutomatically persists sync state", after.hasState)
    }

    @Test
    fun coordinator_overRealPort_runsAPassOnDevice() = runBlocking {
        val vault = stageVault()
        val state = stateDir()
        val coordinator = SyncCoordinator(UniffiVaultSyncPort(session(vault)), state.path)

        val outcome = coordinator.runPass(mergeClockMs)
        assertEquals(SyncOutcome.AppliedAutomatically, outcome)
    }

    /**
     * #733 acceptance, and the #730 regression on device: two working copies branch from the
     * golden vault and each adds its own block, so their clocks are concurrent but no block
     * diverges. Seeding the state from copy B and syncing copy A takes the SilentMerge arm. It
     * must commit its merge (#730): the repeat pass has nothing to do, and the session's next
     * write succeeds. Before #730 the repeat pass was RollbackRejected.
     */
    @Test
    fun silentMerge_thenRepeatPass_thenWrite_onDevice() = runBlocking {
        val vaultA = stageVault()
        val vaultB = stageVault()
        val state = stateDir()
        val sessionA = session(vaultA)
        val sessionB = session(vaultB)
        sessionA.createBlock("only on A")
        sessionB.createBlock("only on B")

        assertEquals(SyncOutcome.AppliedAutomatically, UniffiVaultSyncPort(sessionB).sync(state.path, mergeClockMs))

        val portA = UniffiVaultSyncPort(sessionA)
        assertEquals(SyncOutcome.SilentMerge, portA.sync(state.path, mergeClockMs))
        assertEquals(SyncOutcome.NothingToDo, portA.sync(state.path, mergeClockMs))
        sessionA.createBlock("written after the merge")
        Unit
    }
}
