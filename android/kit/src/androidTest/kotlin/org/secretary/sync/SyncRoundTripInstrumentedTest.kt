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
import org.secretary.browse.hexOfBytes
import uniffi.secretary.syncStatus
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
 * persistence), asserting the SyncOutcome and hasState only. A single golden vault can only
 * fast-forward; [silentMerge_thenRepeatPass_thenWrite_onDevice] stages two working copies to reach
 * the SilentMerge arm (#730). Record-level content fidelity through a merge and the
 * ConflictsPending/commitDecisions path are not covered here (see
 * TwoWorkingCopiesConflictInstrumentedTest for the conflict surface).
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

    private fun session(folder: File, device: ByteArray = GoldenVaultStaging.randomDeviceUuid()): UniffiVaultSession =
        GoldenVaultStaging.openSession(folder, device).also { sessions += it }

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

    /**
     * #749: the SilentMerge ticks THIS session's device UUID, the one its writes stamp
     * (`syncThroughSession` passes `syncDeviceUuid()`). Copy A writes once (A at 1), then merges
     * (A at 2). A wrong UUID would leave A at 1 and tick some other entry. The clock is read from
     * the saved sync state, which the bridge sets to the clock it wrote; no FFI reads the disk
     * clock. `a_silent_merge_writes_a_manifest_carrying_the_local_clock` pins saved == disk on the
     * password entry point, and this session entry point shares its `run_locked_pass` save.
     */
    @Test
    fun silentMerge_ticksTheSessionsOwnDeviceUuid_onDevice() = runBlocking {
        val vaultA = stageVault()
        val vaultB = stageVault()
        val state = stateDir()
        val deviceA = GoldenVaultStaging.randomDeviceUuid()
        val sessionA = session(vaultA, deviceA)
        val sessionB = session(vaultB)
        sessionA.createBlock("only on A")
        sessionB.createBlock("only on B")
        assertEquals(SyncOutcome.AppliedAutomatically, UniffiVaultSyncPort(sessionB).sync(state.path, mergeClockMs))

        assertEquals(SyncOutcome.SilentMerge, UniffiVaultSyncPort(sessionA).sync(state.path, mergeClockMs))

        val clocks = syncStatus(state.path, GoldenVaultStaging.goldenVaultUuid(context)).deviceClocks
        val counterA = clocks.single { it.deviceUuidHex == hexOfBytes(deviceA) }.counter
        assertEquals("A's one write plus the merge tick, in $clocks", A_WRITES + MERGE_TICK, counterA)
    }

    private companion object {
        const val A_WRITES = 1uL
        const val MERGE_TICK = 1uL
    }
}
