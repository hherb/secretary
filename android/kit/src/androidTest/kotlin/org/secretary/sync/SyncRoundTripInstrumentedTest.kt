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

    // The published golden-vault KAT password — not a real secret, so not zeroized.
    private val goldenPassword = "correct horse battery staple".toByteArray()

    // nowMs only stamps merge timestamps (`last_mod_ms`) in the commit/write path
    // (core/src/sync/commit/write.rs), which a single-device pass never reaches: the
    // asserted AppliedAutomatically fast-forward arm consumes it nowhere. Pinned to the
    // golden vault's clock domain for determinism.
    private val mergeClockMs = 2_000_000_000_000uL

    private val toClean = mutableListOf<File>()

    @After fun cleanup() = toClean.forEach { it.deleteRecursively() }

    private fun stageVault(): File =
        GoldenVaultStaging.stageWritableVault(context).also { toClean += it.parentFile!! }

    private fun stateDir(): File =
        GoldenVaultStaging.freshStateDir(context).also { toClean += it }

    @Test
    fun rawPort_statusThenSync_roundTripsThroughNativeFfi() = runBlocking {
        val vault = stageVault()
        val state = stateDir()
        val uuid = GoldenVaultStaging.goldenVaultUuid(context)
        val port = UniffiVaultSyncPort()

        val before = port.status(state.path, uuid)
        assertFalse("fresh state dir reports no sync state", before.hasState)

        // The headline proof: native load + uniffi call + DTO→domain mapping.
        // observed on-device: AppliedAutomatically (not NothingToDo) — the first sync against a
        // fresh state dir has no prior persisted clock, so the single device's current vault state
        // is applied as the initial baseline rather than being a no-op. This is an ADVANCING arm.
        val outcome = port.sync(state.path, vault.path, goldenPassword, mergeClockMs)
        assertEquals(SyncOutcome.AppliedAutomatically, outcome)

        // AppliedAutomatically advances the clock, so the first sync persists sync state.
        val after = port.status(state.path, uuid)
        assertTrue("AppliedAutomatically persists sync state", after.hasState)
    }

    @Test
    fun coordinator_overRealPort_runsAPassOnDevice() = runBlocking {
        val vault = stageVault()
        val state = stateDir()
        val coordinator = SyncCoordinator(UniffiVaultSyncPort(), state.path, vault.path)

        // Proves the assembled slice-1 (pure core) + slice-2a (adapter) stack on device.
        // First pass over a fresh state dir establishes the baseline (advancing arm),
        // matching the rawPort test's characterized AppliedAutomatically result.
        val outcome = coordinator.runPass(goldenPassword, mergeClockMs)
        assertEquals(SyncOutcome.AppliedAutomatically, outcome)
    }
}
