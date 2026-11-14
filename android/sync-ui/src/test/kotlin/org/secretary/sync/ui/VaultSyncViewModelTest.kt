package org.secretary.sync.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.SyncCoordinator
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncVeto
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncModel
import org.secretary.browse.NoopReauthGate

@OptIn(ExperimentalCoroutinesApi::class)
class VaultSyncViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @BeforeEach fun setUp() = Dispatchers.setMain(dispatcher)
    @AfterEach fun tearDown() = Dispatchers.resetMain()

    private fun viewModel(outcome: SyncOutcome): VaultSyncViewModel {
        val port = ScriptedSyncPort(outcome)
        val coordinator = SyncCoordinator(port, stateDir = "s")
        val model = VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null, gate = NoopReauthGate)
        return VaultSyncViewModel(model)
    }

    @Test
    fun beginInteractiveSync_runsOnePassAndForwardsBadge() = runTest(dispatcher) {
        val port = ScriptedSyncPort(SyncOutcome.MergedClean)
        val coordinator = SyncCoordinator(port, stateDir = "s")
        val model = VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null, gate = NoopReauthGate)
        val vm = VaultSyncViewModel(model)

        vm.beginInteractiveSync()
        advanceUntilIdle()
        assertEquals(1, port.syncCalls)
        assertNull(vm.lastError.value)
        // A clean pass with no prior status leaves the badge at NeverSynced (status not refreshed).
        assertEquals(SyncBadgeState.NeverSynced, vm.badge.value)
    }

    @Test
    fun resolve_afterConflict_clearsPendingConflict() = runTest(dispatcher) {
        val veto = SyncVeto(
            recordUuidHex = "aabb", recordType = "login", tags = listOf("work"),
            fieldNames = listOf("password"), localLastModMs = 1uL, peerTombstonedAtMs = 2uL,
            peerDeviceHex = "deadbeefcafef00d",
        )
        val conflict = SyncOutcome.ConflictsPending(
            vetoes = listOf(veto), collisions = emptyList(), manifestHash = byteArrayOf(1, 2, 3),
        )
        val port = ScriptedSyncPort(syncOutcome = conflict, commitOutcome = SyncOutcome.MergedClean)
        val coordinator = SyncCoordinator(port, stateDir = "s")
        val model = VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null, gate = NoopReauthGate)
        val vm = VaultSyncViewModel(model)

        vm.beginInteractiveSync()
        advanceUntilIdle()
        assertNotNull(vm.pendingConflict.value)

        vm.resolve(listOf(SyncVetoDecision("aabb", true)))
        advanceUntilIdle()
        // The clean commit cleared the conflict.
        assertEquals(null, vm.pendingConflict.value)
        assertEquals(1, port.commitCalls)
    }

    @Test
    fun syncAtUnlock_awaitsPass_andForwardsBadge() = runTest(dispatcher) {
        val vm = viewModel(SyncOutcome.AppliedAutomatically)

        // Returns only after the silent pass settles (suspend, not fire-and-forget).
        vm.syncAtUnlock()

        // A clean silent pass leaves no error and clears review state.
        assertNull(vm.lastError.value)
        assertFalse(vm.reviewNeeded.value)
    }
}
