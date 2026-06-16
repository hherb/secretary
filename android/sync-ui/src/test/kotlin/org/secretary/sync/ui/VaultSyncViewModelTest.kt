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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.SyncCoordinator
import org.secretary.sync.SyncOutcome
import org.secretary.sync.SyncVeto
import org.secretary.sync.SyncVetoDecision
import org.secretary.sync.VaultSyncModel

@OptIn(ExperimentalCoroutinesApi::class)
class VaultSyncViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @BeforeEach fun setUp() = Dispatchers.setMain(dispatcher)
    @AfterEach fun tearDown() = Dispatchers.resetMain()

    private fun viewModel(outcome: SyncOutcome): VaultSyncViewModel {
        val port = ScriptedSyncPort(outcome)
        val coordinator = SyncCoordinator(port, stateDir = "s", vaultFolder = "f")
        val model = VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null)
        return VaultSyncViewModel(model)
    }

    @Test
    fun beginInteractiveSync_showsPasswordSheet() {
        val vm = viewModel(SyncOutcome.MergedClean)
        assertFalse(vm.passwordSheetVisible.value)
        vm.beginInteractiveSync()
        assertTrue(vm.passwordSheetVisible.value)
    }

    @Test
    fun submitPassword_cleanOutcome_hidesSheetAndForwardsBadge() = runTest(dispatcher) {
        // Build with an inspectable port so we can assert password forwarding.
        val port = ScriptedSyncPort(SyncOutcome.MergedClean)
        val coordinator = SyncCoordinator(port, stateDir = "s", vaultFolder = "f")
        val model = VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null)
        val vm = VaultSyncViewModel(model)

        vm.beginInteractiveSync()
        vm.submitPassword("pw".toByteArray())
        advanceUntilIdle()
        assertFalse(vm.passwordSheetVisible.value)
        // A clean pass with no prior status leaves the badge at NeverSynced (status not refreshed).
        assertEquals(SyncBadgeState.NeverSynced, vm.badge.value)
        // Assert the password bytes reached the port.
        assertEquals(1, port.passwords.size)
        assertEquals("pw".toByteArray().toList(), port.passwords[0].toList())
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
        val coordinator = SyncCoordinator(port, stateDir = "s", vaultFolder = "f")
        val model = VaultSyncModel(coordinator, ZeroWallClock(), NoopMonitorHook, vaultUuid = null)
        val vm = VaultSyncViewModel(model)

        vm.beginInteractiveSync()
        vm.submitPassword("pw".toByteArray())
        advanceUntilIdle()
        // The interactive pass surfaced a conflict; the password sheet closed (no error).
        assertFalse(vm.passwordSheetVisible.value)
        assertNotNull(vm.pendingConflict.value)

        vm.resolve(listOf(SyncVetoDecision("aabb", true)), "pw".toByteArray())
        advanceUntilIdle()
        // The clean commit cleared the conflict.
        assertEquals(null, vm.pendingConflict.value)
    }

    @Test
    fun dismissPasswordSheet_hidesIt() {
        val vm = viewModel(SyncOutcome.MergedClean)
        vm.beginInteractiveSync()
        vm.dismissPasswordSheet()
        assertFalse(vm.passwordSheetVisible.value)
    }
}
