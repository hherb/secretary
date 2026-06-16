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
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.secretary.sync.SyncBadgeState
import org.secretary.sync.SyncCoordinator
import org.secretary.sync.SyncOutcome
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
        val vm = viewModel(SyncOutcome.MergedClean)
        vm.beginInteractiveSync()
        vm.submitPassword("pw".toByteArray())
        advanceUntilIdle()
        assertFalse(vm.passwordSheetVisible.value)
        // A clean pass with no prior status leaves the badge at NeverSynced (status not refreshed).
        assertEquals(SyncBadgeState.NeverSynced, vm.badge.value)
    }

    @Test
    fun dismissPasswordSheet_hidesIt() {
        val vm = viewModel(SyncOutcome.MergedClean)
        vm.beginInteractiveSync()
        vm.dismissPasswordSheet()
        assertFalse(vm.passwordSheetVisible.value)
    }
}
