package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceSettingsViewModelTest {
    private val folder = "/tmp/vault"
    private val vaultId = "00112233445566778899aabbccddeeff"

    private fun coordinator(
        slotPort: VaultDeviceSlotPort = FakeVaultDeviceSlotPort(),
        enclave: DeviceSecretEnclave = FakeDeviceSecretEnclave(),
        metadata: DeviceEnrollmentMetadataStore = FakeEnrollmentMetadataStore(),
    ) = DeviceUnlockCoordinator(slotPort, enclave, metadata)

    @Test
    fun refresh_reportsUnenrolled_whenNothingStored() {
        val vm = DeviceSettingsViewModel(coordinator())
        vm.refresh()
        assertFalse(vm.state.enrolled)
        assertNull(vm.state.error)
    }

    @Test
    fun enroll_success_marksEnrolled_clearsError() = runTest {
        val vm = DeviceSettingsViewModel(coordinator())
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertTrue(vm.state.enrolled)
        assertFalse(vm.state.working)
        assertNull(vm.state.error)
    }

    @Test
    fun refresh_reportsEnrolled_afterEnroll() = runTest {
        val coord = coordinator()
        val vm = DeviceSettingsViewModel(coord)
        vm.enroll(folder, vaultId, "pw".toByteArray())
        vm.refresh()
        assertTrue(vm.state.enrolled)
    }

    @Test
    fun enroll_wrongPassword_keepsUnenrolled_setsConflatedError() = runTest {
        // addDeviceSlot fails the same way a wrong re-prompted password does.
        val slot = FakeVaultDeviceSlotPort(addError = VaultBrowseError.WrongPasswordOrCorrupt)
        val vm = DeviceSettingsViewModel(coordinator(slotPort = slot))
        vm.enroll(folder, vaultId, "wrong".toByteArray())
        assertFalse(vm.state.enrolled)
        assertEquals(ENROLL_FAILED_MESSAGE, vm.state.error)
    }

    @Test
    fun enroll_noBiometric_setsBiometricUnavailableError() = runTest {
        val enclave = FakeDeviceSecretEnclave(storeError = DeviceUnlockError.BiometryNotEnrolled)
        val vm = DeviceSettingsViewModel(coordinator(enclave = enclave))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertFalse(vm.state.enrolled)
        assertEquals(ENROLL_BIOMETRIC_UNAVAILABLE_MESSAGE, vm.state.error)
    }

    @Test
    fun disenroll_success_marksUnenrolled() = runTest {
        val coord = coordinator()
        val vm = DeviceSettingsViewModel(coord)
        vm.enroll(folder, vaultId, "pw".toByteArray())
        vm.disenroll(folder)
        assertFalse(vm.state.enrolled)
        assertNull(vm.state.error)
    }

    @Test
    fun disenroll_whenNotEnrolled_isIdempotentSuccess() = runTest {
        val vm = DeviceSettingsViewModel(coordinator())
        vm.disenroll(folder)
        assertFalse(vm.state.enrolled)
        assertNull(vm.state.error)
    }
}
