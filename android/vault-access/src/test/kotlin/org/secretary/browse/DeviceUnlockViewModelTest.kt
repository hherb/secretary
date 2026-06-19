package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceUnlockViewModelTest {
    private val folder = "/tmp/vault"
    private val vaultId = "00112233445566778899aabbccddeeff"

    private fun coordinator(
        slotPort: VaultDeviceSlotPort = FakeVaultDeviceSlotPort(),
        enclave: DeviceSecretEnclave = FakeDeviceSecretEnclave(),
        metadata: DeviceEnrollmentMetadataStore = FakeEnrollmentMetadataStore(),
    ) = DeviceUnlockCoordinator(slotPort, enclave, metadata)

    @Test
    fun refresh_unenrolled_whenNoSecretOrMetadata() {
        val vm = DeviceUnlockViewModel(coordinator())
        vm.refresh()
        assertEquals(DeviceUnlockState.Unenrolled, vm.state)
    }

    @Test
    fun enroll_success_setsEnrolledState() = runTest {
        val vm = DeviceUnlockViewModel(coordinator())
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertEquals(DeviceUnlockState.Enrolled, vm.state)
    }

    @Test
    fun unlock_success_emitsCredentialAndReturnsToEnrolled() = runTest {
        val vm = DeviceUnlockViewModel(coordinator())
        vm.enroll(folder, vaultId, "pw".toByteArray())
        var received: UnlockCredential.DeviceSecret? = null
        vm.unlockWithBiometrics(vaultId, "reason") { received = it }
        assertTrue(received != null)
        assertEquals(DeviceUnlockState.Enrolled, vm.state)
    }

    @Test
    fun unlock_cancelled_entersFailed_withoutEmitting() = runTest {
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.UserCancelled)
        val metadata = FakeEnrollmentMetadataStore()
        val vm = DeviceUnlockViewModel(coordinator(enclave = enclave, metadata = metadata))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        var emitted = false
        vm.unlockWithBiometrics(vaultId, "reason") { emitted = true }
        assertTrue(!emitted)
        val failed = vm.state as DeviceUnlockState.Failed
        assertSame(DeviceUnlockError.UserCancelled, failed.error)
    }

    @Test
    fun unlock_wrongVault_entersFailedMismatch_withoutTouchingEnclave() = runTest {
        // enrolled for vaultId, but unlock requests a different vault → guard fires before release.
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.Enclave("must not be called"))
        val metadata = FakeEnrollmentMetadataStore()
        val vm = DeviceUnlockViewModel(coordinator(enclave = enclave, metadata = metadata))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        vm.unlockWithBiometrics("ffffffffffffffffffffffffffffffff", "reason") {}
        assertSame(DeviceUnlockError.VaultSlotMismatch, (vm.state as DeviceUnlockState.Failed).error)
    }

    @Test
    fun enroll_failure_entersFailed() = runTest {
        val enclave = FakeDeviceSecretEnclave(storeError = DeviceUnlockError.Enclave("keystore boom"))
        val vm = DeviceUnlockViewModel(coordinator(enclave = enclave))
        vm.enroll(folder, vaultId, "pw".toByteArray())
        assertTrue(vm.state is DeviceUnlockState.Failed)
    }
}
