package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceUnlockCoordinatorTest {
    private val uuid = ByteArray(16) { 5 }
    private val secret = ByteArray(32) { 6 }

    @Test
    fun `enroll mints, stores a copy, saves metadata, and zeroizes the slot secret`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave()
        val metadata = FakeEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        coordinator.enroll("/vault", "golden", byteArrayOf(0))

        assertTrue(enclave.isEnrolled, "enclave holds the secret")
        assertArrayEquals(secret, enclave.release("x"), "enclave kept its OWN copy of the real bytes")
        assertArrayEquals(ByteArray(32), slot.lastIssuedSecret, "coordinator zeroized the slot's secret array")
        assertEquals("golden", metadata.load()!!.vaultId)
        assertArrayEquals(uuid, metadata.load()!!.deviceUuid)
        assertTrue(coordinator.isEnrolled)
    }

    @Test
    fun `enroll rolls back the slot when the enclave store fails`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave(storeError = DeviceUnlockError.Enclave("boom"))
        val metadata = FakeEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        assertThrows(DeviceUnlockError.Enclave::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.enroll("/vault", "golden", byteArrayOf(0)) }
        }
        assertArrayEquals(ByteArray(32), slot.lastIssuedSecret, "slot secret zeroized even on the failure path")
        assertEquals(1, slot.removeCalls.size, "the just-minted slot was removed")
        assertArrayEquals(uuid, slot.removeCalls[0])
        assertFalse(coordinator.isEnrolled, "metadata was never saved")
    }

    @Test
    fun `enroll rolls back enclave and slot when metadata save fails, rethrowing the original error`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave()
        val metadata = FakeEnrollmentMetadataStore(saveError = IllegalStateException("disk full"))
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        val thrown = assertThrows(IllegalStateException::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.enroll("/vault", "golden", byteArrayOf(0)) }
        }
        assertEquals("disk full", thrown.message)
        assertArrayEquals(ByteArray(32), slot.lastIssuedSecret, "slot secret zeroized even on the failure path")
        assertFalse(enclave.isEnrolled, "enclave was cleared")
        assertEquals(1, slot.removeCalls.size, "the slot was removed")
        assertFalse(coordinator.isEnrolled)
    }

    @Test
    fun `unlock throws NotEnrolled and never touches the enclave when no metadata`() = runTest {
        val enclave = FakeDeviceSecretEnclave(releaseError = IllegalStateException("must not be called"))
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, FakeEnrollmentMetadataStore())
        assertThrows(DeviceUnlockError.NotEnrolled::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.unlock("golden", "why") }
        }
    }

    @Test
    fun `unlock throws VaultSlotMismatch when the enrolled vaultId differs, before release`() = runTest {
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("OTHER", uuid)) }
        val enclave = FakeDeviceSecretEnclave(releaseError = IllegalStateException("must not be called"))
        enclave.store(secret) // enclave is enrolled, but the vaultId guard must fire first
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
        assertThrows(DeviceUnlockError.VaultSlotMismatch::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.unlock("golden", "why") }
        }
    }

    @Test
    fun `unlock returns a DeviceSecret credential carrying the released secret and slot uuid`() = runTest {
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("golden", uuid)) }
        val enclave = FakeDeviceSecretEnclave().apply { store(secret) }
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
        val cred = coordinator.unlock("golden", "why")
        assertArrayEquals(uuid, cred.deviceUuid)
        assertArrayEquals(secret, cred.secret)
    }

    @Test
    fun `unlock propagates a biometric error from the enclave after the guards pass`() = runTest {
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("golden", uuid)) }
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.UserCancelled)
        enclave.store(secret)
        val coordinator = DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
        assertThrows(DeviceUnlockError.UserCancelled::class.java) {
            kotlinx.coroutines.runBlocking { coordinator.unlock("golden", "why") }
        }
    }

    @Test
    fun `disenroll removes the slot and clears enclave and metadata`() = runTest {
        val slot = FakeVaultDeviceSlotPort(deviceUuid = uuid, issuedSecret = secret)
        val enclave = FakeDeviceSecretEnclave()
        val metadata = FakeEnrollmentMetadataStore()
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)
        coordinator.enroll("/vault", "golden", byteArrayOf(0))

        coordinator.disenroll("/vault")

        assertEquals(1, slot.removeCalls.size)
        assertArrayEquals(uuid, slot.removeCalls[0])
        assertFalse(enclave.isEnrolled)
        assertFalse(coordinator.isEnrolled)
    }

    @Test
    fun `disenroll tolerates an already-gone slot`() = runTest {
        val slot = FakeVaultDeviceSlotPort(
            deviceUuid = uuid, issuedSecret = secret,
            removeError = VaultBrowseError.DeviceSlotNotFound,
        )
        val enclave = FakeDeviceSecretEnclave().apply { store(secret) }
        val metadata = FakeEnrollmentMetadataStore().apply { save(DeviceEnrollment("golden", uuid)) }
        val coordinator = DeviceUnlockCoordinator(slot, enclave, metadata)

        coordinator.disenroll("/vault") // must NOT throw

        assertFalse(enclave.isEnrolled)
        assertFalse(coordinator.isEnrolled)
    }

    @Test
    fun `disenroll on a never-enrolled coordinator is a no-op`() = runTest {
        val slot = FakeVaultDeviceSlotPort()
        val coordinator = DeviceUnlockCoordinator(slot, FakeDeviceSecretEnclave(), FakeEnrollmentMetadataStore())
        coordinator.disenroll("/vault")
        assertEquals(0, slot.removeCalls.size, "no metadata → nothing to remove")
        assertFalse(coordinator.isEnrolled)
    }
}
