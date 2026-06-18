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
        assertFalse(enclave.isEnrolled, "enclave was cleared")
        assertEquals(1, slot.removeCalls.size, "the slot was removed")
        assertFalse(coordinator.isEnrolled)
    }
}
