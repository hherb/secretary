package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DeviceUnlockFakesTest {
    @Test
    fun `enclave store then release round-trips a COPY and clear empties it`() = runTest {
        val enclave = FakeDeviceSecretEnclave()
        assertFalse(enclave.isEnrolled)
        val source = byteArrayOf(1, 2, 3, 4)
        enclave.store(source)
        source.fill(0) // caller zeroizes its array; the enclave must hold its own copy
        assertTrue(enclave.isEnrolled)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), enclave.release("why"))
        enclave.clear()
        assertFalse(enclave.isEnrolled)
    }

    @Test
    fun `slot port records adds and removes and supports error injection`() = runTest {
        val port = FakeVaultDeviceSlotPort(
            deviceUuid = ByteArray(16) { 7 },
            issuedSecret = ByteArray(32) { 9 },
        )
        val slot = port.addDeviceSlot("/vault", byteArrayOf(0))
        assertArrayEquals(ByteArray(16) { 7 }, slot.deviceUuid)
        assertEquals(1, port.addCalls.size)
        port.removeDeviceSlot("/vault", slot.deviceUuid)
        assertEquals(1, port.removeCalls.size)
        assertNotNull(port.lastIssuedSecret)
        assertSame(slot.secret, port.lastIssuedSecret) // alias: a later coordinator test asserts this array was zeroized
    }

    @Test
    fun `metadata store loads what it saved and clears`() {
        val store = FakeEnrollmentMetadataStore()
        assertNull(store.load())
        store.save(DeviceEnrollment("golden", ByteArray(16) { 3 }))
        assertEquals("golden", store.load()!!.vaultId)
        store.clear()
        assertNull(store.load())
    }

    @Test
    fun `slot port throws the injected add error`() = runTest {
        val port = FakeVaultDeviceSlotPort(addError = VaultBrowseError.FolderInvalid("nope"))
        assertThrows(VaultBrowseError.FolderInvalid::class.java) {
            kotlinx.coroutines.runBlocking { port.addDeviceSlot("/vault", byteArrayOf(0)) }
        }
    }
}
