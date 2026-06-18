package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class UnlockCredentialTest {
    @Test
    fun `a password credential opens via openWithPassword with the password bytes`() = runTest {
        val port = FakeVaultOpenPort()
        openWithCredential(port, "/vault", UnlockCredential.Password(byteArrayOf(1, 2, 3)))
        assertEquals(1, port.openedWithPassword.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), port.openedWithPassword[0])
        assertTrue(port.openedWithRecovery.isEmpty(), "recovery path must not fire for a password credential")
    }

    @Test
    fun `a recovery credential opens via openWithRecovery with the phrase bytes`() = runTest {
        val port = FakeVaultOpenPort()
        openWithCredential(port, "/vault", UnlockCredential.Recovery(byteArrayOf(7, 7, 9)))
        assertEquals(1, port.openedWithRecovery.size)
        assertArrayEquals(byteArrayOf(7, 7, 9), port.openedWithRecovery[0])
        assertTrue(port.openedWithPassword.isEmpty(), "password path must not fire for a recovery credential")
    }

    @Test
    fun `a device-secret credential opens via openWithDeviceSecret with the uuid and secret bytes`() = runTest {
        val port = FakeVaultOpenPort()
        val uuid = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
        val secret = ByteArray(32) { it.toByte() }
        openWithCredential(port, "/vault", UnlockCredential.DeviceSecret(uuid, secret))
        assertEquals(1, port.openedWithDeviceSecret.size)
        val (openedUuid, openedSecret) = port.openedWithDeviceSecret[0]
        assertArrayEquals(uuid, openedUuid)
        assertArrayEquals(secret, openedSecret)
        assertTrue(port.openedWithPassword.isEmpty(), "password path must not fire for a device-secret credential")
        assertTrue(port.openedWithRecovery.isEmpty(), "recovery path must not fire for a device-secret credential")
    }

    @Test
    fun `secret exposes the underlying bytes for both arms`() {
        assertArrayEquals(byteArrayOf(4, 5), UnlockCredential.Password(byteArrayOf(4, 5)).secret)
        assertArrayEquals(byteArrayOf(6), UnlockCredential.Recovery(byteArrayOf(6)).secret)
    }
}
