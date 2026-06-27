package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import uniffi.secretary.VaultException

class UniffiVaultCreatePortTest {
    @Test
    fun `returns the phrase from a successful create`() = runTest {
        val port = UniffiVaultCreatePort(
            createFn = { _, _, _, _ -> "abandon ability".toByteArray(Charsets.UTF_8) },
        )
        val created = port.createInFolder("/tmp/vault", "pw".toByteArray(Charsets.UTF_8), "Bob")
        assertTrue("abandon ability".toByteArray(Charsets.UTF_8).contentEquals(created.phrase))
    }

    @Test
    fun `forwards utf8 path, password, display name and clock to createFn`() = runTest {
        var seenPath: ByteArray? = null
        var seenPw: ByteArray? = null
        var seenName: String? = null
        var seenClock: ULong? = null
        val port = UniffiVaultCreatePort(
            clockMs = { 1_700_000_000_000L },
            createFn = { fp, pw, dn, ts ->
                seenPath = fp; seenPw = pw; seenName = dn; seenClock = ts
                "x".toByteArray(Charsets.UTF_8)
            },
        )
        port.createInFolder("/tmp/v", byteArrayOf(1, 2, 3), "Alice")
        assertTrue("/tmp/v".toByteArray(Charsets.UTF_8).contentEquals(seenPath!!))
        assertTrue(byteArrayOf(1, 2, 3).contentEquals(seenPw!!))
        assertEquals("Alice", seenName)
        assertEquals(1_700_000_000_000UL, seenClock)
    }

    @Test
    fun `null phrase maps to CreateFailed`() = runTest {
        val port = UniffiVaultCreatePort(createFn = { _, _, _, _ -> null })
        val e = assertThrows(VaultProvisioningError.CreateFailed::class.java) {
            kotlinx.coroutines.runBlocking {
                port.createInFolder("/tmp/v", "pw".toByteArray(Charsets.UTF_8), "Bob")
            }
        }
        assertTrue(e.detail.contains("recovery phrase"))
    }

    @Test
    fun `VaultFolderNotEmpty maps to FolderNotEmpty`() = runTest {
        val port = UniffiVaultCreatePort(
            createFn = { _, _, _, _ -> throw VaultException.VaultFolderNotEmpty() },
        )
        assertThrows(VaultProvisioningError.FolderNotEmpty::class.java) {
            kotlinx.coroutines.runBlocking {
                port.createInFolder("/tmp/v", "pw".toByteArray(Charsets.UTF_8), "Bob")
            }
        }
    }

    @Test
    fun `other VaultException maps to CreateFailed`() = runTest {
        val port = UniffiVaultCreatePort(
            createFn = { _, _, _, _ -> throw VaultException.CorruptVault("bad bytes") },
        )
        val e = assertThrows(VaultProvisioningError.CreateFailed::class.java) {
            kotlinx.coroutines.runBlocking {
                port.createInFolder("/tmp/v", "pw".toByteArray(Charsets.UTF_8), "Bob")
            }
        }
        assertTrue(e.detail.isNotBlank())
    }
}
