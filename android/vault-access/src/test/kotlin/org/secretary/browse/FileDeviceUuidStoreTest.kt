package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class FileDeviceUuidStoreTest {
    @Test
    fun `fresh call creates a 16-byte uuid and persists it`(@TempDir dir: File) {
        val store = FileDeviceUuidStore(File(dir, "devices"))
        val uuid = store.deviceUuid("abcd1234")
        assertEquals(DEVICE_UUID_BYTE_LEN, uuid.size)
        assertEquals(true, File(File(dir, "devices"), "abcd1234.dev").exists())
    }

    @Test
    fun `second call returns the same persisted uuid`(@TempDir dir: File) {
        val store = FileDeviceUuidStore(File(dir, "devices"))
        val first = store.deviceUuid("abcd1234")
        val second = store.deviceUuid("abcd1234")
        assertArrayEquals(first, second)
    }

    @Test
    fun `distinct vaults get distinct uuids`(@TempDir dir: File) {
        val store = FileDeviceUuidStore(File(dir, "devices"))
        val a = store.deviceUuid("aaaa")
        val b = store.deviceUuid("bbbb")
        // Astronomically unlikely to collide; a failure here means the vaultHex was ignored.
        assertEquals(false, a.contentEquals(b))
    }

    @Test
    fun `a corrupt-length file is rejected with a typed error`(@TempDir dir: File) {
        val devices = File(dir, "devices").apply { mkdirs() }
        File(devices, "abcd1234.dev").writeBytes(ByteArray(DEVICE_UUID_BYTE_LEN - 1))   // wrong length
        val store = FileDeviceUuidStore(devices)
        assertThrows(DeviceUuidException::class.java) { store.deviceUuid("abcd1234") }
    }

    @Test
    fun `a backing-store I-O failure folds to a typed error, not a raw IOException`(@TempDir dir: File) {
        // A regular file where the store expects its directory: mkdirs() can't create it and the
        // CREATE_NEW write hits a non-directory parent → IOException. It must surface as the typed
        // DeviceUuidException so UniffiVaultSession can map it rather than crash the write coroutine.
        val notADir = File(dir, "store").apply { writeBytes(ByteArray(1)) }
        val store = FileDeviceUuidStore(notADir)
        assertThrows(DeviceUuidException::class.java) { store.deviceUuid("abcd1234") }
    }
}
