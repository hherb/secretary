package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class FileDeviceEnrollmentMetadataStoreTest {
    private val uuid = ByteArray(16) { it.toByte() }
    private val vaultId = "00112233445566778899aabbccddeeff"

    @Test
    fun load_returnsNull_whenAbsent(@TempDir dir: File) {
        assertNull(FileDeviceEnrollmentMetadataStore(dir).load())
    }

    @Test
    fun saveThenLoad_roundTrips(@TempDir dir: File) {
        val store = FileDeviceEnrollmentMetadataStore(dir)
        store.save(DeviceEnrollment(vaultId, uuid))
        val loaded = store.load()!!
        assertEquals(vaultId, loaded.vaultId)
        assertArrayEquals(uuid, loaded.deviceUuid)
    }

    @Test
    fun clear_removesEnrollment(@TempDir dir: File) {
        val store = FileDeviceEnrollmentMetadataStore(dir)
        store.save(DeviceEnrollment(vaultId, uuid))
        store.clear()
        assertNull(store.load())
    }

    @Test
    fun load_returnsNull_whenMalformed(@TempDir dir: File) {
        File(dir, "enrollment").writeBytes(byteArrayOf(1, 2, 3))
        assertNull(FileDeviceEnrollmentMetadataStore(dir).load())
    }

    @Test
    fun save_overwritesPrevious(@TempDir dir: File) {
        val store = FileDeviceEnrollmentMetadataStore(dir)
        store.save(DeviceEnrollment("aaaa", ByteArray(16) { 9 }))
        store.save(DeviceEnrollment(vaultId, uuid))
        val loaded = store.load()!!
        assertEquals(vaultId, loaded.vaultId)
        assertArrayEquals(uuid, loaded.deviceUuid)
    }
}
