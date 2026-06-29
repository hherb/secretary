package org.secretary.app

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import org.secretary.browse.DeviceEnrollment
import org.secretary.browse.DeviceEnrollmentMetadataStore
import org.secretary.browse.DeviceSecretEnclave
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.EnrolledSlot
import org.secretary.browse.VaultDeviceSlotPort

private class FakeSlotPort(var failAdd: Boolean = false) : VaultDeviceSlotPort {
    val added = mutableListOf<ByteArray>()
    val removed = mutableListOf<ByteArray>()
    override suspend fun addDeviceSlot(vaultFolder: String, password: ByteArray): EnrolledSlot {
        if (failAdd) throw RuntimeException("addDeviceSlot failed")
        val uuid = ByteArray(16) { 0x11 }
        added += uuid
        return EnrolledSlot(uuid, ByteArray(32) { 0x22 })
    }
    override suspend fun removeDeviceSlot(vaultFolder: String, deviceUuid: ByteArray) { removed += deviceUuid }
}

private class FakeEnclave : DeviceSecretEnclave {
    private var blob: ByteArray? = null
    override val isEnrolled: Boolean get() = blob != null
    override suspend fun store(secret: ByteArray) { blob = secret.copyOf() }
    override suspend fun release(reason: String): ByteArray = blob!!.copyOf()
    override suspend fun clear() { blob = null }
}

private class FakeMetadata : DeviceEnrollmentMetadataStore {
    private var e: DeviceEnrollment? = null
    override fun load(): DeviceEnrollment? = e
    override fun save(enrollment: DeviceEnrollment) { e = enrollment }
    override fun clear() { e = null }
}

class CloudDeviceEnrollTest {
    private fun coordinator(slot: FakeSlotPort, enclave: FakeEnclave, meta: FakeMetadata) =
        DeviceUnlockCoordinator(slot, enclave, meta)

    @Test fun happy_path_enrolls_and_flushes() = runTest {
        val slot = FakeSlotPort(); val enclave = FakeEnclave(); val meta = FakeMetadata()
        var flushed = false
        cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = false, "/wd", "abcd", ByteArray(8) { 1 }) { flushed = true }
        assertTrue(enclave.isEnrolled)
        assertEquals("abcd", meta.load()?.vaultId)
        assertTrue(flushed)
        assertEquals(1, slot.added.size)
        assertEquals(0, slot.removed.size)
    }

    @Test fun flush_failure_rolls_back_fully() = runTest {
        val slot = FakeSlotPort(); val enclave = FakeEnclave(); val meta = FakeMetadata()
        try {
            cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = false, "/wd", "abcd", ByteArray(8) { 1 }) {
                throw RuntimeException("flush to cloud failed")
            }
            fail("expected the flush failure to propagate")
        } catch (e: RuntimeException) {
            assertEquals("flush to cloud failed", e.message)
        }
        // Full rollback: enclave cleared, metadata cleared, slot removed — no orphan enrollment.
        assertFalse(enclave.isEnrolled)
        assertNull(meta.load())
        assertEquals(1, slot.removed.size)
    }

    @Test fun already_enrolled_for_same_vault_is_a_noop_skip() = runTest {
        val slot = FakeSlotPort(); val enclave = FakeEnclave(); val meta = FakeMetadata()
        // Pre-enroll for "abcd".
        cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = false, "/wd", "abcd", ByteArray(8) { 1 }) {}
        var flushedAgain = false
        val alreadyEnrolled = enclave.isEnrolled && meta.load()?.vaultId == "abcd"
        cloudEnrollThisDevice(coordinator(slot, enclave, meta), alreadyEnrolledForThisVault = alreadyEnrolled, "/wd", "abcd", ByteArray(8) { 1 }) { flushedAgain = true }
        // No second slot minted, no second flush.
        assertEquals(1, slot.added.size)
        assertFalse(flushedAgain)
    }
}
