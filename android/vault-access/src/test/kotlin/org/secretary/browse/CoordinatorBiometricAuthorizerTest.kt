package org.secretary.browse

import kotlin.test.assertFailsWith
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Enclave that hands back the SAME array instance it last released, so the test can prove the
 *  authorizer zeroized it after the proof. */
private class CapturingEnclave(private val secret: ByteArray = ByteArray(32) { 7 }) : DeviceSecretEnclave {
    var released: ByteArray? = null
        private set
    override val isEnrolled: Boolean = true
    override suspend fun store(secret: ByteArray) {}
    override suspend fun release(reason: String): ByteArray = secret.also { released = it }
    override suspend fun clear() {}
}

class CoordinatorBiometricAuthorizerTest {
    private val vaultId = "abcd"
    private fun coordinator(
        enclave: DeviceSecretEnclave,
        enrolled: Boolean = true,
    ): DeviceUnlockCoordinator {
        val metadata = FakeEnrollmentMetadataStore()
        if (enrolled) metadata.save(DeviceEnrollment(vaultId, ByteArray(16) { 1 }))
        return DeviceUnlockCoordinator(FakeVaultDeviceSlotPort(), enclave, metadata)
    }

    @Test
    fun `isEnrolled reflects the coordinator`() {
        val auth = CoordinatorBiometricAuthorizer(coordinator(FakeDeviceSecretEnclave(), enrolled = false), vaultId)
        assertFalse(auth.isEnrolled)
    }

    @Test
    fun `authorize releases the secret and zeroizes it`() = runTest {
        val enclave = CapturingEnclave()
        val auth = CoordinatorBiometricAuthorizer(coordinator(enclave), vaultId)
        auth.authorize("Confirm saving this entry")
        // The released array exists and was wiped after the proof.
        assertArrayEquals(ByteArray(32), enclave.released)
    }

    @Test
    fun `a release failure propagates as DeviceUnlockError`() = runTest {
        val enclave = FakeDeviceSecretEnclave(releaseError = DeviceUnlockError.UserCancelled)
        // FakeDeviceSecretEnclave.isEnrolled is false until store(); store a secret first so the
        // coordinator gets past its enrollment guard and reaches release().
        enclave.store(ByteArray(32) { 2 })
        val auth = CoordinatorBiometricAuthorizer(coordinator(enclave), vaultId)
        assertFailsWith<DeviceUnlockError.UserCancelled> { auth.authorize("write") }
    }

    @Test
    fun `authorize on a wrong-vault enrollment throws VaultSlotMismatch (guard before prompt)`() = runTest {
        val enclave = CapturingEnclave()
        val auth = CoordinatorBiometricAuthorizer(coordinator(enclave), vaultId = " ffff ".trim())
        // coordinator was built for vaultId="abcd"; authorizer asks for "ffff" → mismatch, no release.
        assertFailsWith<DeviceUnlockError.VaultSlotMismatch> { auth.authorize("write") }
        assertTrue(enclave.released == null)
    }
}
