package org.secretary.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.secretary.browse.CoordinatorBiometricAuthorizer
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.FileDeviceEnrollmentMetadataStore
import org.secretary.browse.GraceWindowReauthGate
import org.secretary.browse.KeystoreDeviceSecretEnclave
import org.secretary.browse.UniffiVaultDeviceSlotPort
import java.io.File

@RunWith(AndroidJUnit4::class)
class WriteReauthInstrumentedTest {
    @Test
    fun graceWindowGate_isEnrolledFalse_isNoOp_whenNotEnrolled() = runBlocking {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(ctx.noBackupFilesDir, "writereauth-test").apply { mkdirs() }
        // Auto-approving gate (no biometric prompt in CI): the cipher passes through unchanged.
        // BiometricGate = suspend (Cipher, String) -> Cipher; lambda matches the typealias.
        val enclave = KeystoreDeviceSecretEnclave(dir = dir, gate = { cipher, _ -> cipher })
        val metadata = FileDeviceEnrollmentMetadataStore(dir)
        val coordinator = DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
        val authorizer = CoordinatorBiometricAuthorizer(coordinator, vaultId = "deadbeef")
        val gate = GraceWindowReauthGate(authorizer, clock = { System.currentTimeMillis() })

        // Not enrolled → the gate authorizes silently (no exception, no prompt).
        gate.authorizeWrite("smoke")
        assertTrue("not-enrolled gate must be a no-op", !authorizer.isEnrolled)

        enclave.clear(); metadata.clear()
    }
}
