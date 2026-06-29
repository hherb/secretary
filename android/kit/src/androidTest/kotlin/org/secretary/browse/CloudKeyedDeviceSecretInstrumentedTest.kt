package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher

/**
 * Instrumented tests for keyed-per-vault [KeystoreDeviceSecretEnclave] isolation and gate
 * release — the two on-device truths host tests cannot prove.
 *
 * Both tests use [KeystoreKeyConfig.TEST_NO_AUTH] and an auto-approving [BiometricGate] so no
 * real biometric prompt appears, matching [KeystoreDeviceSecretEnclaveTest]'s pattern.
 */
@RunWith(AndroidJUnit4::class)
class CloudKeyedDeviceSecretInstrumentedTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val passthrough: BiometricGate = { cipher: Cipher, _: String -> cipher }
    private val enclaves = mutableListOf<KeystoreDeviceSecretEnclave>()
    private val dirs = mutableListOf<File>()

    private fun freshEnclave(keyAlias: String, dirTag: String): KeystoreDeviceSecretEnclave {
        val dir = File(context.noBackupFilesDir, "cloud-ds-$dirTag-${System.nanoTime()}").apply { mkdirs() }
        dirs += dir
        val enclave = KeystoreDeviceSecretEnclave(
            dir = dir,
            gate = passthrough,
            keyAlias = keyAlias,
            keyConfig = KeystoreKeyConfig.TEST_NO_AUTH,
        )
        enclaves += enclave
        return enclave
    }

    @After
    fun cleanup() = runBlocking {
        enclaves.forEach { runCatching { it.clear() } }
        dirs.forEach { it.deleteRecursively() }
    }

    /**
     * Test A — keyed-enclave isolation.
     *
     * Constructs two [KeystoreDeviceSecretEnclave] instances over two DISTINCT dirs and two DISTINCT
     * key aliases (simulating two cloud vaults). Stores a distinct 32-byte secret in each, asserts
     * each [KeystoreDeviceSecretEnclave.release] returns its OWN secret (not the other's), and
     * asserts clearing one leaves the other still enrolled with its secret intact. Proves no
     * cross-talk on the real Keystore — host tests cannot reach the real Keystore.
     */
    @Test
    fun keyedEnclaves_twoKeys_isolated() = runBlocking {
        val enclaveA = freshEnclave("secretary.devicesecret.cloud.KEYA", "vaultA")
        val enclaveB = freshEnclave("secretary.devicesecret.cloud.KEYB", "vaultB")

        val secretA = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val secretB = ByteArray(32).also { SecureRandom().nextBytes(it) }

        // Both start un-enrolled.
        assertFalse("enclaveA must start un-enrolled", enclaveA.isEnrolled)
        assertFalse("enclaveB must start un-enrolled", enclaveB.isEnrolled)

        enclaveA.store(secretA.copyOf())
        enclaveB.store(secretB.copyOf())

        assertTrue("enclaveA must be enrolled after store", enclaveA.isEnrolled)
        assertTrue("enclaveB must be enrolled after store", enclaveB.isEnrolled)

        // Each enclave releases its OWN secret.
        assertArrayEquals("enclaveA must release secretA", secretA, enclaveA.release("test-A"))
        assertArrayEquals("enclaveB must release secretB", secretB, enclaveB.release("test-B"))

        // Clearing A must not affect B.
        enclaveA.clear()
        assertFalse("enclaveA must be un-enrolled after clear", enclaveA.isEnrolled)
        assertTrue("enclaveB must still be enrolled after A is cleared", enclaveB.isEnrolled)
        assertArrayEquals("enclaveB must still release secretB after A is cleared", secretB, enclaveB.release("test-B-post-clear"))
    }

    /**
     * Test B — gate releases from a cloud-keyed enclave.
     *
     * Builds a [DeviceUnlockCoordinator] over a TEST_NO_AUTH [KeystoreDeviceSecretEnclave] at a
     * cloud-keyed dir, pre-enrolled (secret stored + matching [DeviceEnrollment] saved). Builds a
     * [GraceWindowReauthGate] over a [CoordinatorBiometricAuthorizer] with a controllable fake clock.
     *
     * Asserts:
     * - A write within [ReauthWindow.V1_DEFAULT_MS] does NOT trigger a release (silent).
     * - Advancing the fake clock past the window causes [GraceWindowReauthGate.authorizeWrite] to
     *   call [CoordinatorBiometricAuthorizer.authorize], which releases the enclave secret via the
     *   auto-approving gate — succeeds without error.
     *
     * No real vault slot is needed: the gate only proves presence by releasing the enclave secret;
     * it does not call [uniffi.secretary.openWithDeviceSecret].
     */
    @Test
    fun graceWindowGate_releases_cloudKeyedEnclave() = runBlocking {
        val vaultId = "cloud-vault-gate-test-${System.nanoTime()}"
        val dir = File(context.noBackupFilesDir, "cloud-gate-${System.nanoTime()}").apply { mkdirs() }
        dirs += dir

        val enclave = KeystoreDeviceSecretEnclave(
            dir = dir,
            gate = passthrough,
            keyAlias = "secretary.devicesecret.cloud.GATE.${System.nanoTime()}",
            keyConfig = KeystoreKeyConfig.TEST_NO_AUTH,
        )
        enclaves += enclave

        val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
        enclave.store(secret.copyOf())

        val metadata = FileDeviceEnrollmentMetadataStore(dir)
        // Mint a fake 16-byte device UUID (content irrelevant — the gate only releases the secret).
        val fakeDeviceUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
        metadata.save(DeviceEnrollment(vaultId, fakeDeviceUuid))

        val coordinator = DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
        val realAuthorizer = CoordinatorBiometricAuthorizer(coordinator, vaultId)

        // Thin counting wrapper: delegates to the real authorizer while counting calls to authorize().
        // This lets us distinguish "gate stayed silent (within window)" from "gate triggered a release
        // (past window)" — a plain no-throw assertion cannot tell the two cases apart.
        var authorizeCallCount = 0
        val countingAuthorizer = object : BiometricAuthorizer {
            override val isEnrolled: Boolean get() = realAuthorizer.isEnrolled
            override suspend fun authorize(reason: String) {
                authorizeCallCount++
                realAuthorizer.authorize(reason)
            }
        }

        // Use a mutable fake clock seeded at t=0.
        var fakeClockMs = 0L
        val gate = GraceWindowReauthGate(countingAuthorizer, clock = { fakeClockMs })

        // Seed the gate as if the user just unlocked now (t=0).
        gate.seed(fakeClockMs)

        // A write well within the grace window must be silent — gate must NOT call authorize().
        fakeClockMs = ReauthWindow.V1_DEFAULT_MS / 2  // 15 s — still inside the window
        gate.authorizeWrite("within-window")
        assertEquals("within-window write must not trigger authorize()", 0, authorizeCallCount)

        // Advance past the window boundary (elapsed >= windowMs → needs reauth).
        fakeClockMs = ReauthWindow.V1_DEFAULT_MS      // 30 s — exactly at the boundary
        // Auto-approving passthrough gate releases the secret → authorize() returns normally.
        gate.authorizeWrite("past-window")
        assertEquals("past-window write must trigger authorize() exactly once", 1, authorizeCallCount)

        metadata.clear()
    }
}
