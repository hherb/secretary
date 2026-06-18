package org.secretary.browse

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher

/**
 * Instrumented round-trip of the REAL Keystore-backed enclave, using the TEST_NO_AUTH key config so
 * the AES/GCM wrap/unwrap runs headlessly (an auth-required key would need a live BiometricPrompt).
 * The real auth-required PRODUCTION config is proven by the manual adb-emu-finger walking skeleton.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreDeviceSecretEnclaveTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dirs = mutableListOf<File>()
    private val passthrough: BiometricGate = { cipher: Cipher, _: String -> cipher }

    private fun freshEnclave(): KeystoreDeviceSecretEnclave {
        val dir = File(context.noBackupFilesDir, "ds-test-${System.nanoTime()}").apply { mkdirs() }
        dirs += dir
        return KeystoreDeviceSecretEnclave(
            dir = dir,
            gate = passthrough,
            keyAlias = "org.secretary.test.deviceSecret.${System.nanoTime()}",
            keyConfig = KeystoreKeyConfig.TEST_NO_AUTH,
        )
    }

    @After fun cleanup() = dirs.forEach { it.deleteRecursively() }

    @Test
    fun storeThenRelease_roundTrips() = runBlocking {
        val enclave = freshEnclave()
        val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
        assertFalse(enclave.isEnrolled)
        enclave.store(secret.copyOf())
        assertTrue(enclave.isEnrolled)
        val released = enclave.release("test")
        assertArrayEquals(secret, released)
        enclave.clear()
    }

    @Test
    fun clear_dropsEnrollment() = runBlocking {
        val enclave = freshEnclave()
        enclave.store(ByteArray(32).also { SecureRandom().nextBytes(it) })
        enclave.clear()
        assertFalse(enclave.isEnrolled)
    }

    @Test
    fun release_corruptBlob_throwsWrappedSecretCorrupt() = runBlocking {
        val dir = File(context.noBackupFilesDir, "ds-corrupt-${System.nanoTime()}").apply { mkdirs() }
        dirs += dir
        val alias = "org.secretary.test.deviceSecret.corrupt.${System.nanoTime()}"
        val enclave = KeystoreDeviceSecretEnclave(dir, passthrough, alias, KeystoreKeyConfig.TEST_NO_AUTH)
        enclave.store(ByteArray(32).also { SecureRandom().nextBytes(it) })
        // Flip the last ciphertext byte → GCM tag check fails.
        val blob = File(dir, "blob")
        val bytes = blob.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        blob.writeBytes(bytes)
        try {
            enclave.release("test")
            fail("expected WrappedSecretCorrupt")
        } catch (e: DeviceUnlockError.WrappedSecretCorrupt) {
            // expected
        }
        enclave.clear()
    }
}
