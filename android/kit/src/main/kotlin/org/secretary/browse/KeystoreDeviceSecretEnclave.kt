package org.secretary.browse

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The biometric gate: takes an initialized [Cipher] (and a [reason] to show) and returns it
 *  authorized (in production, after a BiometricPrompt(CryptoObject) auth). The :kit enclave routes
 *  both store (one enroll prompt) and release through it; the real impl lives in :app. */
typealias BiometricGate = suspend (cipher: Cipher, reason: String) -> Cipher

/** Keystore key security parameters. PRODUCTION binds the key to a strong biometric per use and
 *  prefers StrongBox; TEST_NO_AUTH is for headless instrumented mechanics tests only. */
data class KeystoreKeyConfig(val requireAuth: Boolean, val strongBox: Boolean) {
    companion object {
        val PRODUCTION = KeystoreKeyConfig(requireAuth = true, strongBox = true)
        val TEST_NO_AUTH = KeystoreKeyConfig(requireAuth = false, strongBox = false)
    }
}

/**
 * Real [DeviceSecretEnclave]: an AES-256-GCM key in the AndroidKeyStore wraps the 32-byte device
 * secret; the ciphertext+IV blob lives under [dir]. With [KeystoreKeyConfig.PRODUCTION] the key is
 * bound to a strong biometric for every use, so [store] (at enroll) and [release] (at each unlock)
 * each route their Cipher through [gate], which presents a BiometricPrompt. Android cannot scope
 * auth to decryption only for a symmetric key, hence the one enroll-time prompt.
 *
 * Mirror of iOS `SecureEnclaveDeviceSecretStore`. Keystore needs a device → instrumented-test-only.
 * [isEnrolled] checks ONLY the blob (never the key) so it never risks a prompt (iOS parity).
 */
class KeystoreDeviceSecretEnclave(
    private val dir: File,
    private val gate: BiometricGate,
    private val keyAlias: String = DEFAULT_ALIAS,
    private val keyConfig: KeystoreKeyConfig = KeystoreKeyConfig.PRODUCTION,
) : DeviceSecretEnclave {

    private val blobFile: File get() = File(dir, BLOB_NAME)

    override val isEnrolled: Boolean get() = blobFile.exists()

    override suspend fun store(secret: ByteArray) {
        val key = ensureKey()
        dir.mkdirs()
        val tmp = File(dir, "$BLOB_NAME.tmp")
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val authorized = gate(cipher, STORE_REASON)
            val ct = authorized.doFinal(secret)
            val iv = authorized.iv
            val out = ByteBuffer.allocate(1 + iv.size + ct.size)
                .put(iv.size.toByte()).put(iv).put(ct).array()
            tmp.writeBytes(out)
            check(tmp.renameTo(blobFile)) { "atomic rename of secret blob failed" }
        } catch (e: GeneralSecurityException) {
            tmp.delete()
            throw DeviceUnlockError.Enclave(e.javaClass.simpleName)
        } catch (e: java.io.IOException) {
            tmp.delete()
            throw DeviceUnlockError.Enclave(e.javaClass.simpleName)
        } catch (e: IllegalStateException) {
            tmp.delete()
            throw DeviceUnlockError.Enclave(e.javaClass.simpleName)
        }
    }

    override suspend fun release(reason: String): ByteArray {
        val blob = try {
            blobFile.takeIf { it.exists() }?.readBytes()
        } catch (e: java.io.IOException) {
            throw DeviceUnlockError.Enclave(e.javaClass.simpleName)
        } ?: throw DeviceUnlockError.NotEnrolled
        if (blob.isEmpty()) throw DeviceUnlockError.WrappedSecretCorrupt
        val ivLen = blob[0].toInt() and 0xFF
        if (blob.size < 1 + ivLen + 1) throw DeviceUnlockError.WrappedSecretCorrupt
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ct = blob.copyOfRange(1 + ivLen, blob.size)
        val key = loadKey() ?: throw DeviceUnlockError.NotEnrolled
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            val authorized = gate(cipher, reason)
            authorized.doFinal(ct)
        } catch (e: AEADBadTagException) {
            throw DeviceUnlockError.WrappedSecretCorrupt
        } catch (e: GeneralSecurityException) {
            // Covers KeyPermanentlyInvalidatedException (post-biometric-re-enrollment) and
            // other InvalidKeyException subclasses. Class name only — never log key/secret bytes.
            throw DeviceUnlockError.Enclave(e.javaClass.simpleName)
        }
    }

    override suspend fun clear() {
        // Best-effort BOTH deletes before surfacing failure (revocation must make maximal progress).
        val blobDeleted = !blobFile.exists() || blobFile.delete()
        val keyDeleted = runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(keyAlias)
        }.isSuccess
        check(blobDeleted) { "failed to delete secret blob" }
        check(keyDeleted) { "failed to delete Keystore entry" }
    }

    private fun loadKey(): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(keyAlias, null) as? SecretKey
    }

    private fun ensureKey(): SecretKey {
        loadKey()?.let { return it }
        return generateKey(strongBox = keyConfig.strongBox)
    }

    private fun generateKey(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (keyConfig.requireAuth) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // API 30+: require a strong biometric for every use (timeout 0 = per-use auth).
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            // API 26-29: setUserAuthenticationRequired(true) alone yields per-use CryptoObject auth.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true)
            }
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        return try {
            generator.init(builder.build())
            generator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            // Emulator / devices without StrongBox: retry without it.
            generateKey(strongBox = false)
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val DEFAULT_ALIAS = "org.secretary.deviceSecret.aesKey"
        const val BLOB_NAME = "blob"
        const val GCM_TAG_BITS = 128
        const val STORE_REASON = "Enable biometric unlock for this device"
    }
}
