package org.secretary.app

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import org.secretary.browse.BiometricGate
import org.secretary.browse.DeviceUnlockError
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The real [BiometricGate] for `:app`: presents a strong-biometric [BiometricPrompt] bound to the
 * enclave's [Cipher] via [BiometricPrompt.CryptoObject], and resumes the suspend fn with the
 * authorized cipher (the one inside the auth result, NOT the input — only it is unlocked). Errors map
 * via [mapBiometricError]; a non-match (`onAuthenticationFailed`) is advisory and does NOT resume —
 * the prompt stays up until success, a hard error, or cancel.
 *
 * Must run on the main thread (BiometricPrompt requirement) — call from a main-dispatched coroutine.
 */
fun biometricPromptGate(activity: FragmentActivity, title: String): BiometricGate =
    { cipher: Cipher, reason: String ->
        suspendCancellableCoroutine { cont ->
            val executor = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authorized = result.cryptoObject?.cipher
                        if (authorized != null) {
                            cont.resume(authorized)
                        } else {
                            cont.resumeWithException(DeviceUnlockError.Enclave("no cipher in auth result"))
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (cont.isActive) cont.resumeWithException(mapBiometricError(errorCode))
                    }
                    // onAuthenticationFailed (single non-match) is intentionally not handled: the
                    // prompt remains until success / a terminal error / cancel.
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(reason)
                .setNegativeButtonText("Use password")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
    }
