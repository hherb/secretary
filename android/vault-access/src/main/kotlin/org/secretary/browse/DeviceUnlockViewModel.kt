package org.secretary.browse

/**
 * Pure UI state for the device-unlock surface. The screen renders from [state]; all enroll/unlock
 * decisions live here, so the full matrix is host-tested over the in-memory fakes. Mirror of iOS
 * `DeviceUnlockViewModel`. The VM never opens the vault — [unlockWithBiometrics] hands the resulting
 * credential to [onCredential] (AppRoot opens via the slice-1 pipeline).
 */
sealed interface DeviceUnlockState {
    /** No enrollment — the screen offers password/recovery (+ the "remember" checkbox). */
    data object Unenrolled : DeviceUnlockState
    /** Enrolled — the screen offers "Unlock with biometrics". */
    data object Enrolled : DeviceUnlockState
    /** A biometric prompt is in flight (disable the button). */
    data object Prompting : DeviceUnlockState
    /** A recoverable failure to surface for display; the screen returns to Enrolled/Unenrolled. */
    data class Failed(val error: DeviceUnlockError) : DeviceUnlockState
}

class DeviceUnlockViewModel(private val coordinator: DeviceUnlockCoordinator) {
    var state: DeviceUnlockState = DeviceUnlockState.Unenrolled
        private set

    /** Cheap, prompt-free recompute of Unenrolled vs Enrolled. */
    fun refresh() {
        state = if (coordinator.isEnrolled) DeviceUnlockState.Enrolled else DeviceUnlockState.Unenrolled
    }

    /** Enroll this device. [password] is caller-owned (forwarded to the coordinator, not zeroized here). */
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray) {
        state = try {
            coordinator.enroll(folder, vaultId, password)
            DeviceUnlockState.Enrolled
        } catch (e: DeviceUnlockError) {
            DeviceUnlockState.Failed(e)
        }
    }

    /**
     * Release the device secret behind the biometric prompt (inside the coordinator's enclave) and
     * hand the credential to [onCredential]. Guards (NotEnrolled/VaultSlotMismatch) run before the
     * prompt. On any [DeviceUnlockError] → [DeviceUnlockState.Failed] and [onCredential] is NOT called.
     */
    suspend fun unlockWithBiometrics(
        @Suppress("UNUSED_PARAMETER") folder: String,
        vaultId: String,
        reason: String,
        onCredential: suspend (UnlockCredential.DeviceSecret) -> Unit,
    ) {
        state = DeviceUnlockState.Prompting
        val credential = try {
            coordinator.unlock(vaultId, reason)
        } catch (e: DeviceUnlockError) {
            state = DeviceUnlockState.Failed(e)
            return
        }
        onCredential(credential)
        state = DeviceUnlockState.Enrolled
    }
}
