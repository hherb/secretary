package org.secretary.browse

/** User-facing copy for the device-settings surface. Conflates wrong-password vs. corrupt per
 *  threat-model §13 — do NOT split [ENROLL_FAILED_MESSAGE] into distinct password/corruption text. */
internal const val ENROLL_BIOMETRIC_UNAVAILABLE_MESSAGE =
    "Couldn't enable biometric unlock — no biometric is set up on this device."
internal const val ENROLL_FAILED_MESSAGE =
    "Couldn't enable biometric unlock — wrong password, or biometrics unavailable."
internal const val DISENROLL_FAILED_MESSAGE =
    "Couldn't disable biometric unlock — please try again."

/**
 * Plain UI state for the device-management Settings surface. Carries [enrolled] (which button to
 * show), [working] (an op is in flight — disable buttons) and an optional user-safe [error] together,
 * so a failure never loses the enrolled/unenrolled status. Rendered by `DeviceSettingsScreen`.
 */
data class DeviceSettingsState(
    val enrolled: Boolean,
    val working: Boolean = false,
    val error: String? = null,
)

/**
 * Pure view-model for the Settings surface: a thin state wrapper over [DeviceUnlockCoordinator]
 * (which holds the real enroll/disenroll). Separate from `DeviceUnlockViewModel` (single
 * responsibility; that VM's states are unlock-flow-shaped). Host-tested over the in-memory fakes.
 *
 * Unlike the unlock-time enroll (whose password was already validated by the open), the Settings
 * enroll re-prompts an UNVERIFIED password — so [enroll] catches BOTH [DeviceUnlockError] AND
 * [VaultBrowseError] (a wrong password surfaces as [VaultBrowseError.WrongPasswordOrCorrupt] from
 * `addDeviceSlot`). [password] is caller-owned (forwarded to the coordinator, not zeroized here).
 */
class DeviceSettingsViewModel(private val coordinator: DeviceUnlockCoordinator) {
    var state: DeviceSettingsState = DeviceSettingsState(enrolled = false)
        private set

    /** Cheap, prompt-free recompute of enrolled-vs-not; clears any prior error. */
    fun refresh() {
        state = DeviceSettingsState(enrolled = coordinator.isEnrolled)
    }

    /** Enroll this device (triggers the one enroll-time biometric prompt inside the enclave). */
    suspend fun enroll(folder: String, vaultId: String, password: ByteArray) {
        state = state.copy(working = true, error = null)
        state = try {
            coordinator.enroll(folder, vaultId, password)
            DeviceSettingsState(enrolled = true)
        } catch (e: DeviceUnlockError) {
            DeviceSettingsState(enrolled = coordinator.isEnrolled, error = enrollErrorMessage(e))
        } catch (e: VaultBrowseError) {
            DeviceSettingsState(enrolled = coordinator.isEnrolled, error = enrollErrorMessage(e))
        }
    }

    /** Revoke this device's enrollment (idempotent; needs no password). */
    suspend fun disenroll(folder: String) {
        state = state.copy(working = true, error = null)
        state = try {
            coordinator.disenroll(folder)
            DeviceSettingsState(enrolled = false)
        } catch (e: VaultBrowseError) {
            DeviceSettingsState(enrolled = coordinator.isEnrolled, error = DISENROLL_FAILED_MESSAGE)
        }
    }
}

/** Map an enroll failure to user-safe copy. Biometric-absent gets its own hint; everything else
 *  (incl. wrong password / corruption) folds to the conflated [ENROLL_FAILED_MESSAGE] (§13). */
internal fun enrollErrorMessage(e: Throwable): String = when (e) {
    is DeviceUnlockError.BiometryNotEnrolled,
    is DeviceUnlockError.BiometryUnavailable -> ENROLL_BIOMETRIC_UNAVAILABLE_MESSAGE
    else -> ENROLL_FAILED_MESSAGE
}
