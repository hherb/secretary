package org.secretary.app

import androidx.fragment.app.FragmentActivity
import java.io.File
import org.secretary.browse.DeviceEnrollmentMetadataStore
import org.secretary.browse.DeviceSecretEnclave
import org.secretary.browse.DeviceUnlockCoordinator
import org.secretary.browse.FileDeviceEnrollmentMetadataStore
import org.secretary.browse.KeystoreDeviceSecretEnclave
import org.secretary.browse.UniffiVaultDeviceSlotPort

/** Which write-reauth gate the cloud open path should use, decided purely from enrollment state. */
enum class GateChoice { GRACE_WINDOW, NOOP }

/** Alias prefix for the per-cloud-vault Keystore key (kept distinct from the demo DEFAULT_ALIAS). */
const val CLOUD_DEVICE_ALIAS_PREFIX = "secretary.devicesecret.cloud."

/**
 * Decide the write-reauth gate for a cloud open. Pure: the caller reads [enclaveEnrolled]
 * (`enclave.isEnrolled`) and [metadataVaultId] (`metadata.load()?.vaultId`) and passes them in.
 *
 * A [GateChoice.GRACE_WINDOW] is returned ONLY when a secret is enrolled AND the stored enrollment
 * is for THIS [openVaultId] — a stale enrollment (different vault behind the same treeUri, or no
 * metadata) falls back to [GateChoice.NOOP] so writes are not blocked by a mismatched slot
 * (which would otherwise throw `VaultSlotMismatch` on every write).
 */
fun cloudReauthRoute(enclaveEnrolled: Boolean, openVaultId: String, metadataVaultId: String?): GateChoice =
    if (enclaveEnrolled && metadataVaultId != null && metadataVaultId == openVaultId) {
        GateChoice.GRACE_WINDOW
    } else {
        GateChoice.NOOP
    }

/** Per-cloud-vault device-secret dir (enclave blob + metadata), namespaced under the demo's parent. */
fun cloudDeviceSecretDir(noBackupBase: File, cloudKey: String): File =
    File(noBackupBase, "devicesecret/cloud/$cloudKey")

/** Per-cloud-vault Keystore key alias. */
fun cloudDeviceKeyAlias(cloudKey: String): String = "$CLOUD_DEVICE_ALIAS_PREFIX$cloudKey"

/**
 * A cloud vault's device-unlock surface: the [coordinator] (enroll/unlock/disenroll) plus cheap,
 * non-prompting reads of enrollment state used to pick the write-reauth gate. The enclave + metadata
 * are namespaced per cloud vault (by [cloudVaultKey]) so demo and multiple cloud vaults hold
 * independent secrets with no cross-talk.
 */
class CloudDeviceUnlock(
    val coordinator: DeviceUnlockCoordinator,
    private val enclave: DeviceSecretEnclave,
    private val metadata: DeviceEnrollmentMetadataStore,
) {
    /** True iff a secret blob exists for this cloud vault (cheap; never prompts). */
    val enclaveEnrolled: Boolean get() = enclave.isEnrolled

    /** The vaultId this device is enrolled against, or null if no metadata. Never prompts. */
    val metadataVaultId: String? get() = runCatching { metadata.load() }.getOrNull()?.vaultId
}

/**
 * Build the per-cloud-vault [CloudDeviceUnlock] keyed by [cloudKey]. The enclave + metadata live under
 * [cloudDeviceSecretDir]; the Keystore key uses [cloudDeviceKeyAlias]. The biometric gate is the same
 * production [biometricPromptGate] the demo uses (titled for cloud unlock).
 */
fun cloudDeviceUnlockCoordinator(
    activity: FragmentActivity,
    noBackupBase: File,
    cloudKey: String,
): CloudDeviceUnlock {
    val dir = cloudDeviceSecretDir(noBackupBase, cloudKey)
    val enclave = KeystoreDeviceSecretEnclave(
        dir = dir,
        gate = biometricPromptGate(activity, title = "Unlock Secretary"),
        keyAlias = cloudDeviceKeyAlias(cloudKey),
    )
    val metadata = FileDeviceEnrollmentMetadataStore(dir)
    val coordinator = DeviceUnlockCoordinator(UniffiVaultDeviceSlotPort(), enclave, metadata)
    return CloudDeviceUnlock(coordinator, enclave, metadata)
}
