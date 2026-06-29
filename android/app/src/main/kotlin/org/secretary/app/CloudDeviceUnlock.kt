package org.secretary.app

import java.io.File

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
