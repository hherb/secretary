package org.secretary.browse

/**
 * Which secret the user supplied at the unlock screen. A single sealed type carries the credential
 * so the `when` over it is the one place that decides how to open.
 * The exhaustive match makes the recovery branch impossible to forget. Mirror of iOS
 * `UnlockViewModel.Mode { password, recovery }`.
 *
 * [secret] is the credential bytes (password UTF-8, or normalized phrase UTF-8). The caller owns
 * zeroizing it after the open returns.
 */
sealed interface UnlockCredential {
    val secret: ByteArray

    /**
     * The master password. [resetSyncState] true routes the open through
     * [VaultOpenPort.resetSyncStateAndOpenWithPassword]: set ONLY from the user's confirmation of
     * the rollback dialog (#746).
     */
    class Password(override val secret: ByteArray, val resetSyncState: Boolean = false) : UnlockCredential
    class Recovery(override val secret: ByteArray) : UnlockCredential
    class DeviceSecret(val deviceUuid: ByteArray, override val secret: ByteArray) : UnlockCredential
}

/**
 * Opens the vault with the supplied [credential]. Pure dispatch over [openPort] — no sync assembly,
 * no zeroize (the caller owns [credential]'s bytes). The host-testable seam for "which credential
 * routes to which open" ([openBrowseWithSync] itself is not host-testable: it calls Looper-gated
 * makeVaultSync).
 */
suspend fun openWithCredential(
    openPort: VaultOpenPort,
    vaultFolder: String,
    credential: UnlockCredential,
): VaultSession = when (credential) {
    is UnlockCredential.Password ->
        if (credential.resetSyncState) {
            openPort.resetSyncStateAndOpenWithPassword(vaultFolder, credential.secret)
        } else {
            openPort.openWithPassword(vaultFolder, credential.secret)
        }
    is UnlockCredential.Recovery -> openPort.openWithRecovery(vaultFolder, credential.secret)
    is UnlockCredential.DeviceSecret -> openPort.openWithDeviceSecret(vaultFolder, credential.deviceUuid, credential.secret)
}
