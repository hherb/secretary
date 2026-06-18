package org.secretary.browse

/**
 * Which secret the user supplied at the unlock screen. A single sealed type carries the credential
 * so the `when` over it is the one place that decides how to open (and, in `:app`, how to sync).
 * The exhaustive match makes the recovery branch impossible to forget. Mirror of iOS
 * `UnlockViewModel.Mode { password, recovery }`.
 *
 * [secret] is the credential bytes (password UTF-8, or normalized phrase UTF-8). The caller owns
 * zeroizing it after the open returns.
 */
sealed interface UnlockCredential {
    val secret: ByteArray

    class Password(override val secret: ByteArray) : UnlockCredential
    class Recovery(override val secret: ByteArray) : UnlockCredential
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
    is UnlockCredential.Password -> openPort.openWithPassword(vaultFolder, credential.secret)
    is UnlockCredential.Recovery -> openPort.openWithRecovery(vaultFolder, credential.secret)
}
