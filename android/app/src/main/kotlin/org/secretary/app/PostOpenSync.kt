package org.secretary.app

import org.secretary.browse.UnlockCredential

/**
 * Chooses the post-open sync action from the unlock credential. Android sync is password-keyed
 * (the SyncCoordinator re-opens the vault with the password per call), so a recovery-opened session
 * has no password to drive a sync pass: it refreshes status only. A password-opened session fires
 * the background sync-at-unlock. The exhaustive `when` makes the recovery case impossible to forget;
 * keeping it pure (lambdas, no FFI/VM) makes it host-testable. Mirrors iOS's optional-password
 * `onUnlocked` (`if let password { syncAtUnlock } else { refreshStatus }`).
 *
 * @param onPassword invoked with the password bytes (caller launches the background sync pass).
 * @param onRecovery invoked with no secret (caller refreshes the status badge).
 */
fun dispatchPostOpenSync(
    credential: UnlockCredential,
    onPassword: (ByteArray) -> Unit,
    onRecovery: () -> Unit,
) = when (credential) {
    is UnlockCredential.Password -> onPassword(credential.secret)
    is UnlockCredential.Recovery -> onRecovery()
}
