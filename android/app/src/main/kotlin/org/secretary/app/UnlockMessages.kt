package org.secretary.app

import org.secretary.browse.VaultBrowseError

/**
 * Pure derivations for the Unlock screen's chrome — kept free of Compose/Android types so they are
 * host-testable in `:app/src/test`. [UnlockScreen] and [AppRoot] consume these; nothing here has side
 * effects.
 */

/** Title prefix shared by every unlock target. */
private const val TITLE_PREFIX = "Secretary — "

/** Suffix for the demo (golden) vault — the [CloudVaultTarget]-less path. */
private const val DEMO_VAULT_SUFFIX = "demo vault"

private const val MSG_WRONG_PASSWORD = "Wrong password, or the vault is damaged."
private const val MSG_WRONG_RECOVERY = "Wrong recovery phrase, or the vault is damaged."
private const val MSG_INVALID_PHRASE_PREFIX = "Invalid recovery phrase: "
private const val MSG_GENERIC = "Couldn't open the vault. Please try again."

/**
 * The Unlock screen title for [cloudTarget]: the demo-vault title when null (the golden-vault path),
 * otherwise the cloud folder's display name. Lets the user tell which vault they are unlocking (#332).
 */
fun unlockScreenTitle(cloudTarget: CloudVaultTarget?): String =
    TITLE_PREFIX + (cloudTarget?.location?.displayName ?: DEMO_VAULT_SUFFIX)

/**
 * A user-facing message for a failed demo/password open. Maps the typed [VaultBrowseError] arms the
 * open port can raise (wrong password/recovery — conflated with corruption per the threat model §13;
 * malformed recovery phrase — safe to surface verbatim) and folds everything else (IO/SAF/unknown)
 * to a generic message. Total over [Throwable] (#332).
 */
fun unlockFailureMessage(error: Throwable): String = when (error) {
    is VaultBrowseError.WrongPasswordOrCorrupt -> MSG_WRONG_PASSWORD
    is VaultBrowseError.WrongRecoveryOrCorrupt -> MSG_WRONG_RECOVERY
    is VaultBrowseError.InvalidRecoveryPhrase -> MSG_INVALID_PHRASE_PREFIX + error.detail
    else -> MSG_GENERIC
}
