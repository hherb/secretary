package org.secretary.app

import org.secretary.browse.UnlockCredential
import org.secretary.browse.VaultBrowseError

// Pure derivations for the Unlock screen's chrome — kept free of Compose/Android types so they are
// host-testable in `:app/src/test`. [UnlockScreen] and [AppRoot] consume these; nothing here has side
// effects.

/** Title prefix shared by every unlock target. */
private const val TITLE_PREFIX = "Secretary — "

/** Suffix for the demo (golden) vault — the [CloudVaultTarget]-less path. */
private const val DEMO_VAULT_SUFFIX = "demo vault"

private const val MSG_WRONG_PASSWORD = "Wrong password, or the vault is damaged."
private const val MSG_WRONG_RECOVERY = "Wrong recovery phrase, or the vault is damaged."
private const val MSG_INVALID_PHRASE_PREFIX = "Invalid recovery phrase: "
private const val MSG_GENERIC = "Couldn't open the vault. Please try again."
private const val MSG_ROLLBACK_USE_PASSWORD =
    "This vault looks older than this device expected. Unlock with your master password to continue."

// Rollback reset dialog copy (#746), shared verbatim with desktop and iOS.
const val ROLLBACK_DIALOG_TITLE = "This vault looks older than expected"
const val ROLLBACK_DIALOG_BODY =
    "This device last saw a newer version of this vault. That can happen after restoring a backup, " +
        "but it can also mean your storage provider is serving an old copy. Only continue if you " +
        "restored this vault from a backup or are sure this copy is current."
const val ROLLBACK_DIALOG_CONFIRM = "Reset and open"
const val ROLLBACK_DIALOG_CANCEL = "Cancel"

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
    is VaultBrowseError.RollbackDetected -> MSG_ROLLBACK_USE_PASSWORD
    else -> MSG_GENERIC
}

/** How the Unlock screen answers an open refused as a rollback (#746). */
internal enum class RollbackRefusal {
    /** A master-password open: show the reset dialog, which reuses the entered password. */
    OfferReset,

    /** A recovery or biometric open: the reset takes the master password, so ask for it. Never
     *  offer the reset from a biometric unlock. */
    UnlockWithPassword,
}

/** The [RollbackRefusal] for a failed open of [credential], or null when [error] is not a rollback. */
internal fun rollbackRefusal(error: Throwable, credential: UnlockCredential): RollbackRefusal? = when {
    error !is VaultBrowseError.RollbackDetected -> null
    credential is UnlockCredential.Password -> RollbackRefusal.OfferReset
    else -> RollbackRefusal.UnlockWithPassword
}

/**
 * The toast for a failed open, or null when the reset dialog answers it instead. [fallback] is the
 * path's usual failure text, used when the open was not refused as a rollback.
 */
internal fun failedOpenToast(rollback: RollbackRefusal?, fallback: String): String? = when (rollback) {
    RollbackRefusal.OfferReset -> null
    RollbackRefusal.UnlockWithPassword -> MSG_ROLLBACK_USE_PASSWORD
    null -> fallback
}
