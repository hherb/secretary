package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.secretary.browse.UnlockCredential
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultLocation
import java.io.File

class UnlockMessagesTest {

    private fun cloudTarget(displayName: String): CloudVaultTarget =
        CloudVaultTarget(
            location = VaultLocation(displayName = displayName, treeUri = "content://tree/x"),
            workingDir = File("working"),
            isCreate = false,
        )

    @Test
    fun titleForDemoTargetIsTheDemoVaultTitle() {
        assertEquals("Secretary — demo vault", unlockScreenTitle(null))
    }

    @Test
    fun titleForCloudTargetUsesItsDisplayName() {
        assertEquals("Secretary — Family Drive", unlockScreenTitle(cloudTarget("Family Drive")))
    }

    @Test
    fun wrongPasswordMapsToTheWrongPasswordMessage() {
        assertEquals(
            "Wrong password, or the vault is damaged.",
            unlockFailureMessage(VaultBrowseError.WrongPasswordOrCorrupt),
        )
    }

    @Test
    fun wrongRecoveryMapsToTheWrongRecoveryMessage() {
        assertEquals(
            "Wrong recovery phrase, or the vault is damaged.",
            unlockFailureMessage(VaultBrowseError.WrongRecoveryOrCorrupt),
        )
    }

    @Test
    fun invalidRecoveryPhraseInterpolatesItsDetail() {
        assertEquals(
            "Invalid recovery phrase: word 3 is not in the wordlist",
            unlockFailureMessage(VaultBrowseError.InvalidRecoveryPhrase("word 3 is not in the wordlist")),
        )
    }

    @Test
    fun unknownThrowableMapsToTheGenericMessage() {
        assertEquals(
            "Couldn't open the vault. Please try again.",
            unlockFailureMessage(RuntimeException("boom")),
        )
    }

    @Test
    fun otherVaultBrowseErrorArmMapsToTheGenericMessage() {
        assertEquals(
            "Couldn't open the vault. Please try again.",
            unlockFailureMessage(VaultBrowseError.FolderInvalid("nope")),
        )
    }

    // --- #746 rollback refusal ---

    @Test
    fun aRollbackRefusedPasswordOpenOffersTheResetAndNoToast() {
        val rollback = rollbackRefusal(VaultBrowseError.RollbackDetected, UnlockCredential.Password(byteArrayOf(1)))
        assertEquals(RollbackRefusal.OfferReset, rollback)
        assertNull(failedOpenToast(rollback, "fallback"), "the dialog answers it, not a toast")
    }

    @Test
    fun aRollbackRefusedBiometricOrRecoveryOpenAsksForThePasswordAndNeverOffersTheReset() {
        for (credential in listOf(
            UnlockCredential.DeviceSecret(ByteArray(16), ByteArray(32)),
            UnlockCredential.Recovery(byteArrayOf(1)),
        )) {
            val rollback = rollbackRefusal(VaultBrowseError.RollbackDetected, credential)
            assertEquals(RollbackRefusal.UnlockWithPassword, rollback)
            assertEquals(
                "This vault looks older than this device expected. Unlock with your master password to continue.",
                failedOpenToast(rollback, "fallback"),
            )
        }
    }

    @Test
    fun aFailedResetIsSurfacedAsAnOrdinaryOpenFailure() {
        // The reset itself never raises RollbackDetected, so its failure gets no second dialog.
        val reset = UnlockCredential.Password(byteArrayOf(1), resetSyncState = true)
        val rollback = rollbackRefusal(VaultBrowseError.WrongPasswordOrCorrupt, reset)
        assertNull(rollback)
        assertEquals(
            "Wrong password, or the vault is damaged.",
            failedOpenToast(rollback, unlockFailureMessage(VaultBrowseError.WrongPasswordOrCorrupt)),
        )
    }

    @Test
    fun rollbackDetectedHasItsOwnUnlockFailureMessage() {
        assertEquals(
            "This vault looks older than this device expected. Unlock with your master password to continue.",
            unlockFailureMessage(VaultBrowseError.RollbackDetected),
        )
    }

    @Test
    fun theRollbackDialogCopyMatchesDesktopAndIos() {
        assertEquals("This vault looks older than expected", ROLLBACK_DIALOG_TITLE)
        assertEquals(
            "This device last saw a newer version of this vault. That can happen after restoring a backup, but " +
                "it can also mean your storage provider is serving an old copy. Only continue if you restored " +
                "this vault from a backup or are sure this copy is current.",
            ROLLBACK_DIALOG_BODY,
        )
        assertEquals("Reset and open", ROLLBACK_DIALOG_CONFIRM)
        assertEquals("Cancel", ROLLBACK_DIALOG_CANCEL)
    }
}
