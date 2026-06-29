package org.secretary.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.secretary.browse.VaultBrowseError
import org.secretary.browse.VaultLocation
import java.io.File

class UnlockMessagesTest {

    private fun cloudTarget(displayName: String): CloudVaultTarget =
        CloudVaultTarget(
            location = VaultLocation(displayName = displayName, treeUri = "content://tree/x"),
            workingDir = File("/tmp/working"),
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
}
