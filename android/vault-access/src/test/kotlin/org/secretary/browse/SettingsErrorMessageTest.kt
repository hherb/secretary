package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SettingsErrorMessageTest {
    @Test
    fun reauthFailed_usesAuthorizeCopyWithDetail() {
        assertEquals(
            "Couldn't authorize the change: no match",
            settingsErrorMessage(VaultBrowseError.ReauthFailed("no match")),
        )
    }

    @Test
    fun vaultChangedOnDisk_usesTheSharedSyncCopy() {
        assertEquals(
            "This vault changed on another device since you opened it. Sync, then try again.",
            settingsErrorMessage(VaultBrowseError.VaultChangedOnDisk),
        )
    }

    @Test
    fun genericLoadOrSaveError_usesNeutralUpdateCopy_notSave() {
        // A hard read error surfaced from load() must NOT read "save" (the #421 bug).
        val msg = settingsErrorMessage(VaultBrowseError.CorruptVault("boom"))
        assertEquals("Couldn't update settings: CorruptVault", msg)
    }
}
