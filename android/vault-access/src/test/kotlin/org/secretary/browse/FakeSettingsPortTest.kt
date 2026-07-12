package org.secretary.browse

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** The `SettingsPort` in-memory double behaves as the model tests rely on. */
class FakeSettingsPortTest {
    @Test
    fun `read returns the seed`() {
        val seed = VaultSettings(600_000L, requirePasswordBeforeEdits = true, 120_000L, 90L * MS_PER_DAY)
        assertEquals(seed, FakeSettingsPort(settings = seed).readSettings())
    }

    @Test
    fun `write records and updates the seed`() = runTest {
        val port = FakeSettingsPort()
        val next = VaultSettings(1L, requirePasswordBeforeEdits = false, 2L, 3L)
        port.writeSettings(next)
        assertEquals(listOf(next), port.writtenSettings)
        assertEquals(next, port.readSettings())
    }

    @Test
    fun `failNextRead throws once then clears`() {
        val port = FakeSettingsPort(failNextRead = VaultBrowseError.CorruptVault("boom"))
        assertThrows(VaultBrowseError.CorruptVault::class.java) { port.readSettings() }
        port.readSettings() // cleared → succeeds, no throw
    }

    @Test
    fun `failNextWrite throws once then clears`() = runTest {
        val port = FakeSettingsPort(failNextWrite = VaultBrowseError.InvalidArgument("bad"))
        val v = VaultSettings(1L, requirePasswordBeforeEdits = false, 2L, 3L)
        var threw = false
        try {
            port.writeSettings(v)
        } catch (e: VaultBrowseError.InvalidArgument) {
            threw = true
        }
        assertTrue(threw)
        port.writeSettings(v) // cleared → succeeds
        assertEquals(listOf(v), port.writtenSettings)
    }

    @Test
    fun `settingsBounds returns the seed`() {
        val b = defaultSettingsBounds()
        assertEquals(b, FakeSettingsPort(bounds = b).settingsBounds())
    }
}
