package org.secretary.browse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import uniffi.secretary.Settings as FfiSettings

/**
 * The generated-uniffi [FfiSettings] ↔ FFI-free [VaultSettings] projection — the one `ULong`↔`Long`
 * boundary the `:kit` settings adapter crosses (host-tested, no native lib). All four fields, both
 * directions, plus the extremes of the projected bounds (0 grace, 3650-day retention).
 */
class SettingsMappingTest {
    private val retentionMax = 3650L * MS_PER_DAY

    @Test
    fun `FfiSettings maps to VaultSettings (ULong to Long, all four fields)`() {
        val v = FfiSettings(
            autoLockTimeoutMs = 600_000uL,
            requirePasswordBeforeEdits = true,
            reauthGraceWindowMs = 120_000uL,
            retentionWindowMs = retentionMax.toULong(),
        ).toVaultSettings()
        assertEquals(600_000L, v.autoLockTimeoutMs)
        assertEquals(true, v.requirePasswordBeforeEdits)
        assertEquals(120_000L, v.reauthGraceWindowMs)
        assertEquals(retentionMax, v.retentionWindowMs)
    }

    @Test
    fun `VaultSettings maps to FfiSettings (Long to ULong, all four fields)`() {
        val ffi = VaultSettings(
            autoLockTimeoutMs = 600_000L,
            requirePasswordBeforeEdits = false,
            reauthGraceWindowMs = 0L,
            retentionWindowMs = retentionMax,
        ).toFfiSettings()
        assertEquals(600_000uL, ffi.autoLockTimeoutMs)
        assertEquals(false, ffi.requirePasswordBeforeEdits)
        assertEquals(0uL, ffi.reauthGraceWindowMs)
        assertEquals(retentionMax.toULong(), ffi.retentionWindowMs)
    }

    @Test
    fun `round-trips through both projections`() {
        val v = VaultSettings(600_000L, requirePasswordBeforeEdits = true, 120_000L, 90L * MS_PER_DAY)
        assertEquals(v, v.toFfiSettings().toVaultSettings())
    }
}
