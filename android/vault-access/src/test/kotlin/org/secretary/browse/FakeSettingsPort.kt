package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred

/**
 * In-memory [SettingsPort] test double. Seed [settings] / [bounds]; prime [failNextRead] /
 * [failNextWrite] to throw once (then they self-clear). Records each write in [writtenSettings].
 * Mirror of iOS `FakeSettingsPort`.
 *
 * When [writeGate] is set, [writeSettings] awaits it before recording — lets a test hold a write in
 * flight while a second call hits the model's re-entrancy guard (a faithful race, not a sleep).
 */
class FakeSettingsPort(
    var settings: VaultSettings = defaultVaultSettings(),
    private val bounds: SettingsBounds = defaultSettingsBounds(),
    var failNextRead: VaultBrowseError? = null,
    var failNextWrite: VaultBrowseError? = null,
    private val writeGate: CompletableDeferred<Unit>? = null,
) : SettingsPort {
    val writtenSettings = mutableListOf<VaultSettings>()

    override fun readSettings(): VaultSettings {
        failNextRead?.let { failNextRead = null; throw it }
        return settings
    }

    override suspend fun writeSettings(settings: VaultSettings) {
        writeGate?.await()
        failNextWrite?.let { failNextWrite = null; throw it }
        writtenSettings += settings
        this.settings = settings
    }

    override fun settingsBounds(): SettingsBounds = bounds
}

/** The real schema defaults, so tests seed the same values production sees for a fresh vault
 *  (bridge `Settings::default()`: auto-lock 10 min, require-password on, grace 2 min, retention 90 d). */
fun defaultVaultSettings(): VaultSettings = VaultSettings(
    autoLockTimeoutMs = 600_000L,
    requirePasswordBeforeEdits = true,
    reauthGraceWindowMs = 120_000L,
    retentionWindowMs = 90L * MS_PER_DAY,
)

/** The real projected bound constants (the six uniffi reader values). */
fun defaultSettingsBounds(): SettingsBounds = SettingsBounds(
    retentionDefaultMs = 90L * MS_PER_DAY,
    retentionMinMs = MS_PER_DAY,
    retentionMaxMs = 3650L * MS_PER_DAY,
    reauthGraceDefaultMs = 120_000L,
    reauthGraceMinMs = 0L,
    reauthGraceMaxMs = 3_600_000L,
)
