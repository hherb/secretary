package org.secretary.browse

/**
 * FFI-free mirror of the vault settings record (the bridge `Settings` value). All four fields are
 * round-tripped on every write, so a partial update that touches only retention / grace never drops
 * [autoLockTimeoutMs] or [requirePasswordBeforeEdits]. Field order mirrors the uniffi `Settings`
 * memberwise shape (auto-lock, require-password, reauth-grace, retention). Kotlin mirror of iOS
 * `VaultSettings`. Values are `Long` (Kotlin idiom, matching [TrashPort.defaultRetentionWindowMs]);
 * the `:kit` adapter converts the generated `ULong` at the FFI boundary.
 */
data class VaultSettings(
    val autoLockTimeoutMs: Long,
    val requirePasswordBeforeEdits: Boolean,
    val reauthGraceWindowMs: Long,
    val retentionWindowMs: Long,
)

/**
 * The projected FFI bound constants (in ms) the Settings UI validates against — a single source of
 * truth (the bridge schema, surfaced through the uniffi reader fns). The `:kit` adapter bundles the
 * six generated readers; `FakeSettingsPort` seeds the real values. Only retention + reauth-grace are
 * surfaced (the two controls); auto-lock has no mobile UI and is enforced server-side by
 * `validate_save_settings`. Kotlin mirror of iOS `SettingsBounds`.
 */
data class SettingsBounds(
    val retentionDefaultMs: Long,
    val retentionMinMs: Long,
    val retentionMaxMs: Long,
    val reauthGraceDefaultMs: Long,
    val reauthGraceMinMs: Long,
    val reauthGraceMaxMs: Long,
)

/**
 * Inline saved-confirmation banner for the Settings screen (mirrors the Trash `PurgeNotice` idiom).
 * A settings save has no partial-failure state, so the banner is always a benign confirmation;
 * failures surface separately via the model's `error`. Kotlin mirror of iOS `SettingsBanner`.
 */
data class SettingsBanner(val text: String)

/**
 * The vault-settings operations the Settings screen and the Trash retention path need. Conformed
 * in-class by the `:kit` adapter ([org.secretary.browse.UniffiVaultSession]) and by `FakeSettingsPort`
 * in tests. Kotlin mirror of the iOS `SettingsPort` protocol.
 *
 * [readSettings] is a synchronous manifest+block read (one AEAD decrypt, no Argon2) — **lenient**: the
 * bridge returns schema defaults for an absent or corrupt settings block and never blocks vault
 * access; it throws [VaultBrowseError] only on a hard vault error. [writeSettings] is `suspend` — the
 * real adapter offloads the FFI `save_block` to the IO dispatcher, like [TrashPort.restoreBlock].
 * Out-of-range values are rejected server-side as [VaultBrowseError.InvalidArgument].
 */
interface SettingsPort {
    /** The persisted settings (schema defaults for an absent/corrupt block). Throws only on a hard vault error. */
    fun readSettings(): VaultSettings

    /** Persist all four fields (a partial update preserves the untouched ones). */
    suspend fun writeSettings(settings: VaultSettings)

    /** The projected FFI bound constants the UI validates against. */
    fun settingsBounds(): SettingsBounds
}
