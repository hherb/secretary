package org.secretary.browse

/**
 * User-facing text for a Settings-screen [error]. Pure + host-tested (extracted from the
 * `SettingsErrorBanner` composable so the wording is verifiable without an instrumented render, #421).
 *
 * The [error] state is populated by BOTH `SettingsModel.load()` and `SettingsModel.save()`; only
 * [VaultBrowseError.ReauthFailed] is save-specific (re-auth gates writes, never reads), so the
 * fallback stays operation-neutral ("update", not "save") — a hard read error from `load()` would
 * otherwise be mislabelled as a save failure. Mirror of iOS `settingsErrorMessage`.
 */
fun settingsErrorMessage(error: VaultBrowseError): String = when (error) {
    is VaultBrowseError.ReauthFailed -> "Couldn't authorize the change: ${error.detail}"
    else -> "Couldn't update settings: ${error::class.simpleName}"
}
