import SecretaryVaultAccess

/// Short user-facing message for a Settings-screen error. Pure + host-tested (extracted from the
/// `SettingsScreen` view so the wording is verifiable without an instrumented render, #421).
///
/// The `error` state is populated by BOTH `SettingsViewModel.load()` and `.save()`; only
/// `.reauthFailed` / `.invalidArgument` are save-specific (re-auth and range-validation never occur
/// on a read), so the fallback stays operation-neutral ("update", not "save") — a hard read error
/// from `load()` would otherwise be mislabelled as a save failure. The anti-oracle "…OrCorrupt"
/// cases are folded upstream. Structural mirror of Android `settingsErrorMessage` (same arms +
/// neutral fallback); the copy differs by platform idiom — iOS ends with a plain "Please try
/// again.", Android appends the error type (`::simpleName`) for debuggability.
public func settingsErrorMessage(_ e: VaultAccessError) -> String {
    switch e {
    case .reauthFailed:
        return "Re-authentication didn’t complete — settings were not saved."
    case .invalidArgument:
        return "That value is out of range — settings were not saved."
    default:
        return "Couldn’t update settings. Please try again."
    }
}
