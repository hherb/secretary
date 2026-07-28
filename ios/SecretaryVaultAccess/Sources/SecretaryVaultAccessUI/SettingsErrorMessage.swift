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

/// Shown when a Settings numeric field doesn't hold a whole number at Save time.
///
/// A free function returning a fixed string rather than an arm of
/// `settingsErrorMessage`: unparseable text is refused by `commitSettingsEdits`
/// before it reaches the view model, so there is no `VaultAccessError` to map. The
/// views hold it in local state and clear it on every Save attempt.
///
/// "Each" not "Both": this fires when EITHER field is unparseable, and "Both fields
/// need…" reads as a diagnosis that both are wrong, sending the user hunting at the
/// valid one. Naming the offending field would be nicer still, but that is extra
/// branching on a render-untested path (#417) — deliberately not done.
public func settingsInputErrorMessage() -> String {
    "Each field needs a whole number — settings were not saved."
}

/// Short user-facing message for a "Forget this device" error, surfaced from
/// `DeviceSlotViewModel.error`. That error can be set from EITHER the re-auth
/// gate (`.reauthFailed`) or the revocation itself (any other case) — see
/// `DeviceSlotViewModel.forget()` — so this needs its own fallback rather than
/// reusing `settingsErrorMessage`, whose copy names the wrong action ("settings")
/// inside a section about forgetting a device.
///
/// Same anti-oracle discipline as `settingsErrorMessage`: the carried diagnostic
/// string is never interpolated into user-facing copy.
public func deviceSlotErrorMessage(_ e: VaultAccessError) -> String {
    switch e {
    case .reauthFailed:
        return "Re-authentication didn’t complete — this device was not forgotten."
    default:
        return "Couldn’t forget this device. Please try again."
    }
}
