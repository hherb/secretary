import Foundation
import SecretaryVaultAccess

/// `SettingsPort` conformance for `UniffiVaultSession`. Reuses the internal
/// `readTrash` / `writeTrash` helpers so a settings read/write gets the same
/// wiped-guard, device-uuid/now resolution, and `VaultError` → `VaultAccessError`
/// mapping as every other vault op. Only the four numeric/bool settings fields
/// cross this boundary — no record plaintext.
///
/// Out-of-range values and a wrong-length device UUID are rejected inside the
/// uniffi `write_settings` wrapper (`VaultError.InvalidArgument`, mapped here to
/// `VaultAccessError.invalidArgument`); the view model also clamps client-side.
extension UniffiVaultSession: SettingsPort {
    public func readSettings() throws -> VaultSettings {
        try readTrash {
            let s = try SecretaryKit.readSettings(identity: identity, manifest: manifest)
            return VaultSettings(
                autoLockTimeoutMs: s.autoLockTimeoutMs,
                requirePasswordBeforeEdits: s.requirePasswordBeforeEdits,
                reauthGraceWindowMs: s.reauthGraceWindowMs,
                retentionWindowMs: s.retentionWindowMs)
        }
    }

    public func writeSettings(_ settings: VaultSettings) throws {
        let uniffi = SecretaryKit.Settings(
            autoLockTimeoutMs: settings.autoLockTimeoutMs,
            requirePasswordBeforeEdits: settings.requirePasswordBeforeEdits,
            reauthGraceWindowMs: settings.reauthGraceWindowMs,
            retentionWindowMs: settings.retentionWindowMs)
        try writeTrash { dev, now in
            try SecretaryKit.writeSettings(
                identity: identity, manifest: manifest, settings: uniffi,
                deviceUuid: Data(dev), nowMs: now)
        }
    }

    public func settingsBounds() -> SettingsBounds {
        SettingsBounds(
            retentionDefaultMs: SecretaryKit.defaultRetentionWindowMs(),
            retentionMinMs: SecretaryKit.retentionWindowMinMs(),
            retentionMaxMs: SecretaryKit.retentionWindowMaxMs(),
            reauthGraceDefaultMs: SecretaryKit.reauthWindowDefaultMs(),
            reauthGraceMinMs: SecretaryKit.reauthWindowMinMs(),
            reauthGraceMaxMs: SecretaryKit.reauthWindowMaxMs())
    }
}
