import SecretaryVaultAccess

/// In-memory `SettingsPort` double with spies + failure injection, modeled on
/// `FakeTrashPort`. Seeds a settings value + bounds; `writeSettings` records the
/// captured value to `writtenSettings` and updates the seed (so a later read
/// reflects it). `failNextRead` / `failNextWrite` throw once then clear.
/// `@unchecked Sendable` for the same single-thread reason as `FakeTrashPort`.
public final class FakeSettingsPort: SettingsPort, @unchecked Sendable {
    public var settings: VaultSettings
    public var bounds: SettingsBounds
    public var failNextRead: VaultAccessError?
    public var failNextWrite: VaultAccessError?

    public private(set) var readCount = 0
    public private(set) var writtenSettings: [VaultSettings] = []

    public init(settings: VaultSettings = FakeSettingsPort.defaultSettings,
                bounds: SettingsBounds = FakeSettingsPort.defaultBounds) {
        self.settings = settings
        self.bounds = bounds
    }

    public func readSettings() throws -> VaultSettings {
        readCount += 1
        if let e = failNextRead { failNextRead = nil; throw e }
        return settings
    }

    public func writeSettings(_ settings: VaultSettings) throws {
        if let e = failNextWrite { failNextWrite = nil; throw e }   // throw before recording: no write happened
        writtenSettings.append(settings)
        self.settings = settings
    }

    public func settingsBounds() -> SettingsBounds { bounds }

    /// The bridge-schema defaults (auto-lock 10 min, require-password true,
    /// grace 2 min, retention 90 d) — what an absent settings block yields.
    public static let defaultSettings = VaultSettings(
        autoLockTimeoutMs: 600_000,
        requirePasswordBeforeEdits: true,
        reauthGraceWindowMs: 120_000,
        retentionWindowMs: 90 * 86_400_000)

    /// The real projected bound values (retention 1…3650 d default 90;
    /// grace 0…60 min default 2).
    public static let defaultBounds = SettingsBounds(
        retentionDefaultMs: 90 * 86_400_000,
        retentionMinMs: 86_400_000,
        retentionMaxMs: 3650 * 86_400_000,
        reauthGraceDefaultMs: 120_000,
        reauthGraceMinMs: 0,
        reauthGraceMaxMs: 3_600_000)
}
