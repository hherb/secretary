import Foundation

/// FFI-free mirror of the vault settings record (the bridge `Settings` value).
/// All four fields are round-tripped on every write, so a partial update that
/// touches only retention / grace never drops `autoLockTimeoutMs` or
/// `requirePasswordBeforeEdits`. Field order mirrors the uniffi memberwise init
/// (auto-lock, require-password, reauth-grace, retention) for reviewer parity.
public struct VaultSettings: Equatable, Sendable {
    public var autoLockTimeoutMs: UInt64
    public var requirePasswordBeforeEdits: Bool
    public var reauthGraceWindowMs: UInt64
    public var retentionWindowMs: UInt64

    public init(autoLockTimeoutMs: UInt64,
                requirePasswordBeforeEdits: Bool,
                reauthGraceWindowMs: UInt64,
                retentionWindowMs: UInt64) {
        self.autoLockTimeoutMs = autoLockTimeoutMs
        self.requirePasswordBeforeEdits = requirePasswordBeforeEdits
        self.reauthGraceWindowMs = reauthGraceWindowMs
        self.retentionWindowMs = retentionWindowMs
    }
}

/// The projected FFI bound constants (in ms) the Settings UI validates against —
/// a single source of truth (the bridge schema, surfaced through the uniffi
/// reader fns). The `SecretaryKit` adapter bundles the six generated readers;
/// `FakeSettingsPort` seeds the real values. Only retention + reauth-grace are
/// surfaced (the two controls); auto-lock has no mobile UI and is enforced
/// server-side by `validate_save_settings`.
public struct SettingsBounds: Equatable, Sendable {
    public let retentionDefaultMs: UInt64
    public let retentionMinMs: UInt64
    public let retentionMaxMs: UInt64
    public let reauthGraceDefaultMs: UInt64
    public let reauthGraceMinMs: UInt64
    public let reauthGraceMaxMs: UInt64

    public init(retentionDefaultMs: UInt64, retentionMinMs: UInt64, retentionMaxMs: UInt64,
                reauthGraceDefaultMs: UInt64, reauthGraceMinMs: UInt64, reauthGraceMaxMs: UInt64) {
        self.retentionDefaultMs = retentionDefaultMs
        self.retentionMinMs = retentionMinMs
        self.retentionMaxMs = retentionMaxMs
        self.reauthGraceDefaultMs = reauthGraceDefaultMs
        self.reauthGraceMinMs = reauthGraceMinMs
        self.reauthGraceMaxMs = reauthGraceMaxMs
    }
}

/// The vault-settings operations the Settings screen and the Trash retention
/// path need. Conformed by the `SecretaryKit` adapter (`UniffiVaultSession`) and
/// by `FakeSettingsPort` in tests. `AnyObject, Sendable` mirrors `TrashPort`
/// (reference identity for handle ownership; crosses the gate's async boundary).
public protocol SettingsPort: AnyObject, Sendable {
    /// The persisted settings. Returns schema defaults for an absent or corrupt
    /// settings block (the bridge is lenient on record shape and never blocks
    /// vault access). Throws only on a hard vault error (e.g. corrupt vault).
    func readSettings() throws -> VaultSettings
    /// Persist all four fields (a partial update preserves the untouched ones).
    /// Out-of-range values are rejected server-side as `invalidArgument`.
    func writeSettings(_ settings: VaultSettings) throws
    /// The projected FFI bound constants the UI validates against.
    func settingsBounds() -> SettingsBounds
}
