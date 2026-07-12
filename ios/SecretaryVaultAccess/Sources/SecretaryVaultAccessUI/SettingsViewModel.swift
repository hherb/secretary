import Combine
import SecretaryVaultAccess

/// Host-testable Settings screen view model. Exposes two editable controls —
/// retention window (days) and re-auth grace (minutes) — validated client-side
/// against the projected FFI bounds. A save routes through the shared re-auth
/// gate (a settings change is a vault write, so it obeys the same gate-integrity
/// invariants as the Trash destructive ops), preserves the two round-tripped
/// fields the UI never edits (`autoLockTimeoutMs` / `requirePasswordBeforeEdits`),
/// and — **strictly after a successful save** — retargets the live gate to the
/// new grace window.
///
/// Security ordering (load-bearing): the save is gated against the CURRENT
/// (pre-save) grace window; the retarget runs only on success. A user at an
/// unlocked-but-unattended session outside the current grace window therefore
/// cannot widen their own grace window to self-authorize the widening — the
/// widening still demands a biometric proof. See `RetargetableReauthGate`.
@MainActor
public final class SettingsViewModel: ObservableObject {
    @Published public private(set) var retentionDays: Int
    @Published public private(set) var graceMinutes: Int
    @Published public private(set) var isWriting = false
    @Published public private(set) var error: VaultAccessError?
    /// Set on a successful save; cleared at the start of any new save. Failures
    /// surface via `error`, not here (a save has no partial-failure state).
    @Published public private(set) var banner: SettingsBanner?

    private let port: SettingsPort
    private let gate: RetargetableReauthGate
    private let bounds: SettingsBounds
    /// The full settings last read or saved — holds the round-tripped fields
    /// (`autoLockTimeoutMs` / `requirePasswordBeforeEdits`) the UI never edits,
    /// so a save preserves them. Overwritten by `load()` and on a successful save.
    private var loaded: VaultSettings

    /// Pre-load / read-error placeholder for the unedited `autoLockTimeoutMs`
    /// (mirrors the bridge `AUTO_LOCK_DEFAULT_MS`, which is not projected onto
    /// the FFI). Only used before a successful `load()`; the happy path reads the
    /// real value (an absent settings block yields the bridge default here too).
    private static let defaultAutoLockTimeoutMs: UInt64 = 600_000

    public init(port: SettingsPort, gate: RetargetableReauthGate) {
        self.port = port
        self.gate = gate
        let b = port.settingsBounds()
        self.bounds = b
        self.loaded = VaultSettings(
            autoLockTimeoutMs: Self.defaultAutoLockTimeoutMs,
            requirePasswordBeforeEdits: true,
            reauthGraceWindowMs: b.reauthGraceDefaultMs,
            retentionWindowMs: b.retentionDefaultMs)
        self.retentionDays = retentionDaysFromMs(b.retentionDefaultMs)
        self.graceMinutes = graceMinutesFromMs(b.reauthGraceDefaultMs)
    }

    /// Load the persisted settings into the two controls. On a hard read error
    /// (corrupt vault — unreachable for a normally-opened vault) the controls
    /// fall back to the bounds defaults and `error` is surfaced.
    public func load() {
        error = nil
        do {
            let s = try port.readSettings()
            loaded = s
            retentionDays = clampRetentionDays(retentionDaysFromMs(s.retentionWindowMs), bounds: bounds)
            graceMinutes = clampGraceMinutes(graceMinutesFromMs(s.reauthGraceWindowMs), bounds: bounds)
        } catch let e as VaultAccessError {
            error = e
            resetControlsToDefault()
        } catch {
            self.error = .other(String(describing: error))
            resetControlsToDefault()
        }
    }

    private func resetControlsToDefault() {
        retentionDays = retentionDaysFromMs(bounds.retentionDefaultMs)
        graceMinutes = graceMinutesFromMs(bounds.reauthGraceDefaultMs)
    }

    /// Set the retention-days control, clamped to the projected bounds.
    public func setRetentionDays(_ days: Int) {
        retentionDays = clampRetentionDays(days, bounds: bounds)
    }

    /// Set the grace-minutes control, clamped to the projected bounds.
    public func setGraceMinutes(_ minutes: Int) {
        graceMinutes = clampGraceMinutes(minutes, bounds: bounds)
    }

    /// Gated save: re-auth against the current window → persist all four fields
    /// → on success retarget the gate to the new grace window + show the banner.
    /// `isWriting` is set before the gate await so a second save during the
    /// biometric prompt is rejected; `banner` is cleared so a new save supersedes
    /// the prior confirmation.
    public func save() async {
        guard !isWriting else { return }
        isWriting = true
        banner = nil
        defer { isWriting = false }

        // Preserve the two round-tripped fields; only retention + grace are edited.
        let newSettings = VaultSettings(
            autoLockTimeoutMs: loaded.autoLockTimeoutMs,
            requirePasswordBeforeEdits: loaded.requirePasswordBeforeEdits,
            reauthGraceWindowMs: msFromGraceMinutes(graceMinutes),
            retentionWindowMs: msFromRetentionDays(retentionDays))

        // Gate the save against the CURRENT (pre-save) grace window.
        do {
            try await gate.authorizeWrite(reason: "Confirm changing vault settings")
        } catch let e as VaultAccessError {
            error = e
            return                              // refused re-auth ⇒ NO write, NO retarget
        } catch {
            self.error = .reauthFailed(String(describing: error))
            return
        }

        // Persist. On failure, do NOT retarget or banner.
        do {
            try port.writeSettings(newSettings)
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .other(String(describing: error))
            return
        }

        // SUCCESS — commit local state, then retarget the live gate strictly
        // after the save (so the just-persisted save was evaluated against the
        // pre-save window).
        loaded = newSettings
        error = nil
        gate.retarget(window: .milliseconds(Int(newSettings.reauthGraceWindowMs)))
        banner = settingsSavedBanner()
    }
}
