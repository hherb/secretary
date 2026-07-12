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

    public init(port: SettingsPort, gate: RetargetableReauthGate) {
        self.port = port
        self.gate = gate
        let b = port.settingsBounds()
        self.bounds = b
        self.retentionDays = retentionDaysFromMs(b.retentionDefaultMs)
        self.graceMinutes = graceMinutesFromMs(b.reauthGraceDefaultMs)
    }

    /// Load the persisted settings into the two controls. On a hard read error
    /// (corrupt vault — unreachable for a normally-opened vault) the controls
    /// fall back to the bounds defaults and `error` is surfaced. The two unedited
    /// fields (`autoLockTimeoutMs` / `requirePasswordBeforeEdits`) are NOT cached
    /// here — `save()` re-reads them fresh, so a save can never write back a stale
    /// placeholder (see `save()`). The persisted retention/grace are bridge-clamped
    /// to their valid ranges on read, so the conversions cannot overflow.
    public func load() {
        error = nil
        do {
            let s = try port.readSettings()
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

    /// The valid retention-days range (from the projected bounds), for the UI
    /// input's range + hint — one source with the client-side clamp.
    public var retentionDaysRange: ClosedRange<Int> {
        retentionDaysFromMs(bounds.retentionMinMs)...retentionDaysFromMs(bounds.retentionMaxMs)
    }

    /// The valid grace-minutes range (from the projected bounds).
    public var graceMinutesRange: ClosedRange<Int> {
        graceMinutesFromMs(bounds.reauthGraceMinMs)...graceMinutesFromMs(bounds.reauthGraceMaxMs)
    }

    /// Set the retention-days control, clamped to the projected bounds.
    public func setRetentionDays(_ days: Int) {
        retentionDays = clampRetentionDays(days, bounds: bounds)
    }

    /// Set the grace-minutes control, clamped to the projected bounds.
    public func setGraceMinutes(_ minutes: Int) {
        graceMinutes = clampGraceMinutes(minutes, bounds: bounds)
    }

    /// Gated save: re-auth against the current window → re-read the persisted
    /// settings and merge only the two edited fields (retention + grace) onto the
    /// two unedited ones → persist all four → on success retarget the gate to the
    /// new grace window + show the banner.
    ///
    /// The unedited fields (`autoLockTimeoutMs` / `requirePasswordBeforeEdits`)
    /// are re-read here — not carried from `load()` — so a save can never write a
    /// stale/placeholder value (e.g. a save before `load()` ran, or after a load
    /// that threw), which would silently loosen the auto-lock or force
    /// require-password. Re-reading right before the write also closes the
    /// load→save TOCTOU against another client that changed those fields.
    ///
    /// `isWriting` is set before the gate await so a second save during the
    /// biometric prompt is rejected; `banner` is cleared so a new save supersedes
    /// the prior confirmation.
    public func save() async {
        guard !isWriting else { return }
        isWriting = true
        banner = nil
        defer { isWriting = false }

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

        // Re-read the persisted settings for the two unedited fields; abort if it
        // fails (no write on a read error, so nothing is clobbered).
        let current: VaultSettings
        do {
            current = try port.readSettings()
        } catch let e as VaultAccessError {
            error = e
            return
        } catch {
            self.error = .other(String(describing: error))
            return
        }

        let newSettings = VaultSettings(
            autoLockTimeoutMs: current.autoLockTimeoutMs,
            requirePasswordBeforeEdits: current.requirePasswordBeforeEdits,
            reauthGraceWindowMs: msFromGraceMinutes(graceMinutes),
            retentionWindowMs: msFromRetentionDays(retentionDays))

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

        // SUCCESS — retarget the live gate strictly after the save (so the
        // just-persisted save was evaluated against the pre-save window).
        error = nil
        gate.retarget(window: .milliseconds(Int(newSettings.reauthGraceWindowMs)))
        banner = settingsSavedBanner()
    }
}
