import Foundation

/// The biometric primitive the re-auth gate drives. The real conformer wraps the
/// Secure-Enclave key-release (the released secret is zeroized + discarded — re-auth
/// only cares that the release succeeded). `isEnrolled` is the prompt-free predicate
/// that decides whether the gate engages at all.
///
/// `Sendable` because a `@MainActor` re-auth gate sends its conformer off-actor
/// to `await authorize` (#231).
public protocol BiometricAuthorizer: Sendable {
    var isEnrolled: Bool { get }
    /// Prove presence. Throws `DeviceUnlockError`-class failures on cancel / non-match
    /// / lockout. `async` because the real conformer drives an `LAContext` evaluation.
    func authorize(reason: String) async throws
}

/// A gate the view models `await` before each mutating write. Conformers decide
/// whether a write needs a fresh biometric prompt (grace window) and engage the
/// biometric only when required.
///
/// `Sendable` because a `@MainActor` view model sends its gate off-actor to
/// `await authorizeWrite` (#231).
public protocol WriteReauthGate: Sendable {
    /// Returns normally when the write may proceed (authorized, within the grace
    /// window, or not enrolled); throws when biometry was required and failed.
    func authorizeWrite(reason: String) async throws
}

/// v1 re-auth grace window. Writes inside this window after the last successful auth
/// do not re-prompt. One global value (no per-write-type tuning in v1).
///
/// This is only the fallback window for a `GraceWindowReauthGate` built without an
/// explicit `window` (e.g. host tests). The **iOS app's effective grace default is
/// 2 min**, not 30 s: the composition root seeds the shared `RetargetableReauthGate`
/// from the vault's persisted `reauth_grace_window_ms` setting, falling back to the
/// schema default `REAUTH_WINDOW_DEFAULT_MS` (2 min) when unset — see
/// `RetargetableGateFactory` in the app target.
public enum ReauthWindow {
    public static let v1Default: Duration = .seconds(30)
}

/// Pure policy: does a write need a fresh biometric prompt? `true` when never authed
/// (`lastAuthAt == nil`) or when at least `window` has elapsed since the last auth.
/// Boundary is inclusive: exactly `window` ⇒ re-auth required.
///
/// Times are `MonotonicInstant`s — a **monotonic** timeline, not wall-clock: the window
/// measures true elapsed time and must not move under an NTP correction or a user
/// clock-set, which on a wall clock can jump backward and silently extend the
/// silent-write window past `window` (issue #282). Only the gap between the two
/// instants is meaningful, so they must come from the same clock.
public func needsReauth(lastAuthAt: MonotonicInstant?, now: MonotonicInstant, window: Duration) -> Bool {
    guard let last = lastAuthAt else { return true }
    return last.duration(to: now) >= window
}
