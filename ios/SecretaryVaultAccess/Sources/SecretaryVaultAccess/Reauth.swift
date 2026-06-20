import Foundation

/// The biometric primitive the re-auth gate drives. The real conformer wraps the
/// Secure-Enclave key-release (the released secret is zeroized + discarded — re-auth
/// only cares that the release succeeded). `isEnrolled` is the prompt-free predicate
/// that decides whether the gate engages at all.
public protocol BiometricAuthorizer {
    var isEnrolled: Bool { get }
    /// Prove presence. Throws `DeviceUnlockError`-class failures on cancel / non-match
    /// / lockout. `async` because the real conformer drives an `LAContext` evaluation.
    func authorize(reason: String) async throws
}

/// A gate the view models `await` before each mutating write. Conformers decide
/// whether a write needs a fresh biometric prompt (grace window) and engage the
/// biometric only when required.
public protocol WriteReauthGate {
    /// Returns normally when the write may proceed (authorized, within the grace
    /// window, or not enrolled); throws when biometry was required and failed.
    func authorizeWrite(reason: String) async throws
}

/// v1 re-auth grace window. Writes inside this window after the last successful auth
/// do not re-prompt. One global value (no per-write-type tuning in v1).
public enum ReauthWindow {
    public static let v1Default: TimeInterval = 30
}

/// Pure policy: does a write need a fresh biometric prompt? `true` when never authed
/// (`lastAuthAt == nil`) or when at least `window` seconds have elapsed since the last
/// auth. Boundary is inclusive: exactly `window` seconds ⇒ re-auth required.
public func needsReauth(lastAuthAt: Date?, now: Date, window: TimeInterval) -> Bool {
    guard let last = lastAuthAt else { return true }
    return now.timeIntervalSince(last) >= window
}
