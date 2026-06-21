import Foundation
import SecretaryVaultAccess

/// Grace-window re-auth gate over a `BiometricAuthorizer`. Engages only when the
/// authorizer is enrolled; within `window` of the last successful auth it is a no-op.
/// `@MainActor` because it holds mutable `lastAuthAt` consumed on the main actor
/// alongside the view models. `initialAuthAt` lets a device-unlock open seed the
/// clock (the unlock biometric counts); the password open path passes `nil`.
///
/// The clock is a **monotonic** source (`MonotonicInstant`, see issue #282) — wall-clock
/// would let a backward clock jump extend the silent window. It is injected (no default)
/// so the pure module stays clock-free; the composition root supplies the real
/// `MonotonicInstant.now`, exactly as the folder-change detector does. `clock` and
/// `initialAuthAt` must share the same monotonic base.
@MainActor
public final class GraceWindowReauthGate: WriteReauthGate {
    private let authorizer: BiometricAuthorizer
    private let window: Duration
    private let clock: () -> MonotonicInstant
    private var lastAuthAt: MonotonicInstant?

    public init(authorizer: BiometricAuthorizer,
                window: Duration = ReauthWindow.v1Default,
                clock: @escaping () -> MonotonicInstant,
                initialAuthAt: MonotonicInstant? = nil) {
        self.authorizer = authorizer
        self.window = window
        self.clock = clock
        self.lastAuthAt = initialAuthAt
    }

    public func authorizeWrite(reason: String) async throws {
        guard authorizer.isEnrolled else { return }            // no SE key: no gate
        guard needsReauth(lastAuthAt: lastAuthAt, now: clock(), window: window) else { return }
        try await authorizer.authorize(reason: reason)         // biometric prompt
        lastAuthAt = clock()                                   // advance only on success
    }
}
