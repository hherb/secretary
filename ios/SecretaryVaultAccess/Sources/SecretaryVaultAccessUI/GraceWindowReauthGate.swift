import Foundation
import SecretaryVaultAccess

/// Grace-window re-auth gate over a `BiometricAuthorizer`. Engages only when the
/// authorizer is enrolled; within `window` of the last successful auth it is a no-op.
/// `@MainActor` because it holds mutable `lastAuthAt` consumed on the main actor
/// alongside the view models. `initialAuthAt` lets a device-unlock open seed the
/// clock (the unlock biometric counts); the password open path passes `nil`.
@MainActor
public final class GraceWindowReauthGate: WriteReauthGate {
    private let authorizer: BiometricAuthorizer
    private let window: TimeInterval
    private let clock: () -> Date
    private var lastAuthAt: Date?

    public init(authorizer: BiometricAuthorizer,
                window: TimeInterval = ReauthWindow.v1Default,
                clock: @escaping () -> Date = Date.init,
                initialAuthAt: Date? = nil) {
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
