import Foundation
import SecretaryVaultAccess

/// Pass-through `WriteReauthGate` for host tests that don't exercise gating.
/// `failNext` makes the NEXT `authorizeWrite` throw it once. `suspension`, when
/// set, holds every `authorizeWrite` open (a prompt that is up) until released.
/// `@unchecked Sendable`
/// for the same single-thread reason as `FakeBiometricAuthorizer`.
public final class FakeWriteReauthGate: WriteReauthGate, @unchecked Sendable {
    public private(set) var authorizeCount = 0
    public private(set) var lastReason: String?
    public var failNext: VaultAccessError?
    public var suspension: SuspensionGate?

    public init() {}

    public func authorizeWrite(reason: String) async throws {
        authorizeCount += 1
        lastReason = reason
        if let suspension { await suspension.enterAndWait() }
        if let e = failNext { failNext = nil; throw e }
    }
}
