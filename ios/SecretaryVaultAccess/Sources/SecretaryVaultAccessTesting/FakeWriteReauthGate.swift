import Foundation
import SecretaryVaultAccess

/// Pass-through `WriteReauthGate` for host tests that don't exercise gating.
/// `failNext` makes the NEXT `authorizeWrite` throw it once. `@unchecked Sendable`
/// for the same single-thread reason as `FakeBiometricAuthorizer`.
public final class FakeWriteReauthGate: WriteReauthGate, @unchecked Sendable {
    public private(set) var authorizeCount = 0
    public var failNext: VaultAccessError?

    public init() {}

    public func authorizeWrite(reason: String) async throws {
        authorizeCount += 1
        if let e = failNext { failNext = nil; throw e }
    }
}
