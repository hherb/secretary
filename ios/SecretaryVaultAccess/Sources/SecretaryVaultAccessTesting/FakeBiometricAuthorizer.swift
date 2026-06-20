import Foundation
import SecretaryVaultAccess

/// Spy `BiometricAuthorizer` for host tests. `@unchecked Sendable`: a reference type
/// with mutable counters driven single-threaded by host tests (no real concurrency).
public final class FakeBiometricAuthorizer: BiometricAuthorizer, @unchecked Sendable {
    public var isEnrolled: Bool
    public private(set) var authorizeCount = 0
    /// When set, the NEXT `authorize` throws this once, then clears.
    public var failNextAuthorize: Error?

    public init(isEnrolled: Bool = true) { self.isEnrolled = isEnrolled }

    public func authorize(reason: String) async throws {
        authorizeCount += 1
        if let e = failNextAuthorize { failNextAuthorize = nil; throw e }
    }
}
