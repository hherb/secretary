import SecretaryDeviceUnlock

/// `@unchecked Sendable`: a mutable spy double satisfying the (now `Sendable`)
/// `OpenedVault` protocol. Safe because XCTest drives it serially through
/// `await` — there is no real concurrent access — and the compiler cannot prove
/// that for a mutable class. The assumption is stated, not hidden (#231).
public final class FakeOpenedVault: OpenedVault, @unchecked Sendable {
    public let vaultUuid: [UInt8]
    public private(set) var wipeCount = 0
    public init(vaultUuid: [UInt8]) { self.vaultUuid = vaultUuid }
    public func wipe() { wipeCount += 1 }
}
