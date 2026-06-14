import Foundation
import SecretaryVaultAccess

/// In-memory `FolderWatchPort`. Tests call `emit` to deliver pulses on demand.
public final class FakeFolderWatch: FolderWatchPort {
    public private(set) var started = false
    public private(set) var stopCount = 0
    public private(set) var startCount = 0
    /// Set before `start` to make it throw.
    public var startError: Error?
    private var onPulse: (@MainActor (MonotonicInstant) -> Void)?

    public init() {}

    public func start(onPulse: @escaping @MainActor (MonotonicInstant) -> Void) throws {
        if let startError { throw startError }
        startCount += 1
        started = true
        self.onPulse = onPulse
    }

    public func stop() {
        stopCount += 1
        started = false
        onPulse = nil
    }

    /// Test hook: deliver a pulse to the registered callback.
    @MainActor public func emit(at instant: MonotonicInstant) { onPulse?(instant) }
}
