import Foundation
import SecretaryVaultAccess

/// Spy `SyncMonitorHook` for VM tests.
@MainActor
public final class FakeSyncMonitorHook: SyncMonitorHook {
    public private(set) var muteCalls = 0
    public private(set) var acknowledgeCalls = 0
    public init() {}
    public func muteSelfWrite() { muteCalls += 1 }
    public func acknowledge() { acknowledgeCalls += 1 }
}
