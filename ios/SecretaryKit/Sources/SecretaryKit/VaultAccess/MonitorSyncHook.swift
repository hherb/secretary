import Foundation
import SecretaryVaultAccess

/// Real `SyncMonitorHook` over a `ChangeDetectionMonitor`: mute around our own
/// vault writes (a window starting now) and acknowledge handled changes.
@MainActor
public final class MonitorSyncHook: SyncMonitorHook {
    private let monitor: ChangeDetectionMonitor
    private let muteWindow: Duration
    public init(monitor: ChangeDetectionMonitor,
                muteWindow: Duration = ChangeDetectionTuning.defaultSelfWriteMuteWindow) {
        self.monitor = monitor
        self.muteWindow = muteWindow
    }
    public func muteSelfWrite() {
        monitor.muteUntil(MonotonicInstant.now().advanced(by: muteWindow))
    }
    public func acknowledge() {
        monitor.acknowledge()
    }
}
