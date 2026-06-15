import Foundation

/// The sync VM's view of the change monitor: mute the monitor around the VM's own
/// vault writes, and reset it after a pass so the next remote change re-detects.
/// `@MainActor` because the real conformer wraps the `@MainActor` monitor.
@MainActor
public protocol SyncMonitorHook: AnyObject {
    /// Suppress watcher pulses for a self-write window starting now.
    func muteSelfWrite()
    /// Acknowledge handled changes so the detector re-arms for the next one.
    func acknowledge()
}
