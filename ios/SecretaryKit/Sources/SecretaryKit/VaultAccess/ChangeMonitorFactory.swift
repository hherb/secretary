import Foundation
import SecretaryVaultAccess

/// Compose a ready-to-start `ChangeDetectionMonitor` over the real conformers for
/// `folder`. `debounceWindow` defaults to the production value; tests pass a tiny
/// window. Must be called on the main actor (the monitor is `@MainActor`).
@MainActor
public func makeChangeMonitor(
    folder: URL,
    debounceWindow: Duration = ChangeDetectionTuning.defaultDebounceWindow,
    onChange: @escaping () -> Void
) -> ChangeDetectionMonitor {
    ChangeDetectionMonitor(
        detector: FolderChangeDetector(debounceWindow: debounceWindow),
        watch: PresenterFolderWatch(folder: folder),
        scheduler: DispatchFlushScheduler(),
        onChange: onChange)
}
