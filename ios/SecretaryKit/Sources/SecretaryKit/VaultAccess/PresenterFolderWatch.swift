import Foundation
import SecretaryVaultAccess

/// Real `FolderWatchPort` over `NSFilePresenter`. Registers on the vault folder
/// and forwards every sub-item change as a pulse, stamped with the current
/// monotonic instant and delivered on the main actor. `NSFilePresenter` is the
/// most general fit for the security-scoped, possibly-iCloud folders the app
/// opens via bookmarks. (Future: `NSMetadataQuery` for iCloud-download-specific
/// detection.)
public final class PresenterFolderWatch: NSObject, FolderWatchPort, NSFilePresenter {
    public let presentedItemURL: URL?
    public let presentedItemOperationQueue: OperationQueue
    private var onPulse: (@MainActor (MonotonicInstant) -> Void)?

    public init(folder: URL) {
        self.presentedItemURL = folder
        // Deliver presenter callbacks on the main queue so every access to
        // `onPulse` — the start/stop writes AND the pulse() read — is confined to
        // the main thread. No cross-thread data race on the stored closure.
        self.presentedItemOperationQueue = .main
        super.init()
    }

    public func start(onPulse: @escaping @MainActor (MonotonicInstant) -> Void) throws {
        self.onPulse = onPulse
        NSFileCoordinator.addFilePresenter(self)
    }

    public func stop() {
        NSFileCoordinator.removeFilePresenter(self)
        onPulse = nil
    }

    // The OS frequently delivers BOTH callbacks for a single sub-item write; the
    // extra pulse is harmless — the detector's trailing debounce (`recordPulse`
    // uses `max`) folds it into the same deadline. Keep BOTH overrides:
    // `presentedSubitemDidChange` catches block-file writes inside the folder,
    // `presentedItemDidChange` catches changes to the folder item itself.
    public func presentedSubitemDidChange(at url: URL) { pulse() }
    public func presentedItemDidChange() { pulse() }

    /// Forward a change as a main-actor pulse, stamped at OS-event time. Runs on
    /// the main queue (the presenter's operation queue), so `assumeIsolated` is
    /// safe and `onPulse` is read on the same thread it is written from. A pulse
    /// enqueued before `stop()` is harmless: stop() runs on the same main queue
    /// (it cannot interleave mid-pulse), and any later stale pulse finds
    /// `onPulse == nil`.
    private func pulse() {
        let instant = MonotonicInstant.now()
        MainActor.assumeIsolated { onPulse?(instant) }
    }
}
