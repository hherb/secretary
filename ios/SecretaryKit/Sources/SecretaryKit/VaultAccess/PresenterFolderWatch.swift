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
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1   // serial; underlying thread is not main
        self.presentedItemOperationQueue = queue
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

    public func presentedSubitemDidChange(at url: URL) { pulse() }
    public func presentedItemDidChange() { pulse() }

    private func pulse() {
        let instant = MonotonicInstant.now()
        // Hop onto the main actor: the presenter queue is a background serial
        // queue, but the `FolderWatchPort` contract delivers callbacks
        // main-actor-isolated. The closure capture of `onPulse` is safe because
        // `onPulse` is only written from `start`/`stop`, both of which callers
        // invoke before (or after) any pulses arrive; the Task captures the
        // current value at the moment `pulse()` fires.
        Task { @MainActor [onPulse] in onPulse?(instant) }
    }
}
