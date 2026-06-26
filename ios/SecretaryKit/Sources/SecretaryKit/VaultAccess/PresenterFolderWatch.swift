import Foundation
import SecretaryVaultAccess

/// Real `FolderWatchPort` over `NSFilePresenter`. Registers on the vault folder
/// and forwards every sub-item change as a pulse, stamped with the current
/// monotonic instant and delivered on the main actor. `NSFilePresenter` is the
/// most general fit for the security-scoped, possibly-iCloud folders the app
/// opens via bookmarks. (Future: `NSMetadataQuery` for iCloud-download-specific
/// detection.)
/// `@unchecked Sendable`: the OS retains this presenter and the monitor that owns
/// it may be referenced from any thread, but its only mutable state — `onPulse` —
/// is confined to the main queue (the presenter's `presentedItemOperationQueue`
/// is `.main`, and `start`/`stop` are reached from the `@MainActor`; see the
/// `init` comment). Main-queue confinement is the isolation discipline that earns
/// `Sendable` here, the way `UniffiVaultSession` earns it via a lock (#231).
public final class PresenterFolderWatch: NSObject, FolderWatchPort, NSFilePresenter, @unchecked Sendable {
    public let presentedItemURL: URL?
    public let presentedItemOperationQueue: OperationQueue
    private var onPulse: (@MainActor (MonotonicInstant) -> Void)?

    public init(folder: URL) {
        self.presentedItemURL = folder
        // Deliver presenter callbacks on the main queue so every access to
        // `onPulse` — the start/stop writes AND the pulse() read — is confined to
        // the main thread. No cross-thread data race on the stored closure.
        //
        // Apple cautions against `.main` here because a *synchronous*
        // `NSFileCoordinator` write driven from the main thread could deadlock
        // waiting on a presenter callback that also needs the main queue. That
        // hazard does not apply to this presenter:
        //   1. It implements only the notification callbacks
        //      (`presentedSubitemDidChange` / `presentedItemDidChange`), never the
        //      blocking coordination callbacks (`relinquishPresentedItem(toWriter:)`,
        //      `savePresentedItemChanges`) that participate in a write's critical
        //      section.
        //   2. The app performs NO Swift `NSFileCoordinator` writes — vault writes
        //      go through the Rust core's atomic rename over FFI, not file
        //      coordination — so there is no same-process coordinated write to
        //      contend with on any thread, let alone the main one.
        // Slice 3's `muteUntil` self-write hook (if wired around a write) must
        // preserve property (2): keep vault writes off Swift file coordination.
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
