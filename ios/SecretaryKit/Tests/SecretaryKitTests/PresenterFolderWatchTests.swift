import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Drives the real NSFilePresenter watcher on a temp folder: a coordinated write
/// by another writer should pulse the monitor and (after a short debounce) flip
/// pendingChanges. One real-IO smoke test; logic is covered host-side.
@MainActor
final class PresenterFolderWatchTests: XCTestCase {
    func testCoordinatedWriteRaisesPendingChanges() throws {
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }

        let changed = expectation(description: "pendingChanges raised")
        let monitor = makeChangeMonitor(
            folder: folder,
            debounceWindow: .milliseconds(100),
            onChange: { changed.fulfill() })
        try monitor.start()
        defer { monitor.stop() }

        // Write a file via a separate coordinator (filePresenter: nil) so our
        // registered presenter is notified of the external change. This models
        // the real scenario: an EXTERNAL writer (the sync engine / iCloud)
        // mutating the folder. It deliberately does NOT model a same-process
        // synchronous coordinated write from the main thread — the one shape that
        // could deadlock a `.main` presenter queue — because the app performs no
        // such write (vault writes go through the Rust core's atomic rename, not
        // Swift file coordination); see PresenterFolderWatch.init.
        let target = folder.appendingPathComponent("block-0001.bin")
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordError: NSError?
        coordinator.coordinate(writingItemAt: target, options: [], error: &coordError) { url in
            try? Data([0x01, 0x02, 0x03]).write(to: url)
        }
        XCTAssertNil(coordError)

        wait(for: [changed], timeout: 5.0)
        XCTAssertTrue(monitor.pendingChanges)
    }
}
