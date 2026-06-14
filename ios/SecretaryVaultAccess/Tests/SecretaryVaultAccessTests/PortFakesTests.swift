import XCTest
@testable import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class PortFakesTests: XCTestCase {
    func testFakeFolderWatchDeliversEmittedPulse() throws {
        let watch = FakeFolderWatch()
        var seen: MonotonicInstant?
        try watch.start(onPulse: { seen = $0 })
        XCTAssertTrue(watch.started)
        watch.emit(at: MonotonicInstant(nanoseconds: 42))
        XCTAssertEqual(seen, MonotonicInstant(nanoseconds: 42))
        watch.stop()
        XCTAssertEqual(watch.stopCount, 1)
        XCTAssertFalse(watch.started)
    }

    func testFakeFolderWatchStartThrowsConfiguredError() {
        let watch = FakeFolderWatch()
        struct Boom: Error {}
        watch.startError = Boom()
        XCTAssertThrowsError(try watch.start(onPulse: { _ in }))
    }

    func testManualSchedulerFiresPendingWorkOnce() {
        let scheduler = ManualFlushScheduler()
        var fired: MonotonicInstant?
        scheduler.schedule(after: .seconds(1)) { fired = $0 }
        XCTAssertEqual(scheduler.scheduledDelay, .seconds(1))
        scheduler.fire(at: MonotonicInstant(nanoseconds: 7))
        XCTAssertEqual(fired, MonotonicInstant(nanoseconds: 7))
        XCTAssertNil(scheduler.scheduledDelay)
    }

    func testManualSchedulerCancelDropsPendingWork() {
        let scheduler = ManualFlushScheduler()
        var fired = false
        scheduler.schedule(after: .seconds(1)) { _ in fired = true }
        scheduler.cancel()
        XCTAssertEqual(scheduler.cancelCount, 1)
        scheduler.fire(at: MonotonicInstant(nanoseconds: 1))
        XCTAssertFalse(fired)
    }
}
