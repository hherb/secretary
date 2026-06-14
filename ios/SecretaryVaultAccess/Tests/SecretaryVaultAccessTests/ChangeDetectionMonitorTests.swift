// ChangeDetectionMonitorTests.swift
import XCTest
@testable import SecretaryVaultAccess
import SecretaryVaultAccessTesting

@MainActor
final class ChangeDetectionMonitorTests: XCTestCase {
    private let window: Duration = .milliseconds(1_000)
    private func t(_ ns: Int64) -> MonotonicInstant { MonotonicInstant(nanoseconds: ns) }

    private func make(onChange: @escaping () -> Void = {})
        -> (ChangeDetectionMonitor, FakeFolderWatch, ManualFlushScheduler) {
        let watch = FakeFolderWatch()
        let scheduler = ManualFlushScheduler()
        let monitor = ChangeDetectionMonitor(
            detector: FolderChangeDetector(debounceWindow: window),
            watch: watch, scheduler: scheduler, onChange: onChange)
        return (monitor, watch, scheduler)
    }

    func testStartBeginsWatchingAndPulseSchedulesFlush() throws {
        let (monitor, watch, scheduler) = make()
        try monitor.start()
        XCTAssertTrue(watch.started)
        watch.emit(at: t(0))
        XCTAssertEqual(scheduler.scheduledDelay, window)        // armed to deadline
    }

    func testFlushRaisesPendingAndCallsOnChangeOnce() throws {
        var changes = 0
        let (monitor, watch, scheduler) = make(onChange: { changes += 1 })
        try monitor.start()
        watch.emit(at: t(0))
        scheduler.fire(at: t(1_000_000_000))
        XCTAssertTrue(monitor.pendingChanges)
        XCTAssertEqual(changes, 1)
    }

    func testBurstProducesSingleOnChange() throws {
        var changes = 0
        let (monitor, watch, scheduler) = make(onChange: { changes += 1 })
        try monitor.start()
        watch.emit(at: t(0))
        watch.emit(at: t(500_000_000))                          // re-arms to 1.5s
        scheduler.fire(at: t(1_000_000_000))                    // still noisy → re-arm, no fire
        XCTAssertFalse(monitor.pendingChanges)
        scheduler.fire(at: t(1_500_000_000))                    // quiet → fire
        XCTAssertEqual(changes, 1)
        XCTAssertTrue(monitor.pendingChanges)
    }

    func testStopCancelsSchedulerAndStopsWatch() throws {
        let (monitor, watch, scheduler) = make()
        try monitor.start()
        watch.emit(at: t(0))
        monitor.stop()
        XCTAssertGreaterThanOrEqual(scheduler.cancelCount, 1)
        XCTAssertEqual(watch.stopCount, 1)
        XCTAssertFalse(monitor.pendingChanges)
    }

    func testAcknowledgeResetsPending() throws {
        let (monitor, watch, scheduler) = make()
        try monitor.start()
        watch.emit(at: t(0))
        scheduler.fire(at: t(1_000_000_000))
        XCTAssertTrue(monitor.pendingChanges)
        monitor.acknowledge()
        XCTAssertFalse(monitor.pendingChanges)
    }

    func testStartPropagatesWatchError() {
        let (monitor, watch, _) = make()
        struct Boom: Error {}
        watch.startError = Boom()
        XCTAssertThrowsError(try monitor.start())
    }

    func testStartAfterFailedStartSucceedsCleanly() throws {
        let (monitor, watch, scheduler) = make()
        struct Boom: Error {}
        watch.startError = Boom()
        XCTAssertThrowsError(try monitor.start())   // first attempt fails + rolls back
        watch.startError = nil
        try monitor.start()                          // retry must succeed (gate not wedged)
        XCTAssertTrue(watch.started)
        watch.emit(at: t(0))
        XCTAssertEqual(scheduler.scheduledDelay, window)   // detector usable again
    }

    func testDoubleStartIsIgnored() throws {
        let (monitor, watch, _) = make()
        try monitor.start()
        try monitor.start()                          // second start ignored
        XCTAssertEqual(watch.startCount, 1)
    }

    func testAcknowledgeReArmsAPulseThatArrivedWhilePending() throws {
        var changes = 0
        let (monitor, watch, scheduler) = make(onChange: { changes += 1 })
        try monitor.start()
        watch.emit(at: t(0))
        scheduler.fire(at: t(1_000_000_000))         // first signal raised
        XCTAssertEqual(changes, 1)
        watch.emit(at: t(1_500_000_000))             // a pulse arrives WHILE pending
        monitor.acknowledge()                         // must re-arm for the preserved pulse
        XCTAssertNotNil(scheduler.scheduledDelay)     // re-armed (was nil before the fix)
        scheduler.fire(at: t(3_000_000_000))         // preserved deadline (2.5s) has passed → fires
        XCTAssertEqual(changes, 2)
        XCTAssertTrue(monitor.pendingChanges)
    }
}
