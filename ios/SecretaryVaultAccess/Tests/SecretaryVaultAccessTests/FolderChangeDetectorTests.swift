import XCTest
@testable import SecretaryVaultAccess

final class FolderChangeDetectorTests: XCTestCase {
    private let window: Duration = .milliseconds(1_000)
    private func t(_ ns: Int64) -> MonotonicInstant { MonotonicInstant(nanoseconds: ns) }
    private func active() -> FolderChangeDetector {
        var d = FolderChangeDetector(debounceWindow: window)
        d.setActive(true)
        return d
    }

    func testSinglePulseRaisesPendingAfterWindow() {
        var d = active()
        d.recordPulse(at: t(0))
        XCTAssertEqual(d.nextFlushDeadline, t(1_000_000_000))   // 0 + 1s
        XCTAssertFalse(d.flush(now: t(999_000_000)))            // not quiet yet
        XCTAssertFalse(d.pendingChanges)
        XCTAssertTrue(d.flush(now: t(1_000_000_000)))           // quiet → raise (returns flipped=true)
        XCTAssertTrue(d.pendingChanges)
        XCTAssertNil(d.nextFlushDeadline)
    }

    func testBurstCoalescesToOneSignal() {
        var d = active()
        d.recordPulse(at: t(0))
        d.recordPulse(at: t(500_000_000))                      // within window → extends deadline
        XCTAssertEqual(d.nextFlushDeadline, t(1_500_000_000))
        XCTAssertFalse(d.flush(now: t(1_000_000_000)))         // old deadline; still noisy
        XCTAssertTrue(d.flush(now: t(1_500_000_000)))          // quiet from last pulse
        XCTAssertTrue(d.pendingChanges)
    }

    func testReorderedPulsesUseLatestInstant() {
        var d = active()
        d.recordPulse(at: t(500_000_000))
        d.recordPulse(at: t(0))                                // arrives late, earlier stamp
        XCTAssertEqual(d.nextFlushDeadline, t(1_500_000_000))  // max-instant wins
    }

    func testPulsesWhileInactiveAreDropped() {
        var d = FolderChangeDetector(debounceWindow: window)   // not active
        d.recordPulse(at: t(0))
        XCTAssertNil(d.nextFlushDeadline)
        XCTAssertFalse(d.flush(now: t(2_000_000_000)))
        XCTAssertFalse(d.pendingChanges)
    }

    func testGoingInactiveResetsPendingAndDeadline() {
        var d = active()
        d.recordPulse(at: t(0))
        _ = d.flush(now: t(1_000_000_000))
        XCTAssertTrue(d.pendingChanges)
        d.setActive(false)
        XCTAssertFalse(d.pendingChanges)
        XCTAssertNil(d.nextFlushDeadline)
    }

    func testMutedPulseIsIgnored() {
        var d = active()
        d.muteUntil(t(1_000_000_000))                          // suppress until 1s
        d.recordPulse(at: t(500_000_000))                      // before mute end → ignored
        XCTAssertNil(d.nextFlushDeadline)
        d.recordPulse(at: t(1_000_000_000))                    // at/after mute end → counts
        XCTAssertEqual(d.nextFlushDeadline, t(2_000_000_000))
    }

    func testAcknowledgeClearsThenLaterPulseReArms() {
        var d = active()
        d.recordPulse(at: t(0))
        _ = d.flush(now: t(1_000_000_000))
        d.acknowledge()
        XCTAssertFalse(d.pendingChanges)
        d.recordPulse(at: t(2_000_000_000))
        XCTAssertEqual(d.nextFlushDeadline, t(3_000_000_000))
    }

    func testFlushDoesNotDoubleFireWhilePending() {
        var d = active()
        d.recordPulse(at: t(0))
        XCTAssertTrue(d.flush(now: t(1_000_000_000)))
        XCTAssertFalse(d.flush(now: t(2_000_000_000)))         // already pending → no second flip
    }
}
